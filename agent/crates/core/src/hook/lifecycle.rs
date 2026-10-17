use super::{ErrorCode, Manifest, PayloadManifest, Result, Stage, capture, files};
use serde::Serialize;
use std::path::{Path, PathBuf};

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(tag = "state", rename_all = "snake_case")]
pub enum Status {
    Off,
    EnabledNoRecords,
    Observing,
    UpdatePending,
    RemovePending,
    Error { code: ErrorCode },
}

/// A package's sidecar and its trusted build manifest; never supplied by a webview.
pub struct Payload {
    pub(super) path: PathBuf,
    manifest: PayloadManifest,
}
impl Payload {
    pub fn bundled() -> Result<Self> {
        let executable = std::env::current_exe().map_err(|_| ErrorCode::UntrustedPayload)?;
        Self::at(executable.parent().ok_or(ErrorCode::UnsafePath)?)
    }
    pub(super) fn at(directory: &Path) -> Result<Self> {
        let directory = std::fs::canonicalize(directory).map_err(|_| ErrorCode::UntrustedPayload)?;
        if directory.components().any(|part| {
            let name = part.as_os_str().to_string_lossy();
            name == "_npx" || name.starts_with(".mount_")
        }) || std::env::var_os("APPDIR").is_some_and(|appdir| directory.starts_with(appdir))
        {
            return Err(ErrorCode::UntrustedPayload);
        }
        files::chain(&directory).map_err(|_| ErrorCode::UntrustedPayload)?;
        let raw = files::read(&directory.join("payload-manifest.json"), 4096, false)
            .map_err(|_| ErrorCode::UntrustedPayload)?;
        let manifest: PayloadManifest = serde_json::from_slice(&raw).map_err(|_| ErrorCode::UntrustedPayload)?;
        let path = directory.join(super::helper_name());
        let value = Self { path, manifest };
        value.bytes()?;
        Ok(value)
    }
    fn bytes(&self) -> Result<Vec<u8>> {
        if self.manifest.schema_version != 1
            || semver::Version::parse(&self.manifest.version).is_err()
            || self.manifest.platform != platform()
            || self.manifest.target != target()
            || !valid_hash(&self.manifest.sha256)
        {
            return Err(ErrorCode::UntrustedPayload);
        }
        let bytes = files::read(&self.path, 32 * 1024 * 1024, false).map_err(|_| ErrorCode::UntrustedPayload)?;
        if bytes.is_empty() || files::hash(&bytes) != self.manifest.sha256 {
            return Err(ErrorCode::UntrustedPayload);
        }
        Ok(bytes)
    }
}

pub(super) fn platform() -> String {
    let os = if cfg!(target_os = "macos") { "darwin" } else { std::env::consts::OS };
    let arch = if cfg!(target_arch = "x86_64") { "x64" } else { "arm64" };
    format!("{os}-{arch}")
}
pub(super) fn target() -> String {
    match (std::env::consts::OS, std::env::consts::ARCH) {
        ("linux", "x86_64") => "x86_64-unknown-linux-musl",
        ("linux", "aarch64") => "aarch64-unknown-linux-musl",
        ("windows", "x86_64") => "x86_64-pc-windows-gnu",
        ("macos", "x86_64") => "x86_64-apple-darwin",
        ("macos", "aarch64") => "aarch64-apple-darwin",
        _ => "unsupported",
    }
    .to_owned()
}
fn valid_hash(hash: &str) -> bool {
    hash.len() == 64 && hash.bytes().all(|b| b.is_ascii_hexdigit())
}

/// Production uses only OS roots. Tests construct this service with a synthetic root.
pub struct Lifecycle {
    pub(super) root: PathBuf,
}
impl Lifecycle {
    pub fn for_user() -> Result<Self> {
        Ok(Self { root: super::root()? })
    }
    pub fn status(&self) -> Status {
        match self.status_checked() {
            Ok(status) => status,
            Err(code) => Status::Error { code },
        }
    }
    fn status_checked(&self) -> Result<Status> {
        if !self.root.try_exists().map_err(|_| ErrorCode::UnsafePath)? {
            return Ok(Status::Off);
        }
        files::private_dir_existing(&self.root)?;
        let _lock = files::Lock::acquire(&self.root.join("lock"), false)?;
        let Some(manifest) = self.manifest()? else { return Ok(Status::Off) };
        match manifest.stage {
            Stage::Removing => Ok(Status::RemovePending),
            Stage::Installing => Ok(Status::UpdatePending),
            Stage::Enabled => {
                if !super::settings::contains(&manifest.settings_target, &manifest.entry)? {
                    return Ok(Status::Off);
                }
                let files = std::fs::read_dir(self.root.join("records")).map_err(|_| ErrorCode::FileFailure)?;
                let has_record = files.take(capture::MAX_RECORDS).filter_map(std::result::Result::ok).any(|entry| {
                    let Ok(bytes) = files::read(&entry.path(), capture::RECORD_LIMIT, true) else { return false };
                    serde_json::from_slice::<serde_json::Value>(&bytes).ok().is_some_and(|v| {
                        v.get("installationGeneration").and_then(|v| v.as_str())
                            == Some(&manifest.installation_generation)
                    })
                });
                Ok(if has_record { Status::Observing } else { Status::EnabledNoRecords })
            }
        }
    }
    pub fn set_enabled(&self, on: bool) -> Result<Status> {
        if on { self.enable(&Payload::bundled()?, super::settings::target()?) } else { self.disable() }
    }
    pub fn reconcile_existing_consent(&self) -> Result<Status> {
        if !self.root.try_exists().map_err(|_| ErrorCode::UnsafePath)? {
            return Ok(Status::Off);
        }
        let lock = files::Lock::acquire(&self.root.join("lock"), false)?;
        let Some(manifest) = self.manifest()? else { return Ok(Status::Off) };
        if matches!(manifest.stage, Stage::Removing) {
            return self.finish_remove(manifest, lock);
        }
        if !super::settings::contains(&manifest.settings_target, &manifest.entry)?
            && matches!(manifest.stage, Stage::Enabled)
        {
            return Ok(Status::Off);
        }
        let payload = Payload::bundled()?;
        self.finish_enable(manifest, &payload, &lock)?;
        drop(lock);
        Ok(self.status())
    }
    pub(super) fn enable(&self, payload: &Payload, target: PathBuf) -> Result<Status> {
        // Complete validation before creating even a consent directory.
        let _ = payload.bytes()?;
        let target = super::settings::canonical_target(&target, true)?;
        files::parents(self.root.parent().ok_or(ErrorCode::UnsafePath)?)?;
        files::private_dir(&self.root)?;
        let lock = files::Lock::acquire(&self.root.join("lock"), true)?;
        let existing = self.manifest()?;
        if existing.as_ref().is_some_and(|m| matches!(m.stage, Stage::Removing)) {
            return Err(ErrorCode::RemovePending);
        }
        if let Some(current) = &existing {
            let installed = semver::Version::parse(&current.payload.version).map_err(|_| ErrorCode::InvalidManifest)?;
            let next = semver::Version::parse(&payload.manifest.version).map_err(|_| ErrorCode::UntrustedPayload)?;
            if next == installed && payload.manifest.sha256 != current.payload.sha256 {
                return Err(ErrorCode::Conflict);
            }
        }
        let mut manifest = match existing {
            Some(mut current) => {
                if current.settings_target != target {
                    current.previous = Some((current.settings_target.clone(), current.entry.clone()));
                    current.settings_target = target;
                    current.installation_generation = super::uuid()?;
                    current.entry = self.entry(&current.installation_generation);
                    current.stage = Stage::Installing;
                }
                current
            }
            None => {
                let generation = super::uuid()?;
                Manifest {
                    schema_version: 1,
                    entry: self.entry(&generation),
                    installation_generation: generation,
                    stage: Stage::Installing,
                    payload: payload.manifest.clone(),
                    next_payload: None,
                    settings_target: target,
                    previous: None,
                }
            }
        };
        // Even a retry advertises an intent before changing files/settings.
        manifest.stage = Stage::Installing;
        self.save(&manifest)?;
        self.finish_enable(manifest, payload, &lock)?;
        drop(lock);
        Ok(self.status())
    }
    fn finish_enable(&self, mut manifest: Manifest, payload: &Payload, lock: &files::Lock) -> Result<()> {
        lock.validate()?;
        files::private_dir(&self.root.join("records"))?;
        let path = self.root.join(super::helper_name());
        let bytes = payload.bytes()?;
        if let Some(pending) = manifest.next_payload.take() {
            let current = files::read(&path, 32 * 1024 * 1024, true)?;
            if files::hash(&current) == pending.sha256 {
                manifest.payload = pending;
            } else if files::hash(&current) != manifest.payload.sha256 {
                return Err(ErrorCode::Conflict);
            }
            self.save(&manifest)?;
        }
        if path.try_exists().map_err(|_| ErrorCode::UnsafePath)? {
            let installed =
                semver::Version::parse(&manifest.payload.version).map_err(|_| ErrorCode::InvalidManifest)?;
            let next = semver::Version::parse(&payload.manifest.version).map_err(|_| ErrorCode::UntrustedPayload)?;
            let current = files::read(&path, 32 * 1024 * 1024, true)?;
            if files::hash(&current) != manifest.payload.sha256 {
                return Err(ErrorCode::Conflict);
            }
            if next == installed && payload.manifest.sha256 != manifest.payload.sha256 {
                return Err(ErrorCode::Conflict);
            }
            if next > installed {
                manifest.next_payload = Some(payload.manifest.clone());
                self.save(&manifest)?;
                files::atomic(&path, &bytes, true).map_err(|_| ErrorCode::UpdatePending)?;
                manifest.payload = payload.manifest.clone();
                manifest.next_payload = None;
                self.save(&manifest)?;
            }
        } else {
            if payload.manifest.sha256 != manifest.payload.sha256 {
                return Err(ErrorCode::Conflict);
            }
            files::atomic(&path, &bytes, true)?;
        }
        if let Some((target, entry)) = &manifest.previous {
            super::settings::edit(target, entry, false)?;
            // Retire every old-generation record under the same publication lock.
            self.clear_records()?;
        }
        super::settings::edit(&manifest.settings_target, &manifest.entry, true)?;
        manifest.previous = None;
        manifest.stage = Stage::Enabled;
        self.save(&manifest)
    }
    fn disable(&self) -> Result<Status> {
        if !self.root.try_exists().map_err(|_| ErrorCode::UnsafePath)? {
            return Ok(Status::Off);
        }
        files::private_dir_existing(&self.root)?;
        let lock = files::Lock::acquire(&self.root.join("lock"), false)?;
        let Some(mut manifest) = self.manifest()? else { return Err(ErrorCode::InvalidManifest) };
        manifest.stage = Stage::Removing;
        self.save(&manifest)?;
        self.finish_remove(manifest, lock)
    }
    fn finish_remove(&self, manifest: Manifest, lock: files::Lock) -> Result<Status> {
        lock.validate()?;
        super::settings::edit(&manifest.settings_target, &manifest.entry, false)?;
        if let Some((target, entry)) = &manifest.previous {
            super::settings::edit(target, entry, false)?;
        }
        self.clear_records()?;
        let records = self.root.join("records");
        if records.try_exists().map_err(|_| ErrorCode::UnsafePath)? {
            std::fs::remove_dir(&records).map_err(|_| ErrorCode::RemovePending)?;
        }
        for name in [super::helper_name(), "manifest.json"] {
            let path = self.root.join(name);
            match files::open(&path, false, false, true) {
                Ok(file) => {
                    files::same_name(&file, &path)?;
                    std::fs::remove_file(&path).map_err(|_| ErrorCode::RemovePending)?;
                }
                Err(ErrorCode::NoEntry) => (),
                Err(e) => return Err(e),
            }
        }
        lock.retire()?;
        std::fs::remove_dir(&self.root).map_err(|_| ErrorCode::RemovePending)?;
        Ok(Status::Off)
    }
    fn clear_records(&self) -> Result<()> {
        let directory = self.root.join("records");
        if !directory.try_exists().map_err(|_| ErrorCode::UnsafePath)? {
            return Ok(());
        }
        files::private_dir_existing(&directory)?;
        let entries = std::fs::read_dir(&directory).map_err(|_| ErrorCode::FileFailure)?;
        for entry in entries.take(capture::MAX_RECORDS + 1) {
            let entry = entry.map_err(|_| ErrorCode::FileFailure)?;
            let path = entry.path();
            let name = entry.file_name();
            let name = name.to_str().ok_or(ErrorCode::UnsafePath)?;
            let own = name.strip_suffix(".json").is_some_and(super::valid_uuid)
                || name.strip_prefix(".quotum-").and_then(|n| n.strip_suffix(".tmp")).is_some_and(super::valid_uuid);
            if !own {
                return Err(ErrorCode::RemovePending);
            }
            let file = files::open(&path, false, false, true)?;
            files::same_name(&file, &path)?;
            std::fs::remove_file(&path).map_err(|_| ErrorCode::RemovePending)?;
        }
        Ok(())
    }
    fn entry(&self, generation: &str) -> serde_json::Value {
        serde_json::json!({"type":"command","command":self.root.join(super::helper_name()),"args":["--generation",generation],"timeout":1})
    }
    fn save(&self, manifest: &Manifest) -> Result<()> {
        files::atomic(
            &self.root.join("manifest.json"),
            &serde_json::to_vec(manifest).map_err(|_| ErrorCode::InvalidManifest)?,
            false,
        )
    }
    pub(super) fn manifest(&self) -> Result<Option<Manifest>> {
        let bytes = match files::read(&self.root.join("manifest.json"), 16 * 1024, true) {
            Err(ErrorCode::NoEntry) => return Ok(None),
            other => other?,
        };
        let value: Manifest = serde_json::from_slice(&bytes).map_err(|_| ErrorCode::InvalidManifest)?;
        if value.schema_version != 1
            || !super::valid_uuid(&value.installation_generation)
            || value.entry != self.entry(&value.installation_generation)
            || !value.settings_target.is_absolute()
            || !valid_hash(&value.payload.sha256)
            || semver::Version::parse(&value.payload.version).is_err()
            || value.previous.as_ref().is_some_and(|(target, entry)| {
                let generation = entry.get("args").and_then(|v| v.get(1)).and_then(|v| v.as_str());
                !target.is_absolute() || generation.is_none_or(|g| !super::valid_uuid(g) || *entry != self.entry(g))
            })
        {
            return Err(ErrorCode::InvalidManifest);
        }
        Ok(Some(value))
    }
    pub(crate) fn routes(
        &self,
        sessions: &[crate::activity::Session],
    ) -> Result<std::collections::BTreeMap<(u32, Vec<u8>), crate::route::Route>> {
        if !self.root.try_exists().map_err(|_| ErrorCode::UnsafePath)? {
            return Ok(Default::default());
        }
        let _lock = files::Lock::acquire(&self.root.join("lock"), false)?;
        let Some(manifest) = self.manifest()? else { return Ok(Default::default()) };
        if !matches!(manifest.stage, Stage::Enabled) {
            return Ok(Default::default());
        }
        capture::routes(&self.root, &manifest, sessions)
    }
}
