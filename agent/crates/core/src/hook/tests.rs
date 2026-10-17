use super::*;
use std::path::Path;

pub(super) struct Fixture {
    pub base: PathBuf,
    pub service: Lifecycle,
    pub payload: Payload,
    pub settings: PathBuf,
}
impl Fixture {
    pub fn new() -> Self {
        // A synthetic account boundary. No test consults or prepares the user's hook root.
        let parent = std::env::var_os("CARGO_HOME")
            .map(PathBuf::from)
            .unwrap_or_else(|| dirs::home_dir().unwrap().join(".cache"));
        files::parents(&parent).unwrap();
        let base = parent.join(format!("quotum-hook-test-{}", uuid().unwrap()));
        files::private_dir(&base).unwrap();
        let source = base.join("package");
        files::private_dir(&source).unwrap();
        let payload = payload(&source, "1.0.0", b"synthetic helper v1");
        let service = Lifecycle { root: base.join("hooks") };
        let settings = base.join("settings.json");
        Self { base, service, payload, settings }
    }
    pub fn enable(&self) -> Result<Status> {
        self.service.enable(&self.payload, self.settings.clone())
    }
    pub fn generation(&self) -> String {
        self.service.manifest().unwrap().unwrap().installation_generation
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.base);
    }
}

fn payload(source: &Path, version: &str, bytes: &[u8]) -> Payload {
    let manifest = PayloadManifest {
        schema_version: 1,
        version: version.to_owned(),
        platform: lifecycle::platform(),
        target: lifecycle::target(),
        sha256: files::hash(bytes),
    };
    files::atomic(&source.join(helper_name()), bytes, true).unwrap();
    files::atomic(&source.join("payload-manifest.json"), &serde_json::to_vec(&manifest).unwrap(), false).unwrap();
    Payload::at(source).unwrap()
}

#[test]
fn cli_and_app_share_generation_settings_and_exact_removal() {
    let f = Fixture::new();
    std::fs::write(&f.settings,br#"{"unknown":{"keep":true},"hooks":{"SessionStart":[{"matcher":"startup","hooks":[{"type":"command","command":"foreign"}]}]}}"#).unwrap();
    let original: serde_json::Value = serde_json::from_slice(&std::fs::read(&f.settings).unwrap()).unwrap();
    assert_eq!(f.enable().unwrap(), Status::EnabledNoRecords);
    let generation = f.generation();
    let second = Lifecycle { root: f.service.root.clone() };
    assert_eq!(second.status(), Status::EnabledNoRecords);
    assert_eq!(f.enable().unwrap(), Status::EnabledNoRecords);
    assert_eq!(f.generation(), generation);
    assert_eq!(second.set_enabled(false).unwrap(), Status::Off);
    assert!(!f.service.root.clone().exists());
    assert_eq!(serde_json::from_slice::<serde_json::Value>(&std::fs::read(&f.settings).unwrap()).unwrap(), original);
    assert_eq!(second.set_enabled(false).unwrap(), Status::Off);
    f.enable().unwrap();
    assert_ne!(generation, f.generation());
}

#[test]
fn relocation_retires_old_profile_and_generation() {
    let f = Fixture::new();
    f.enable().unwrap();
    let generation = f.generation();
    let next = f.base.join("other-settings.json");
    f.service.enable(&f.payload, next.clone()).unwrap();
    assert_ne!(generation, f.generation());
    let old: serde_json::Value = serde_json::from_slice(&std::fs::read(&f.settings).unwrap()).unwrap();
    assert_eq!(old, serde_json::json!({}));
    assert!(settings::contains(&next, &f.service.manifest().unwrap().unwrap().entry).unwrap());
    f.service.set_enabled(false).unwrap();
    assert_eq!(
        serde_json::from_slice::<serde_json::Value>(&std::fs::read(next).unwrap()).unwrap(),
        serde_json::json!({})
    );
}

#[test]
fn malformed_and_oversized_settings_are_never_rewritten() {
    for bytes in [b"{broken json".to_vec(), b"[]".to_vec(), vec![b' '; 1024 * 1024 + 1]] {
        let f = Fixture::new();
        std::fs::write(&f.settings, &bytes).unwrap();
        assert!(f.enable().is_err());
        assert_eq!(std::fs::read(&f.settings).unwrap(), bytes);
        assert_eq!(f.service.status(), Status::UpdatePending);
    }
}

#[cfg(unix)]
#[test]
fn settings_symlink_mode_and_foreign_values_survive() {
    use std::os::unix::fs::{PermissionsExt, symlink};
    let f = Fixture::new();
    let real = f.base.join("dotfiles.json");
    std::fs::write(&real, b"{\"arbitrary\":42}").unwrap();
    std::fs::set_permissions(&real, std::fs::Permissions::from_mode(0o640)).unwrap();
    symlink(&real, &f.settings).unwrap();
    f.enable().unwrap();
    assert!(std::fs::symlink_metadata(&f.settings).unwrap().file_type().is_symlink());
    assert_eq!(std::fs::metadata(&real).unwrap().permissions().mode() & 0o777, 0o640);
    f.service.set_enabled(false).unwrap();
    assert!(std::fs::symlink_metadata(&f.settings).unwrap().file_type().is_symlink());
    assert_eq!(
        serde_json::from_slice::<serde_json::Value>(&std::fs::read(real).unwrap()).unwrap(),
        serde_json::json!({"arbitrary":42})
    );
}

#[test]
fn monotonic_payload_replacement_and_equal_version_conflict() {
    let f = Fixture::new();
    f.enable().unwrap();
    let generation = f.generation();
    let next = f.base.join("newer");
    files::private_dir(&next).unwrap();
    let newer = payload(&next, "1.1.0", b"synthetic helper v2");
    f.service.enable(&newer, f.settings.clone()).unwrap();
    f.enable().unwrap();
    assert_eq!(f.service.manifest().unwrap().unwrap().payload.version, "1.1.0");
    assert_eq!(f.generation(), generation);
    assert_eq!(std::fs::read(f.service.root.clone().join(helper_name())).unwrap(), b"synthetic helper v2");
    let conflict = payload(&next, "1.1.0", b"different build");
    assert_eq!(f.service.enable(&conflict, f.settings.clone()), Err(ErrorCode::Conflict));
    assert_eq!(f.service.status(), Status::EnabledNoRecords);
    f.service.set_enabled(false).unwrap();
}

#[test]
fn payload_rejects_npx_appimage_and_unsafe_chain() {
    let f = Fixture::new();
    for name in ["_npx", ".mount_Quotum123"] {
        let bad = f.base.join(name);
        files::private_dir(&bad).unwrap();
        std::fs::copy(f.payload.path.clone(), bad.join(helper_name())).unwrap();
        std::fs::copy(
            f.payload.path.parent().unwrap().join("payload-manifest.json"),
            bad.join("payload-manifest.json"),
        )
        .unwrap();
        assert!(matches!(Payload::at(&bad), Err(ErrorCode::UntrustedPayload)));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let source = f.payload.path.parent().unwrap();
        std::fs::set_permissions(source, std::fs::Permissions::from_mode(0o770)).unwrap();
        assert!(matches!(Payload::at(source), Err(ErrorCode::UntrustedPayload)));
    }
    assert!(!f.service.root.clone().exists());
}

#[test]
fn lock_never_allows_an_old_waiter_to_mutate_a_new_installation() {
    let f = Fixture::new();
    f.enable().unwrap();
    let root = f.service.root.clone();
    let path = root.join("lock");
    let old = files::open(&path, true, false, true).unwrap();
    f.service.set_enabled(false).unwrap();
    f.enable().unwrap();
    assert!(files::same_name(&old, &path).is_err());
    let lock = files::Lock::acquire(&path, false).unwrap();
    assert_eq!(f.service.set_enabled(false), Err(ErrorCode::Busy));
    drop(lock);
    f.service.set_enabled(false).unwrap();
    assert!(!root.exists());
}

#[test]
fn native_parent_order_rejects_pre_first_read_pid_reuse() {
    use crate::activity::hook_parent_order as accepts;
    assert!(accepts(7, 102, 7, 101));
    for (boot, child, parent_boot, parent) in
        [(7, 102, 7, 103), (7, 102, 7, 102), (7, 102, 7, 0), (7, 0, 7, 101), (7, 102, 8, 101)]
    {
        assert!(!accepts(boot, child, parent_boot, parent));
    }
    // No wall clock enters this decision.
}
