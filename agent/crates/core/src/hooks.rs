//! Trusted local collectors. Discovery reads identities only; measurement receives
//! the selected identities on stdin, so each account keeps the hub's own duty and pace.

use std::collections::{BTreeMap, BTreeSet};
use std::time::Duration;

use serde::{Deserialize, Serialize};
use serde_json::json;

use crate::config::{Config, HookSettings, Paths, jitter};
use crate::measurement_policy::MeasurementPolicy;
use crate::model::{
    ErrorKind, Failure, Kind, Millis, Outcome, Provider, Snapshot, TEXT_LIMIT, Window, now_ms, parse_time, pseudonym,
};
use crate::process::{Client, ProcError};
use crate::runner::Event;
use crate::schedule::Schedule;
use crate::sink::{Ask, Directive, Sink};
use crate::stop::Stop;

const TIMEOUT: Duration = Duration::from_secs(60);
const OUTPUT_LIMIT: usize = 256 * 1024;
const ACCOUNT_LIMIT: usize = 16;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Identity {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    email: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    organization: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    account_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    account_name: Option<String>,
}

impl Identity {
    fn account(&self, provider: Provider) -> Result<Option<String>, ()> {
        let valid = |value: &str| {
            !value.trim().is_empty() && value.chars().count() <= TEXT_LIMIT && !value.chars().any(char::is_control)
        };
        let only = match provider {
            Provider::Claude => self.account_id.is_none() && self.account_name.is_none(),
            Provider::Codex => self.email.is_none() && self.organization.is_none() && self.account_name.is_none(),
            Provider::Antigravity => self.email.is_none() && self.organization.is_none() && self.account_id.is_none(),
        };
        if !only {
            return Err(());
        }
        match provider {
            Provider::Claude => {
                let email = self.email.as_deref().filter(|v| valid(v)).ok_or(())?;
                let organization = self.organization.as_deref().ok_or(())?;
                if organization.chars().count() > TEXT_LIMIT || organization.chars().any(char::is_control) {
                    return Err(());
                }
                Ok(Some(pseudonym(provider, &format!("{email}/{organization}"))))
            }
            Provider::Codex => {
                Ok(Some(pseudonym(provider, self.account_id.as_deref().filter(|v| valid(v)).ok_or(())?)))
            }
            Provider::Antigravity => {
                self.account_name.as_deref().filter(|v| valid(v)).ok_or(())?;
                Ok(None)
            }
        }
    }

    fn key(&self, provider: Provider) -> Result<String, ()> {
        Ok(self.account(provider)?.unwrap_or_else(|| self.account_name.as_deref().unwrap().trim().to_lowercase()))
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Reply {
    version: u32,
    accounts: Vec<Account>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Account {
    provider: Provider,
    identity: Identity,
    plan: Option<String>,
    windows: Option<Vec<HookWindow>>,
    error: Option<ErrorKind>,
}

// The native timestamp decoder tolerates malformed times. A hook contract must not.
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct HookWindow {
    id: String,
    kind: Kind,
    minutes: Option<u32>,
    label: Option<String>,
    used_percent: f64,
    resets_at: Option<String>,
}

impl From<HookWindow> for Window {
    fn from(value: HookWindow) -> Self {
        Self {
            id: value.id,
            kind: value.kind,
            minutes: value.minutes,
            label: value.label,
            used_percent: value.used_percent,
            resets_at: value.resets_at.as_deref().and_then(parse_time),
        }
    }
}

fn invalid(provider: Provider) -> Failure {
    Failure::new(provider, ErrorKind::InvalidOutput, "the hook returned an invalid v1 reply")
}

fn parse(provider: Provider, output: &[u8], measuring: bool) -> Result<Vec<Account>, Failure> {
    let reply: Reply = serde_json::from_slice(output).map_err(|_| invalid(provider))?;
    if reply.version != 1 || reply.accounts.len() > ACCOUNT_LIMIT {
        return Err(invalid(provider));
    }
    let mut seen = BTreeSet::new();
    for account in &reply.accounts {
        let key = account.identity.key(provider).map_err(|_| invalid(provider))?;
        if account.provider != provider || !seen.insert(key) {
            return Err(invalid(provider));
        }
        if !measuring {
            if account.windows.is_some() || account.error.is_some() || account.plan.is_some() {
                return Err(invalid(provider));
            }
            continue;
        }
        if account.error.is_some() {
            if account.windows.is_some() || account.plan.is_some() {
                return Err(invalid(provider));
            }
            continue;
        }
        let windows = account.windows.as_ref().ok_or_else(|| invalid(provider))?;
        let text = |value: &str| {
            !value.trim().is_empty() && value.chars().count() <= TEXT_LIMIT && !value.chars().any(char::is_control)
        };
        let mut ids = BTreeSet::new();
        if windows.is_empty()
            || windows.len() > 32
            || account.plan.as_deref().is_some_and(|v| !text(v))
            || windows.iter().any(|w| {
                !text(&w.id)
                    || !ids.insert(w.id.trim())
                    || !w.used_percent.is_finite()
                    || !(0.0..=100.0).contains(&w.used_percent)
                    || w.minutes == Some(0)
                    || w.resets_at.as_deref().is_some_and(|v| parse_time(v).is_none())
                    || w.label.as_deref().is_some_and(|v| !text(v))
            })
        {
            return Err(invalid(provider));
        }
    }
    Ok(reply.accounts)
}

pub(crate) struct Hook {
    provider: Provider,
    command: HookSettings,
    interval: u64,
    minimum: Option<u64>,
    eco: bool,
    discover_at: Millis,
    discovery_failures: u32,
    accounts: BTreeMap<String, Slot>,
}

struct Slot {
    identity: Identity,
    account: Option<String>,
    schedule: Schedule,
}

impl Hook {
    pub fn configured(config: &Config) -> Vec<Self> {
        config
            .providers
            .iter()
            .filter_map(|(&provider, settings)| {
                let command = settings.hook.clone().filter(|_| config.enabled(provider))?;
                Some(Self {
                    provider,
                    command,
                    interval: config.interval_ms(provider),
                    minimum: config.min_interval_ms(provider),
                    eco: config.eco(),
                    discover_at: 0,
                    discovery_failures: 0,
                    accounts: BTreeMap::new(),
                })
            })
            .collect()
    }

    pub fn provider(&self) -> Provider {
        self.provider
    }

    fn invoke(&self, identities: Option<Vec<&Identity>>, paths: &Paths, stop: &Stop) -> Result<Vec<Account>, Failure> {
        let measuring = identities.is_some();
        let request = match identities {
            Some(identities) => json!({"version": 1, "action": "measure", "accounts": identities}),
            None => json!({"version": 1, "action": "discover"}),
        };
        let output = Client::command_output(
            &self.command.path,
            &self.command.args,
            Some(serde_json::to_vec(&request).expect("hook request is serializable")),
            &paths.work,
            TIMEOUT,
            stop,
            OUTPUT_LIMIT,
        )
        .map_err(|error| {
            Failure::new(
                self.provider,
                match error {
                    ProcError::Timeout => ErrorKind::Timeout,
                    ProcError::NotFound => ErrorKind::NotInstalled,
                    _ => ErrorKind::Failed,
                },
                "the local hook did not complete successfully",
            )
        })?;
        parse(self.provider, &output, measuring)
    }

    fn discover(&mut self, paths: &Paths, stop: &Stop, now: Millis) -> Result<(), Failure> {
        let accounts = self.invoke(None, paths, stop)?;
        let mut before = std::mem::take(&mut self.accounts);
        for account in accounts {
            let key = account.identity.key(self.provider).map_err(|_| invalid(self.provider))?;
            let slot = match before.remove(&key) {
                Some(mut slot) => {
                    slot.identity = account.identity;
                    slot
                }
                None => Slot {
                    account: account.identity.account(self.provider).map_err(|_| invalid(self.provider))?,
                    identity: account.identity,
                    schedule: Schedule::new(&[self.interval], now, self.eco),
                },
            };
            self.accounts.insert(key, slot);
        }
        self.discovery_failures = 0;
        self.discover_at = now + self.interval as Millis;
        Ok(())
    }

    fn measure(&self, keys: &[String], paths: &Paths, stop: &Stop) -> Vec<Outcome> {
        let identities = keys.iter().map(|key| &self.accounts[key].identity).collect();
        let results = self.invoke(Some(identities), paths, stop).and_then(|accounts| {
            let mut results = BTreeMap::new();
            for account in accounts {
                let key = account.identity.key(self.provider).map_err(|_| invalid(self.provider))?;
                if !keys.contains(&key) {
                    return Err(invalid(self.provider));
                }
                let outcome = match account.error {
                    Some(error) => Err(Failure::new(self.provider, error, "the hook could not measure this account")),
                    None => {
                        let mut snapshot = Snapshot {
                            provider: self.provider,
                            account: account.identity.account(self.provider).map_err(|_| invalid(self.provider))?,
                            account_name: account.identity.account_name,
                            plan: account.plan,
                            observed_at: now_ms(),
                            via: "local-hook/v1".into(),
                            client: None,
                            stale_after_ms: self.interval,
                            windows: account.windows.unwrap().into_iter().map(Window::from).collect(),
                            resets: None,
                            resource_status: None,
                            balances: None,
                        };
                        snapshot.tidy();
                        Ok(snapshot)
                    }
                };
                results.insert(key, outcome);
            }
            Ok(results)
        });
        keys.iter()
            .map(|key| match &results {
                Ok(results) => results.get(key).cloned().unwrap_or_else(|| Err(invalid(self.provider))),
                Err(failure) => Err(failure.clone()),
            })
            .collect()
    }

    pub fn once(&mut self, paths: &Paths, stop: &Stop, each: &mut impl FnMut(&Outcome)) {
        if let Err(failure) = self.discover(paths, stop, now_ms()) {
            each(&Err(failure));
            return;
        }
        let keys = self.accounts.keys().cloned().collect::<Vec<_>>();
        if !keys.is_empty() {
            for outcome in self.measure(&keys, paths, stop) {
                each(&outcome);
            }
        }
    }

    pub fn shift(&mut self, back: Millis) {
        self.discover_at -= back;
        for slot in self.accounts.values_mut() {
            slot.schedule.shift(-back);
        }
    }

    pub fn tick(
        &mut self,
        paths: &Paths,
        stop: &Stop,
        sink: &mut dyn Sink,
        collectors: &[Provider],
        policy: &mut Option<MeasurementPolicy>,
        each: &mut impl FnMut(Event),
    ) -> bool {
        if stop.requested() || !sink.allows_measurement(self.provider) {
            return false;
        }
        let now = now_ms();
        if now >= self.discover_at {
            if let Err(failure) = self.discover(paths, stop, now) {
                self.discovery_failures = self.discovery_failures.saturating_add(1);
                self.discover_at = now_ms()
                    + (self.interval.saturating_mul(1 << self.discovery_failures.min(4)))
                        .min(900_000)
                        .max(self.interval) as Millis;
                if !stop.requested() {
                    let attempt = policy.as_ref().map(|p| p.attempt(self.provider, None, None));
                    let outcome = Err(failure);
                    sink.deliver_attempt(&outcome, attempt.as_ref());
                    each(Event::Measured(&outcome, self.discover_at));
                }
                return false;
            }
        }
        // A failed discovery suspends the roster without discarding its schedules.
        if self.discovery_failures > 0 || !self.accounts.values().any(|slot| !slot.schedule.asks(now).is_empty()) {
            return false;
        }
        // Send the full roster, not a singleton that would look like a changed login.
        let keys = self.accounts.keys().cloned().collect::<Vec<_>>();
        let asks = keys
            .iter()
            .map(|key| {
                let slot = &self.accounts[key];
                Ask {
                    provider: self.provider,
                    account: slot.account.as_deref(),
                    account_name: slot.identity.account_name.as_deref(),
                    active: false,
                    min_interval_ms: self.minimum,
                }
            })
            .collect::<Vec<_>>();
        let answer = sink.checkin_managed(&asks, collectors);
        *policy = answer.policy.or(policy.take());
        sink.flush();
        if stop.requested() || sink.refused().is_some() || !sink.allows_measurement(self.provider) {
            return true;
        }
        let now = now_ms();
        let mut selected = Vec::new();
        for (i, key) in keys.into_iter().enumerate() {
            let slot = self.accounts.get_mut(&key).unwrap();
            let directive = answer.directives.get(i).copied().unwrap_or(Directive::Unanswered);
            // A full identity roster must not accelerate an unrelated account's local
            // backoff when a legacy or unreachable hub supplies no per-account pace.
            if !slot.schedule.paced(0)
                && slot.schedule.asks(now).is_empty()
                && matches!(directive, Directive::Unanswered | Directive::Measure { paced: None })
            {
                continue;
            }
            slot.schedule.answer(&[(0, directive)], now);
            if let Some((_, next)) = slot.schedule.take_cleared() {
                let target = answer.accounts.get(i).cloned().flatten().or_else(|| slot.account.clone());
                let attempt = policy
                    .as_ref()
                    .map(|p| p.attempt(self.provider, target, answer.commands.get(i).cloned().flatten()));
                selected.push((key, next, attempt));
            }
        }
        if selected.is_empty() {
            return true;
        }
        let keys = selected.iter().map(|(key, _, _)| key.clone()).collect::<Vec<_>>();
        let outcomes = self.measure(&keys, paths, stop);
        if stop.requested() {
            return true;
        }
        for ((key, next_in, attempt), mut outcome) in selected.into_iter().zip(outcomes) {
            let schedule = &mut self.accounts.get_mut(&key).unwrap().schedule;
            let now = now_ms();
            let next = if let Some(next_in) = next_in {
                let stale = schedule.measured_paced(0, now, next_in);
                if let Ok(snapshot) = &mut outcome {
                    snapshot.stale_after_ms = stale;
                }
                now + next_in as Millis
            } else {
                schedule.unpace(0);
                let next = schedule.complete(0, now, &outcome, false, jitter());
                if let Ok(snapshot) = &mut outcome {
                    snapshot.stale_after_ms = schedule.stale_after_ms(0, now);
                }
                next
            };
            sink.deliver_attempt(&outcome, attempt.as_ref());
            each(Event::Measured(&outcome, next));
        }
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[cfg(unix)]
    use crate::measurement_policy::{AttemptContext, AttemptTarget, CollectorPolicy};
    use serde_json::Value;

    fn account(id: &str) -> Value {
        json!({"provider":"claude", "identity":{"email":id,"organization":"Example"}})
    }

    fn reply(accounts: Vec<Value>) -> Vec<u8> {
        serde_json::to_vec(&json!({"version":1,"accounts":accounts})).unwrap()
    }

    fn measured(mut account: Value) -> Value {
        account["windows"] = json!([{"id":"session","kind":"session","minutes":300,"usedPercent":12.5,
            "resetsAt":"2026-10-26T23:00:00Z"}]);
        account
    }

    #[test]
    fn hook_config_is_opt_in_strict_and_survives_serialization() {
        assert!(Hook::configured(&Config::default()).is_empty());
        let mut config = Config::default();
        config.providers.entry(Provider::Claude).or_default().hook =
            Some(HookSettings { path: std::env::current_exe().unwrap(), args: vec!["literal argument".into()] });
        let encoded = toml::to_string(&config).unwrap();
        assert_eq!(Config::parse(&encoded).unwrap(), config);
        assert_eq!(Hook::configured(&config).len(), 1);
        config.providers.get_mut(&Provider::Claude).unwrap().enabled = Some(false);
        assert!(Hook::configured(&config).is_empty());
        for path in ["relative", "~/hook", "hook --arg", "/absolute/hook.cmd", "/absolute/hook.BAT"] {
            let text = format!("[providers.claude.hook]\npath = {path:?}\n");
            assert!(Config::parse(&text).is_err(), "{path}");
        }
        config.providers.get_mut(&Provider::Claude).unwrap().hook.as_mut().unwrap().args = vec!["x".into(); 33];
        assert!(Config::parse(&toml::to_string(&config).unwrap()).is_err());
    }

    #[test]
    fn identities_match_native_collectors_and_duplicates_fail_closed() {
        let accounts = parse(Provider::Claude, &reply(vec![account("user@example.com")]), false).unwrap();
        assert_eq!(
            accounts[0].identity.account(Provider::Claude).unwrap().as_deref(),
            Some("73d68562e0a4449082684fee")
        );
        assert!(
            parse(Provider::Claude, &reply(vec![account("user@example.com"), account("USER@example.com")]), false)
                .is_err()
        );
        let codex = json!({"provider":"codex","identity":{"accountId":"acc-1"}});
        assert_eq!(
            parse(Provider::Codex, &reply(vec![codex]), false).unwrap()[0].identity.account(Provider::Codex).unwrap(),
            Some(pseudonym(Provider::Codex, "acc-1"))
        );
        let agy = json!({"provider":"antigravity","identity":{"accountName":"work"}});
        let agy = parse(Provider::Antigravity, &reply(vec![agy]), false).unwrap();
        assert_eq!(agy[0].identity.account(Provider::Antigravity).unwrap(), None);
        assert_eq!(agy[0].identity.key(Provider::Antigravity).unwrap(), "work");
    }

    #[test]
    fn antigravity_names_use_the_hubs_case_insensitive_identity() {
        let account = |name| json!({"provider":"antigravity","identity":{"accountName":name}});
        let accounts = parse(Provider::Antigravity, &reply(vec![account(" Work ")]), false).unwrap();
        assert_eq!(accounts[0].identity.key(Provider::Antigravity).unwrap(), "work");
        for measuring in [false, true] {
            let accounts = vec![account("work"), account(" Work ")];
            let accounts = if measuring { accounts.into_iter().map(measured).collect() } else { accounts };
            assert!(parse(Provider::Antigravity, &reply(accounts), measuring).is_err());
        }
    }

    #[test]
    fn contract_rejects_malformed_versions_identity_windows_and_credentials() {
        for bytes in [
            b"not JSON".as_slice(),
            br#"{"version":2,"accounts":[]}"#,
            br#"{"version":1,"accounts":[],"token":"synthetic"}"#,
        ] {
            assert!(parse(Provider::Claude, bytes, false).is_err());
        }
        assert!(parse(Provider::Claude, &reply(vec![account("user@example.com"); 17]), false).is_err());
        for mut value in [account(""), account("user@example.com")] {
            value["identity"]["access_token"] = json!("synthetic");
            let failure = parse(Provider::Claude, &reply(vec![value]), false).err().unwrap();
            assert!(!format!("{failure:?}").contains("synthetic"));
        }
        let good = measured(account("user@example.com"));
        assert!(parse(Provider::Claude, &reply(vec![good.clone()]), true).is_ok());
        assert!(parse(Provider::Claude, &reply(vec![good.clone()]), false).is_err());
        for (field, value) in [
            ("usedPercent", json!(-1)),
            ("usedPercent", json!(101)),
            ("minutes", json!(0)),
            ("resetsAt", json!("bad")),
            ("id", json!("")),
            ("kind", json!("unknown")),
        ] {
            let mut bad = good.clone();
            bad["windows"][0][field] = value;
            assert!(parse(Provider::Claude, &reply(vec![bad]), true).is_err(), "{field}");
        }
        let mut bad = good.clone();
        bad["windows"].as_array_mut().unwrap().push(good["windows"][0].clone());
        assert!(parse(Provider::Claude, &reply(vec![bad]), true).is_err());
        let mut bad = good;
        bad["provider"] = json!("codex");
        assert!(parse(Provider::Claude, &reply(vec![bad]), true).is_err());
        let mut failure = account("user@example.com");
        failure["error"] = json!("not_logged_in");
        assert!(parse(Provider::Claude, &reply(vec![failure.clone()]), true).is_ok());
        failure["windows"] = json!([]);
        assert!(parse(Provider::Claude, &reply(vec![failure]), true).is_err());
    }

    #[cfg(unix)]
    fn policy(enabled: bool) -> MeasurementPolicy {
        MeasurementPolicy {
            version: 1,
            authority: "11111111-1111-4111-8111-111111111111".into(),
            revision: 1,
            enabled,
            collectors: Provider::ALL
                .into_iter()
                .map(|p| (p, CollectorPolicy { enabled: true, epoch: 2, requires_epoch: true, changed_at: None }))
                .collect(),
        }
    }

    #[cfg(unix)]
    struct Fixture {
        paths: Paths,
        hook: Hook,
    }

    #[cfg(unix)]
    impl Fixture {
        fn new(body: &str) -> Self {
            use std::os::unix::fs::PermissionsExt;
            let state = std::env::temp_dir().join(format!("quotum-hook-{}", crate::config::random_hex()));
            let paths = Paths { config: state.join("config.toml"), work: state.join("work"), state };
            paths.ensure().unwrap();
            let program = paths.state.join("hook");
            std::fs::write(&program, format!("#!/bin/sh\n{body}\n")).unwrap();
            std::fs::set_permissions(&program, std::fs::Permissions::from_mode(0o700)).unwrap();
            let mut config = Config::default();
            config.providers.entry(Provider::Claude).or_default().hook =
                Some(HookSettings { path: program, args: vec![] });
            Self { paths, hook: Hook::configured(&config).remove(0) }
        }
    }

    #[cfg(unix)]
    impl Drop for Fixture {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.paths.state);
        }
    }

    #[cfg(unix)]
    struct Recording {
        policy: MeasurementPolicy,
        asks: Vec<Vec<Option<String>>>,
        outcomes: Vec<(Outcome, Option<AttemptContext>)>,
        deny_second: bool,
        deny_on_checkin: bool,
        unreachable: bool,
    }

    #[cfg(unix)]
    impl Recording {
        fn new() -> Self {
            Self {
                policy: policy(true),
                asks: vec![],
                outcomes: vec![],
                deny_second: false,
                deny_on_checkin: false,
                unreachable: false,
            }
        }
    }

    #[cfg(unix)]
    impl Sink for Recording {
        fn deliver(&mut self, outcome: &Outcome) {
            self.outcomes.push((outcome.clone(), None));
        }
        fn allows_measurement(&self, provider: Provider) -> bool {
            self.policy.allows(provider)
        }
        fn deliver_attempt(&mut self, outcome: &Outcome, context: Option<&AttemptContext>) {
            self.outcomes.push((outcome.clone(), context.cloned()));
        }
        fn checkin_managed(&mut self, asks: &[Ask], collectors: &[Provider]) -> crate::sink::CheckinAnswer {
            assert_eq!(collectors, [Provider::Claude]);
            self.asks.push(asks.iter().map(|a| a.account.map(str::to_string)).collect());
            if self.unreachable {
                return crate::sink::CheckinAnswer {
                    directives: vec![Directive::Unanswered; asks.len()],
                    commands: vec![None; asks.len()],
                    accounts: vec![None; asks.len()],
                    policy: None,
                };
            }
            if self.deny_on_checkin {
                self.policy.enabled = false;
            }
            crate::sink::CheckinAnswer {
                directives: asks
                    .iter()
                    .enumerate()
                    .map(|(i, _)| {
                        if self.deny_second && i == 1 {
                            Directive::Wait { ask_at: now_ms() + 60000, on_duty: false }
                        } else {
                            Directive::Measure {
                                paced: Some(crate::sink::Paced { ask_at: now_ms() + 15000, next_in_ms: 120000 }),
                            }
                        }
                    })
                    .collect(),
                commands: asks
                    .iter()
                    .enumerate()
                    .map(|(i, _)| Some(format!("22222222-2222-4222-8222-{i:012x}")))
                    .collect(),
                accounts: asks.iter().map(|a| a.account.map(str::to_string)).collect(),
                policy: Some(self.policy.clone()),
            }
        }
    }

    #[cfg(unix)]
    fn body(accounts: &[Value]) -> String {
        let discover = String::from_utf8(reply(accounts.to_vec())).unwrap();
        let measure = String::from_utf8(reply(accounts.iter().cloned().map(measured).collect())).unwrap();
        format!(
            "IFS= read -r request\nprintf '%s' \"$request\" > request\ncase \"$request\" in\n*discover*) printf '%s' '{discover}' ;;\n*) printf '%s' '{measure}' ;;\nesac"
        )
    }

    #[cfg(unix)]
    #[test]
    fn multiple_accounts_keep_distinct_commands_and_never_supply_native_login_evidence() {
        let mut fixture = Fixture::new(&body(&[account("one@example.com"), account("two@example.com")]));
        let mut sink = Recording::new();
        let mut policy = None;
        fixture.hook.tick(&fixture.paths, &Stop::new(), &mut sink, &[Provider::Claude], &mut policy, &mut |_| {});
        assert_eq!(sink.asks[0].len(), 2);
        assert_eq!(sink.outcomes.len(), 2);
        for (outcome, context) in &sink.outcomes {
            let snapshot = outcome.as_ref().unwrap();
            let context = context.as_ref().unwrap();
            assert_eq!(context.target, AttemptTarget::Verified { account_key: snapshot.account.clone().unwrap() });
            assert!(context.command_id.is_some());
            assert_eq!(context.collector_epoch, 2);
            assert_eq!(snapshot.via, "local-hook/v1");
            assert_eq!(snapshot.stale_after_ms, 204000);
            let serialized = serde_json::to_string(snapshot).unwrap();
            assert!(!serialized.contains("@"));
            assert!(!serialized.contains("Example"));
        }
        assert_ne!(sink.outcomes[0].0.as_ref().unwrap().account, sink.outcomes[1].0.as_ref().unwrap().account);
        assert_ne!(sink.outcomes[0].1.as_ref().unwrap().command_id, sink.outcomes[1].1.as_ref().unwrap().command_id);
        let before = sink.outcomes.len();
        fixture.hook.tick(&fixture.paths, &Stop::new(), &mut sink, &[Provider::Claude], &mut policy, &mut |_| {});
        assert_eq!(sink.outcomes.len(), before, "no extra invocation before the next hub check-in");
    }

    #[cfg(unix)]
    #[test]
    fn selection_is_sent_on_stdin_and_unrequested_accounts_fail_closed() {
        let mut fixture = Fixture::new(&body(&[account("one@example.com"), account("two@example.com")]));
        let mut sink = Recording::new();
        sink.deny_second = true;
        let mut policy = None;
        fixture.hook.tick(&fixture.paths, &Stop::new(), &mut sink, &[Provider::Claude], &mut policy, &mut |_| {});
        assert_eq!(sink.outcomes.len(), 1);
        assert_eq!(sink.outcomes[0].0.as_ref().unwrap_err().error, ErrorKind::InvalidOutput);
        let request: Value =
            serde_json::from_slice(&std::fs::read(fixture.paths.work.join("request")).unwrap()).unwrap();
        assert_eq!(request["action"], "measure");
        assert_eq!(request["accounts"].as_array().unwrap().len(), 1);
        let identity: Identity = serde_json::from_value(request["accounts"][0].clone()).unwrap();
        assert_eq!(identity.account(Provider::Claude).unwrap(), sink.asks[0][0]);
    }

    #[cfg(unix)]
    #[test]
    fn denial_and_stop_prevent_discovery_and_a_new_denial_prevents_measurement() {
        let mut fixture = Fixture::new(&body(&[account("one@example.com")]));
        let mut sink = Recording::new();
        sink.policy.enabled = false;
        let mut policy = None;
        fixture.hook.tick(&fixture.paths, &Stop::new(), &mut sink, &[Provider::Claude], &mut policy, &mut |_| {});
        assert!(!fixture.paths.work.join("request").exists());
        sink.policy.enabled = true;
        let stop = Stop::new();
        stop.request(crate::stop::How::Exit);
        fixture.hook.tick(&fixture.paths, &stop, &mut sink, &[Provider::Claude], &mut policy, &mut |_| {});
        assert!(!fixture.paths.work.join("request").exists());
        sink.deny_on_checkin = true;
        fixture.hook.tick(&fixture.paths, &Stop::new(), &mut sink, &[Provider::Claude], &mut policy, &mut |_| {});
        let request: Value =
            serde_json::from_slice(&std::fs::read(fixture.paths.work.join("request")).unwrap()).unwrap();
        assert_eq!(request["action"], "discover");
        assert!(sink.outcomes.is_empty(), "a denial learned after discovery starts no measurement");
    }

    #[cfg(unix)]
    #[test]
    fn partial_success_and_missing_accounts_are_isolated_and_discovery_recovers() {
        let mut fixture = Fixture::new(&body(&[account("one@example.com"), account("two@example.com")]));
        let stop = Stop::new();
        fixture.hook.discover(&fixture.paths, &stop, now_ms()).unwrap();
        let keys = fixture.hook.accounts.keys().cloned().collect::<Vec<_>>();
        let identity = serde_json::to_value(&fixture.hook.accounts[&keys[0]].identity).unwrap();
        let one = measured(json!({"provider":"claude","identity":identity}));
        let output = String::from_utf8(reply(vec![one])).unwrap();
        std::fs::write(&fixture.hook.command.path, format!("#!/bin/sh\nprintf '%s' '{output}'\n")).unwrap();
        let outcomes = fixture.hook.measure(&keys, &fixture.paths, &stop);
        assert!(outcomes[0].is_ok());
        assert_eq!(outcomes[1].as_ref().unwrap_err().error, ErrorKind::InvalidOutput);
        std::fs::write(&fixture.hook.command.path, "#!/bin/sh\nprintf 'private-invalid-output'\n").unwrap();
        fixture.hook.discover_at = 0;
        let mut sink = Recording::new();
        let mut policy = Some(sink.policy.clone());
        fixture.hook.tick(&fixture.paths, &stop, &mut sink, &[Provider::Claude], &mut policy, &mut |_| {});
        assert_eq!(fixture.hook.accounts.len(), 2, "unconfirmed accounts retain their schedules");
        assert!(fixture.hook.discover_at > now_ms());
        assert!(!fixture.hook.tick(&fixture.paths, &stop, &mut sink, &[Provider::Claude], &mut policy, &mut |_| {}));
        assert!(sink.asks.is_empty(), "an unconfirmed roster is not checked in or measured");
        assert_eq!(sink.outcomes[0].1.as_ref().unwrap().target, AttemptTarget::Unknown);
        assert!(!format!("{:?}", sink.outcomes[0]).contains("private-invalid-output"));
        std::fs::write(&fixture.hook.command.path, format!("#!/bin/sh\n{}\n", body(&[account("one@example.com")])))
            .unwrap();
        fixture.hook.discover_at = 0;
        fixture.hook.tick(&fixture.paths, &stop, &mut sink, &[Provider::Claude], &mut policy, &mut |_| {});
        assert_eq!(fixture.hook.accounts.len(), 1);
        assert!(sink.outcomes.last().unwrap().0.is_ok());
    }

    #[cfg(unix)]
    #[test]
    fn antigravity_case_changes_match_measurements_and_preserve_schedules() {
        let original = json!({"provider":"antigravity","identity":{"accountName":"Work"}});
        let changed = json!({"provider":"antigravity","identity":{"accountName":"work"}});
        let mut fixture = Fixture::new(&body(&[original]));
        fixture.hook.provider = Provider::Antigravity;
        let stop = Stop::new();
        fixture.hook.discover(&fixture.paths, &stop, 100).unwrap();
        let keys = fixture.hook.accounts.keys().cloned().collect::<Vec<_>>();
        std::fs::write(&fixture.hook.command.path, format!("#!/bin/sh\n{}\n", body(&[changed]))).unwrap();
        let outcomes = fixture.hook.measure(&keys, &fixture.paths, &stop);
        let snapshot = outcomes[0].as_ref().unwrap();
        assert_eq!(snapshot.account, None);
        assert_eq!(snapshot.account_name.as_deref(), Some("work"));
        fixture
            .hook
            .accounts
            .get_mut(&keys[0])
            .unwrap()
            .schedule
            .answer(&[(0, Directive::Wait { ask_at: 10000, on_duty: false })], 100);
        let due = fixture.hook.accounts[&keys[0]].schedule.due(0);
        fixture.hook.discover(&fixture.paths, &stop, 200).unwrap();
        assert_eq!(fixture.hook.accounts.len(), 1);
        assert_eq!(fixture.hook.accounts[&keys[0]].schedule.due(0), due);
        assert_eq!(fixture.hook.accounts[&keys[0]].identity.account_name.as_deref(), Some("work"));
    }

    #[cfg(unix)]
    #[test]
    fn discovery_recovery_keeps_local_failure_backoff_with_an_unreachable_hub() {
        let script = body(&[account("one@example.com")]);
        let mut fixture = Fixture::new(&script);
        let stop = Stop::new();
        fixture.hook.discover(&fixture.paths, &stop, now_ms()).unwrap();
        let key = fixture.hook.accounts.keys().next().unwrap().clone();
        let failure = Err(Failure::new(Provider::Claude, ErrorKind::NotLoggedIn, "not logged in"));
        let now = now_ms();
        let due = fixture.hook.accounts.get_mut(&key).unwrap().schedule.complete(0, now, &failure, false, 0.0);
        assert_eq!(due, now + 900000);
        std::fs::write(&fixture.hook.command.path, "#!/bin/sh\nexit 1\n").unwrap();
        fixture.hook.discover_at = 0;
        let mut sink = Recording::new();
        sink.unreachable = true;
        fixture.hook.tick(&fixture.paths, &stop, &mut sink, &[Provider::Claude], &mut None, &mut |_| {});
        assert_eq!(fixture.hook.accounts[&key].schedule.due(0), due);
        assert_eq!(sink.outcomes.len(), 1);
        assert!(sink.asks.is_empty());
        // Even an overdue account must not use a roster whose discovery failed.
        fixture.hook.accounts.get_mut(&key).unwrap().schedule.shift(-1000000);
        assert!(!fixture.hook.tick(&fixture.paths, &stop, &mut sink, &[Provider::Claude], &mut None, &mut |_| {}));
        assert!(sink.asks.is_empty());
        fixture.hook.accounts.get_mut(&key).unwrap().schedule.shift(1000000);
        std::fs::write(&fixture.hook.command.path, format!("#!/bin/sh\n{script}\n")).unwrap();
        fixture.hook.discover_at = 0;
        fixture.hook.tick(&fixture.paths, &stop, &mut sink, &[Provider::Claude], &mut None, &mut |_| {});
        assert_eq!(fixture.hook.accounts[&key].schedule.due(0), due);
        assert_eq!(sink.outcomes.len(), 1, "recovery does not measure before the backoff expires");
        assert!(sink.asks.is_empty());
        fixture.hook.accounts.get_mut(&key).unwrap().schedule.shift(-1000000);
        fixture.hook.tick(&fixture.paths, &stop, &mut sink, &[Provider::Claude], &mut None, &mut |_| {});
        assert_eq!(sink.asks.len(), 1);
        assert_eq!(sink.outcomes.len(), 2);
        assert!(sink.outcomes[1].0.is_ok());
    }

    #[cfg(unix)]
    #[test]
    fn discovery_recovery_keeps_the_original_offline_fallback_deadline() {
        let script = body(&[account("one@example.com")]);
        let mut fixture = Fixture::new(&script);
        let stop = Stop::new();
        let mut sink = Recording::new();
        let mut policy = None;
        fixture.hook.tick(&fixture.paths, &stop, &mut sink, &[Provider::Claude], &mut policy, &mut |_| {});
        let key = fixture.hook.accounts.keys().next().unwrap().clone();
        assert!(fixture.hook.accounts[&key].schedule.paced(0));
        assert!(sink.outcomes[0].0.is_ok());
        let due = fixture.hook.accounts[&key].schedule.due(0);
        // Make the check-in overdue while keeping its four-minute fallback in the future.
        fixture.hook.accounts.get_mut(&key).unwrap().schedule.shift(-30000);
        std::fs::write(&fixture.hook.command.path, "#!/bin/sh\nexit 1\n").unwrap();
        fixture.hook.discover_at = 0;
        sink.unreachable = true;
        fixture.hook.tick(&fixture.paths, &stop, &mut sink, &[Provider::Claude], &mut policy, &mut |_| {});
        assert_eq!(fixture.hook.accounts[&key].schedule.due(0), due - 30000);
        assert_eq!(sink.outcomes.len(), 2);
        std::fs::write(&fixture.hook.command.path, format!("#!/bin/sh\n{script}\n")).unwrap();
        fixture.hook.discover_at = 0;
        fixture.hook.tick(&fixture.paths, &stop, &mut sink, &[Provider::Claude], &mut policy, &mut |_| {});
        assert_eq!(sink.asks.len(), 2, "recovery checks in with the unreachable hub");
        assert_eq!(sink.outcomes.len(), 2, "recovery must still wait for offline fallback");
        assert!(fixture.hook.accounts[&key].schedule.paced(0));
        fixture.hook.accounts.get_mut(&key).unwrap().schedule.shift(-215000);
        fixture.hook.tick(&fixture.paths, &stop, &mut sink, &[Provider::Claude], &mut policy, &mut |_| {});
        assert_eq!(sink.asks.len(), 3);
        assert_eq!(sink.outcomes.len(), 3);
        assert!(sink.outcomes[2].0.is_ok(), "the original fallback eventually permits measurement");
        assert!(!fixture.hook.accounts[&key].schedule.paced(0));
    }

    #[cfg(unix)]
    #[test]
    fn a_partial_due_set_preserves_full_roster_evidence_and_independent_local_backoff() {
        let mut fixture = Fixture::new(&body(&[account("one@example.com"), account("two@example.com")]));
        let stop = Stop::new();
        fixture.hook.discover(&fixture.paths, &stop, now_ms()).unwrap();
        let keys = fixture.hook.accounts.keys().cloned().collect::<Vec<_>>();
        let identity = serde_json::to_value(&fixture.hook.accounts[&keys[0]].identity).unwrap();
        let output =
            String::from_utf8(reply(vec![measured(json!({"provider":"claude","identity":identity}))])).unwrap();
        std::fs::write(&fixture.hook.command.path, format!("#!/bin/sh\ncat > request\nprintf '%s' '{output}'\n"))
            .unwrap();
        let mut sink = Recording::new();
        sink.deny_second = true;
        let mut policy = None;
        assert!(fixture.hook.tick(&fixture.paths, &stop, &mut sink, &[Provider::Claude], &mut policy, &mut |_| {}));
        assert_eq!(sink.asks[0].len(), 2);
        assert_eq!(sink.outcomes.len(), 1);
        assert!(sink.outcomes[0].0.is_ok());
        // With a legacy sink, one due account does not pull another account forward.
        fixture.hook.accounts.get_mut(&keys[0]).unwrap().schedule = Schedule::new(&[120000], now_ms(), false);
        fixture.hook.accounts.get_mut(&keys[1]).unwrap().schedule = Schedule::new(&[120000], now_ms() + 60000, false);
        let mut observed = Vec::new();
        fixture.hook.tick(
            &fixture.paths,
            &stop,
            &mut crate::sink::Discard,
            &[Provider::Claude],
            &mut None,
            &mut |event| {
                if let Event::Measured(outcome, _) = event {
                    observed.push(outcome.clone());
                }
            },
        );
        assert_eq!(observed.len(), 1);
        assert!(observed[0].is_ok());
        assert!(!fixture.hook.tick(
            &fixture.paths,
            &stop,
            &mut crate::sink::Discard,
            &[Provider::Claude],
            &mut None,
            &mut |_| {}
        ));
    }

    #[cfg(unix)]
    #[test]
    fn runner_replaces_only_measurements_and_honors_only_without_starting_native_clients() {
        let fixture = Fixture::new(&body(&[account("one@example.com"), account("two@example.com")]));
        let mut config = Config::default();
        for provider in Provider::ALL {
            config.providers.entry(provider).or_default().enabled = Some(provider == Provider::Claude);
        }
        config.providers.get_mut(&Provider::Claude).unwrap().hook = Some(fixture.hook.command.clone());
        let mut runner = crate::runner::Runner::new(config.clone(), fixture.paths.clone(), &[], Stop::new());
        assert_eq!(runner.providers(), [Provider::Claude]);
        let mut outcomes = Vec::new();
        runner.measure_all(|outcome| outcomes.push(outcome.clone()));
        assert_eq!(outcomes.len(), 2);
        assert!(outcomes.iter().all(Result::is_ok));
        assert!(runner.clients().contains(&crate::clients::ClientId::Claude));
        std::fs::remove_file(fixture.paths.work.join("request")).unwrap();
        let mut runner =
            crate::runner::Runner::new(config, fixture.paths.clone(), &[crate::clients::ClientId::Codex], Stop::new());
        runner.measure_all(|_| panic!("excluded hook must not run"));
        assert!(!fixture.paths.work.join("request").exists());
    }

    #[cfg(unix)]
    #[test]
    fn roster_refresh_preserves_schedules_and_removes_disappeared_accounts() {
        let mut fixture = Fixture::new(&body(&[account("one@example.com"), account("two@example.com")]));
        let stop = Stop::new();
        fixture.hook.discover(&fixture.paths, &stop, 100).unwrap();
        let key = fixture.hook.accounts.keys().next().unwrap().clone();
        fixture
            .hook
            .accounts
            .get_mut(&key)
            .unwrap()
            .schedule
            .answer(&[(0, Directive::Wait { ask_at: 10000, on_duty: false })], 100);
        let before = fixture.hook.accounts[&key].schedule.due(0);
        fixture.hook.discover(&fixture.paths, &stop, 200).unwrap();
        assert_eq!(fixture.hook.accounts[&key].schedule.due(0), before);
        std::fs::write(&fixture.hook.command.path, format!("#!/bin/sh\n{}\n", body(&[account("two@example.com")])))
            .unwrap();
        fixture.hook.discover(&fixture.paths, &stop, 300).unwrap();
        assert_eq!(fixture.hook.accounts.len(), 1);
    }
}
