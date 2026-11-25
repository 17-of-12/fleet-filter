//! Client classification: the controller's rendered map plus a memo of the gateway's own
//! detections (Bundle R4).
//!
//! Why this exists at all: once the gateway fronts Apache, the backend can no longer classify a
//! client by its socket address, because the address Apache sees is the gateway's. Apache's
//! `RewriteMap` lookup uses the *peer* address, and the gateway's own address is allowlisted so
//! the proxy does not quarantine itself. That moves the enforcement point for per-client
//! quarantine to the gateway, and the gateway needs the same answer Apache would have given.
//!
//! The answer comes from two places, in this order:
//!   1. a memo of detections this process just made, so a client is not re-classified as normal
//!      during the window between "we saw this" and "the controller rendered a new map" (measured
//!      in R5 as minutes, not milliseconds);
//!   2. the rendered `/etc/httpd/tarpit-ips.map`, refreshed on a TTL rather than per request, so
//!      a burst of requests from one client does not turn classification into a file-syscall storm.
//!
//! The failure mode the bundle calls out explicitly is a *silent* degrade to allow: if the map
//! cannot be read, answering "normal" for every client is what makes a controller outage invisible.
//! Here the previous map is kept, the failure is counted and logged (rate-limited), and the
//! behaviour with no map at all is a named configuration choice rather than an accident.

use std::collections::HashMap;
use std::fs;
use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

/// The controller's map format is one address and one value per line; anything else is a parse
/// error rather than a line to guess about.
const MAX_MAP_BYTES: u64 = 4 * 1024 * 1024;

/// PTN-14: how old the rendered map may get before its quarantine entries stop being trusted.
///
/// The number lives in the policy layer (`policy::DEFAULT_MAP_MAX_AGE_SECS`) so a bundle and the
/// binary running it can never disagree about the age they are enforcing; this is the same value
/// expressed as a `Duration` for the runtime.
const DEFAULT_MAP_MAX_AGE: Duration = Duration::from_secs(crate::policy::DEFAULT_MAP_MAX_AGE_SECS);

/// What the controller (or this process) says about one address.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Verdict {
    /// Not quarantined.
    Normal,
    /// Quarantined and inside the quota: Stage 1 would slow-drip this client.
    Tarpitted,
    /// Quarantined but past the quota: Stage 1 answers with a cheap local reject.
    OverQuota,
}

impl Verdict {
    /// Parse the RewriteMap value for an address (`0`, `1`, `2`).
    fn from_map_value(raw: &str) -> Option<Verdict> {
        match raw {
            "0" => Some(Verdict::Normal),
            "1" => Some(Verdict::Tarpitted),
            "2" => Some(Verdict::OverQuota),
            _ => None,
        }
    }

    /// Lower-case label used in logs and in the `X-Fleet-Filter-Class` header.
    pub fn label(&self) -> &'static str {
        match self {
            Verdict::Normal => "normal",
            Verdict::Tarpitted => "tarpitted",
            Verdict::OverQuota => "over-quota",
        }
    }

    /// The claim verdict this classification implies when reporting a detection upstream.
    ///
    /// A local detection is always `confirmed` (the owner's rule: sending exploit code is 100%
    /// certainty), and a quarantined address read from the map is reported as `confirmed` too,
    /// because the map does not carry the suspect/confirmed distinction - only the state does.
    pub fn claim_verdict(&self) -> &'static str {
        match self {
            Verdict::Normal => "suspect",
            Verdict::Tarpitted | Verdict::OverQuota => "confirmed",
        }
    }
}

/// Where a classification came from, which is what makes "we are guessing" visible.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Source {
    /// The rendered map (refreshed within the TTL).
    Map,
    /// A detection this process made and has not yet seen reflected in the map.
    Memo,
    /// No map has ever been loaded and the configured fallback is being applied.
    Fallback,
    /// Classification is disabled (`--map` unset): every client is normal.
    Disabled,
    /// PTN-14: the map exists but is older than `map-max-age`, so its quarantine entries were
    /// refused and the configured fallback answered instead.
    StaleMap,
}

impl Source {
    /// Lower-case label for logs.
    fn label(&self) -> &'static str {
        match self {
            Source::Map => "map",
            Source::Memo => "memo",
            Source::Fallback => "fallback",
            Source::Disabled => "disabled",
            Source::StaleMap => "stale-map",
        }
    }
}

/// A classification result: the verdict plus the reason it can be trusted (or not).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Classification {
    pub verdict: Verdict,
    pub source: Source,
}

impl Classification {
    /// The value put in `X-Fleet-Filter-Class`: the verdict and its source in one token, so a
    /// captured response says whether the answer came from the map, a memo, or a fallback.
    pub fn header_value(&self) -> String {
        format!("{};source={}", self.verdict.label(), self.source.label())
    }
}

/// What to do when no map has ever been loaded. `Allow` is the default but it is never silent:
/// every request classified that way is labelled `fallback` in the log and counted.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Fallback {
    /// Serve normally (labelled and counted).
    Allow,
    /// Treat every client as quarantined.
    Tarpit,
    /// Treat every client as over quota (cheap local reject).
    Reject,
}

impl Fallback {
    /// Parse the `--map-fallback` value.
    pub fn parse(raw: &str) -> Option<Fallback> {
        match raw {
            "allow" => Some(Fallback::Allow),
            "tarpit" => Some(Fallback::Tarpit),
            "reject" => Some(Fallback::Reject),
            _ => None,
        }
    }

    /// The label used in the config fingerprint and in logs.
    pub fn label(&self) -> &'static str {
        match self {
            Fallback::Allow => "allow",
            Fallback::Tarpit => "tarpit",
            Fallback::Reject => "reject",
        }
    }

    /// The verdict this fallback yields.
    fn verdict(&self) -> Verdict {
        match self {
            Fallback::Allow => Verdict::Normal,
            Fallback::Tarpit => Verdict::Tarpitted,
            Fallback::Reject => Verdict::OverQuota,
        }
    }
}

/// One parsed map file, kept so the previous good state survives a failed refresh.
#[derive(Debug)]
struct MapFile {
    entries: HashMap<IpAddr, Verdict>,
    loaded_at: Instant,
    /// PTN-14: when the file itself was written, taken from the filesystem, not from the moment we
    /// read it. `loaded_at` cannot answer "is this map current?" because a gateway that re-reads a
    /// dead controller's frozen file every TTL keeps refreshing its own timestamp and looks fresh.
    generated_at: SystemTime,
}

/// The mutable part of the classifier, behind one mutex so a refresh cannot race a memo write.
#[derive(Debug)]
struct State {
    map: Option<MapFile>,
    memo: HashMap<IpAddr, (Verdict, Instant)>,
    /// Last full memo sweep, so pruning is rate-limited instead of running per request (PTN-11).
    last_prune: Option<Instant>,
    loads: u64,
    load_failures: u64,
    last_error: Option<String>,
    last_error_at: Option<Instant>,
}

impl State {
    /// Fresh state: nothing loaded, nothing memoised, no errors.
    fn new() -> State {
        State {
            map: None,
            memo: HashMap::new(),
            last_prune: None,
            loads: 0,
            load_failures: 0,
            last_error: None,
            last_error_at: None,
        }
    }
}

/// The classifier: map file + TTL + local detection memo.
pub struct Classifier {
    path: Option<PathBuf>,
    map_ttl: Duration,
    memo_ttl: Duration,
    /// PTN-14: the age past which a map's quarantine entries are refused (`0` = trust any age).
    map_max_age: Duration,
    fallback: Fallback,
    /// Minimum seconds between two "map load failed" log lines for the same condition. A gateway
    /// that logs every request would bury the one message an operator needs.
    error_log_interval: Duration,
    state: Mutex<State>,
}

impl Classifier {
    /// Build a classifier. `path: None` disables map-based classification entirely.
    pub fn new(
        path: Option<String>,
        map_ttl: Duration,
        memo_ttl: Duration,
        fallback: Fallback,
    ) -> Classifier {
        Classifier {
            path: path.map(PathBuf::from),
            map_ttl,
            memo_ttl,
            map_max_age: DEFAULT_MAP_MAX_AGE,
            fallback,
            error_log_interval: Duration::from_secs(60),
            state: Mutex::new(State::new()),
        }
    }

    /// Override the PTN-14 staleness bound; `0` means "trust a map however old it is".
    pub fn with_max_age(mut self, map_max_age: Duration) -> Classifier {
        self.map_max_age = map_max_age;
        self
    }

    /// PTN-14: how long a rendered map stays trustworthy, for `--show-policy` and tests.
    pub fn map_max_age(&self) -> Duration {
        self.map_max_age
    }

    /// A stable description of the settings, used to decide whether a reload may reuse this instance.
    ///
    /// A policy reload that changes only the posture must not discard the map cache or the detection
    /// memo, so the comparison is a fingerprint rather than a field-by-field diff at the call site.
    pub fn fingerprint(&self) -> String {
        format!(
            "map={}|ttl={}|memo={}|max_age={}|fallback={}",
            self.path
                .as_ref()
                .map(|p| p.to_string_lossy().to_string())
                .unwrap_or_else(|| "disabled".to_string()),
            self.map_ttl.as_secs(),
            self.memo_ttl.as_secs(),
            self.map_max_age.as_secs(),
            self.fallback.label(),
        )
    }

    /// Parse a rendered RewriteMap into address -> verdict entries.
    ///
    /// Rules mirror the controller's renderer rather than inventing a dialect: comments start with
    /// `#`, fields are whitespace-separated, the address must parse as an IP, and the value must be
    /// `0`, `1`, or `2`. A duplicate address is not a coin flip - the controller guarantees unique
    /// keys, so a duplicate means the file was hand-edited and the whole file is rejected rather
    /// than silently resolved.
    pub fn parse_map(text: &str) -> Result<HashMap<IpAddr, Verdict>, String> {
        let mut entries = HashMap::new();
        for (number, line) in text.lines().enumerate() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            let mut fields = line.split_whitespace();
            let address = fields.next().unwrap_or("");
            // A line with one field is a truncated render, not a bad address, and saying so is the
            // difference between "the value column is missing" and "the address column is wrong".
            let value = match fields.next() {
                Some(value) => value,
                None => return Err(format!("map line {}: missing value", number + 1)),
            };
            if fields.next().is_some() {
                return Err(format!("map line {}: too many fields", number + 1));
            }
            let ip = match address.parse::<IpAddr>() {
                Ok(ip) => ip,
                Err(error) => {
                    return Err(format!(
                        "map line {}: bad address {address:?} ({error})",
                        number + 1
                    ));
                }
            };
            let verdict = match Verdict::from_map_value(value) {
                Some(verdict) => verdict,
                None => return Err(format!("map line {}: bad value {value:?}", number + 1)),
            };
            if entries.insert(ip, verdict).is_some() {
                return Err(format!("map line {}: duplicate address {ip}", number + 1));
            }
        }
        Ok(entries)
    }

    /// Classify one client address, refreshing the map first if it has gone stale.
    pub fn classify(&self, ip: IpAddr) -> Classification {
        let mut state = match self.state.lock() {
            Ok(guard) => guard,
            // A poisoned mutex means a previous holder panicked; the data is still the last
            // consistent state, so use it rather than losing classification for the request.
            Err(poisoned) => poisoned.into_inner(),
        };
        self.refresh_locked(&mut state);
        self.prune_locked(&mut state);

        if self.path.is_none() {
            return Classification {
                verdict: Verdict::Normal,
                source: Source::Disabled,
            };
        }
        // PTN-06: an explicit allow (`0`) in the map outranks this process's own detection. Without
        // this check an authorised scanner that tripped one signature is tarpitted for the whole memo
        // TTL even though the operator wrote it down as allowed.
        if Self::is_allowlisted(&state, ip) {
            return Classification {
                verdict: Verdict::Normal,
                source: Source::Map,
            };
        }
        // The memo wins over the map: it is the newer observation. The map can only *confirm* what
        // we already believe, and a shorter memo TTL means the map takes over as soon as the
        // controller has had its say.
        let memo = state
            .memo
            .get(&ip)
            .map(|(verdict, expires)| (*verdict, *expires > Instant::now()));
        if let Some((verdict, live)) = memo {
            if live {
                return Classification {
                    verdict,
                    source: Source::Memo,
                };
            }
            // Expired: drop it now rather than waiting for the next sweep, so a lookup never leaves
            // dead rows behind (PTN-11).
            state.memo.remove(&ip);
        }
        if let Some(map) = state.map.as_ref() {
            let entry = map.entries.get(&ip).copied();
            let stale = self.map_is_stale(map);
            return match entry {
                // An allow row (`0`) is a standing statement about a client we chose to trust, and it
                // does not expire the way a quarantine lease does. Withdrawing it because the file
                // aged out would quarantine an authorised scanner - the PTN-06 failure in a new
                // costume - so an allow entry (and a client the map simply says nothing about) stays
                // normal whatever the file's age; only the label changes.
                Some(Verdict::Normal) | None => Classification {
                    verdict: Verdict::Normal,
                    source: if stale { Source::StaleMap } else { Source::Map },
                },
                // PTN-14: a quarantine entry the map can no longer date. The map format carries one
                // value per address and no expiry, so once the controller stops rendering, every
                // entry in it silently outlives the lease behind it. The configured fallback answers
                // - the same answer the operator already gave for "this map is not readable" - and
                // the source says so instead of the gateway quietly holding the address forever.
                Some(_) if stale => Classification {
                    verdict: self.fallback.verdict(),
                    source: Source::StaleMap,
                },
                Some(verdict) => Classification {
                    verdict,
                    source: Source::Map,
                },
            };
        }
        Classification {
            verdict: self.fallback.verdict(),
            source: Source::Fallback,
        }
    }

    /// Record a detection made by this process so the next request from the same address is
    /// classified immediately, without waiting for the controller to drain and render.
    ///
    /// Only quarantined verdicts are memoised. Memoising `Normal` would freeze a client as
    /// acceptable for the memo window even after the controller quarantines it, which is the
    /// opposite of the point.
    pub fn memoize(&self, ip: IpAddr, verdict: Verdict) {
        if verdict == Verdict::Normal {
            return;
        }
        let mut state = match self.state.lock() {
            Ok(guard) => guard,
            Err(poisoned) => poisoned.into_inner(),
        };
        // PTN-06: the allowlist is checked before the memo is written, not after. Memoising an
        // allowlisted address is what turned "the gateway ignored my allow entry" into a
        // self-inflicted outage for one authorised scanner.
        if Self::is_allowlisted(&state, ip) {
            return;
        }
        self.prune_locked(&mut state);
        state
            .memo
            .insert(ip, (verdict, Instant::now() + self.memo_ttl));
    }

    /// How often the memo may be swept: a quarter of the memo TTL, never faster than one second.
    ///
    /// The sweep costs time proportional to the memo, so running it on every request would make the
    /// fix more expensive than the leak it prevents. A quarter of the TTL keeps the worst-case
    /// overshoot to one sweep interval while bounding the work to four sweeps per TTL.
    fn prune_interval(&self) -> Duration {
        let quarter = self.memo_ttl / 4;
        if quarter < Duration::from_secs(1) {
            Duration::from_secs(1)
        } else {
            quarter
        }
    }

    /// PTN-11: drop memo rows whose lease has lapsed.
    ///
    /// The control is time, not size. The owner's rule of 2026-11-16 is explicit that in-memory
    /// pruning must expire by age rather than by a cardinality cap, because a worm or a zero-day
    /// rotates through address pools continuously: a size cap evicts the newest - and therefore most
    /// relevant - observations first, which is the opposite of what a detection memo is for.
    fn prune_locked(&self, state: &mut State) {
        let now = Instant::now();
        if state
            .last_prune
            .map(|at| now.saturating_duration_since(at) < self.prune_interval())
            .unwrap_or(false)
        {
            return;
        }
        state.last_prune = Some(now);
        state.memo.retain(|_, (_, expires)| *expires > now);
    }

    /// PTN-06: does the rendered map carry an *explicit* allow (`0`) for this address?
    ///
    /// An allow entry is the operator's written word about one address, which is why it outranks both
    /// this process's own suspicion (the memo) and a quarantined map entry elsewhere. The absence of
    /// an entry is not an allow - that is the fallback's job - so only a literal `0` counts here.
    fn is_allowlisted(state: &State, ip: IpAddr) -> bool {
        matches!(
            state.map.as_ref().and_then(|map| map.entries.get(&ip)),
            Some(Verdict::Normal)
        )
    }

    /// Memo rows currently held, live or expired - the number the leak was measured in.
    pub fn memo_len(&self) -> usize {
        self.state
            .lock()
            .map(|state| state.memo.len())
            .unwrap_or_else(|poisoned| poisoned.into_inner().memo.len())
    }

    /// One-line status for logs and for the `--status` style checks.
    pub fn status(&self) -> String {
        let state = match self.state.lock() {
            Ok(guard) => guard,
            Err(poisoned) => poisoned.into_inner(),
        };
        let now = Instant::now();
        let entries = state.map.as_ref().map(|m| m.entries.len()).unwrap_or(0);
        let age = state
            .map
            .as_ref()
            .map(|m| now.saturating_duration_since(m.loaded_at).as_secs())
            .map(|v| v.to_string())
            .unwrap_or_else(|| "never".to_string());
        // PTN-14: `age_s` is how long since WE last read the file; `generated_s` is how long since
        // the controller wrote it. Only the second one can answer whether the controller is alive,
        // and `stale=` is the field an operator or a monitor should alert on.
        let generated = match state.map.as_ref() {
            Some(map) => match self.map_age_seconds(map) {
                Some(secs) => secs.to_string(),
                None => "unknown".to_string(),
            },
            None => "never".to_string(),
        };
        let stale = match state.map.as_ref() {
            Some(map) => (if self.map_is_stale(map) { "yes" } else { "no" }).to_string(),
            None => "n/a".to_string(),
        };
        let live_memo = state
            .memo
            .values()
            .filter(|(_, expires)| *expires > now)
            .count();
        format!(
            "map={} entries={entries} age_s={age} generated_s={generated} stale={stale} max_age_s={} loads={} load_failures={} memo_live={live_memo} memo_ttl_s={} fallback={}",
            self.path
                .as_ref()
                .map(|p| p.display().to_string())
                .unwrap_or_else(|| "disabled".to_string()),
            self.map_max_age.as_secs(),
            state.loads,
            state.load_failures,
            self.memo_ttl.as_secs(),
            match self.fallback {
                Fallback::Allow => "allow",
                Fallback::Tarpit => "tarpit",
                Fallback::Reject => "reject",
            }
        )
    }

    /// PTN-14: is the loaded map too old to trust its quarantine entries? `map-max-age = 0` opts out.
    fn map_is_stale(&self, map: &MapFile) -> bool {
        if self.map_max_age.is_zero() {
            return false;
        }
        self.map_age_seconds(map)
            .map(|age| age > self.map_max_age.as_secs())
            .unwrap_or(false)
    }

    /// Age of the loaded map in seconds, from the file's own write time. `None` when the filesystem
    /// will not give one; a clock in the future reads as brand new rather than ancient.
    fn map_age_seconds(&self, map: &MapFile) -> Option<u64> {
        match map.generated_at.elapsed() {
            Ok(age) => Some(age.as_secs()),
            Err(_) => Some(0),
        }
    }

    /// Reload the map when it is older than the TTL; keep the previous file when a read fails.
    ///
    /// Called with the state lock held. The TTL exists for two reasons: the file is rewritten
    /// atomically by the controller on a 5-minute cadence (so per-request reads buy nothing), and
    /// Apache itself caches a `txt:` map for 60 seconds, so a faster refresh cannot change what
    /// the backend would have answered.
    fn refresh_locked(&self, state: &mut State) {
        let path = match self.path.as_ref() {
            Some(path) => path,
            None => return,
        };
        let now = Instant::now();
        if let Some(map) = state.map.as_ref() {
            if now.saturating_duration_since(map.loaded_at) < self.map_ttl {
                return;
            }
        }
        match read_map_file(path) {
            Ok((text, generated_at)) => match Classifier::parse_map(&text) {
                Ok(entries) => {
                    state.map = Some(MapFile {
                        entries,
                        loaded_at: now,
                        generated_at,
                    });
                    state.loads += 1;
                }
                Err(error) => {
                    state.load_failures += 1;
                    state.last_error = Some(error);
                }
            },
            Err(error) => {
                state.load_failures += 1;
                state.last_error = Some(error);
            }
        }
        // Log at most once per interval; the counter is the durable signal, the log line is the
        // notification.
        let should_log = match state.last_error_at {
            None => true,
            Some(at) => now.saturating_duration_since(at) >= self.error_log_interval,
        };
        if should_log {
            if let Some(error) = state.last_error.clone() {
                eprintln!("map load failed ({} total): {error}", state.load_failures);
                state.last_error_at = Some(now);
            }
        }
    }
}

/// Read a map file, refusing anything that is not a regular file.
///
/// A symlinked map is worth refusing rather than following: the file the service is configured to
/// read should be the file it opens, and `--config` style indirection is what turns a bad deploy
/// into a confusing one.
fn read_map_file(path: &Path) -> Result<(String, SystemTime), String> {
    let metadata =
        fs::symlink_metadata(path).map_err(|error| format!("{}: {error}", path.display()))?;
    if !metadata.file_type().is_file() {
        return Err(format!("{}: not a regular file", path.display()));
    }
    if metadata.len() > MAX_MAP_BYTES {
        return Err(format!(
            "{}: {} bytes exceeds the {} byte limit",
            path.display(),
            metadata.len(),
            MAX_MAP_BYTES
        ));
    }
    // PTN-14: the write time is the map's own claim about when it was rendered. A filesystem that
    // will not report one is treated as just-written rather than as epoch-old, so the missing
    // metadata cannot by itself lift every quarantine on the host.
    let generated_at = map_generated_at(path, &metadata);
    fs::read_to_string(path)
        .map(|text| (text, generated_at))
        .map_err(|error| format!("{}: {error}", path.display()))
}

/// PTN-14: when was this map actually rendered by the controller?
///
/// The controller deliberately does not rewrite a map whose entries did not change, so the file's
/// mtime freezes whenever the lease set is stable - "nothing changed" and "the controller died" look
/// identical from the mtime alone. The controller writes a sibling `<map>.stamp` on every render
/// (`controller/adaptive-tarpit.py: write_render_stamp`) and that is what the age check uses. A map
/// with no stamp - a host whose controller predates the sidecar - falls back to the file mtime, which
/// is the pre-PTN-14 behaviour rather than a hard failure.
fn map_generated_at(path: &Path, metadata: &fs::Metadata) -> SystemTime {
    let mut stamp = path.as_os_str().to_os_string();
    stamp.push(".stamp");
    if let Ok(text) = fs::read_to_string(&stamp) {
        for line in text.lines() {
            if let Some(raw) = line.strip_prefix("rendered_at=") {
                if let Ok(secs) = raw.trim().parse::<u64>() {
                    return UNIX_EPOCH + Duration::from_secs(secs);
                }
            }
        }
    }
    metadata.modified().unwrap_or_else(|_| SystemTime::now())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicU64, Ordering};

    /// Fixture counter shared by every helper in this module.
    ///
    /// One counter, not one per helper. Two helpers used to carry their own `static SEQ`, both
    /// starting at zero, and both built `fleet-filter-gw-test-<pid>-0.map` - so a "fresh" fixture and
    /// an "aged" fixture in the same parallel run could be the same file, and the staleness tests
    /// read whichever write-time won the race. Observed 2026-11-24 as two failures in roughly one
    /// run in three on a freshly built binary, passing when the file survived: a flake that hid the
    /// exact property it was written to prove.
    static FIXTURE_SEQ: AtomicU64 = AtomicU64::new(0);

    /// A fixture path no other test in this process can collide with.
    fn fixture_path(kind: &str) -> PathBuf {
        let mut path = std::env::temp_dir();
        path.push(format!(
            "pt-gw-test-{}-{}-{}.map",
            std::process::id(),
            FIXTURE_SEQ.fetch_add(1, Ordering::SeqCst),
            kind
        ));
        path
    }

    /// Build a classifier over a map file the caller already created (so the test controls the name).
    ///
    /// The TTL is long so a second `classify()` does not re-read the file and move the load counters
    /// that other assertions depend on.
    fn classifier_with_dir(path: &std::path::Path) -> Classifier {
        Classifier::new(
            Some(path.to_string_lossy().to_string()),
            Duration::from_secs(3600),
            Duration::from_secs(60),
            Fallback::Allow,
        )
    }

    /// Build a classifier over a fresh temp file and load it once.
    fn classifier_with(body: &str) -> Classifier {
        let path = fixture_path("current");
        fs::write(&path, body).expect("write fixture map");
        let classifier = classifier_with_dir(&path);
        // Force the first load now so tests assert against a loaded map rather than a lazily
        // loaded one; the file is removed by the caller that owns it.
        classifier.classify("203.0.113.1".parse().unwrap());
        classifier
    }

    #[test]
    fn parses_the_rendered_format() {
        let entries = Classifier::parse_map(
            "# Generated by adaptive-tarpit at 2026-11-14T16:22:08Z - do not edit by hand.\n\
             # source of truth: the controller store; this file is a build artifact.\n\
             \n\
             198.51.100.111 0\n\
             198.51.100.99 1\n\
             198.51.100.96 1\n\
             2001:db8::1 2\n",
        )
        .expect("valid map");
        assert_eq!(entries.len(), 4);
        assert_eq!(
            entries[&"198.51.100.111".parse::<IpAddr>().unwrap()],
            Verdict::Normal
        );
        assert_eq!(
            entries[&"198.51.100.99".parse::<IpAddr>().unwrap()],
            Verdict::Tarpitted
        );
        assert_eq!(
            entries[&"2001:db8::1".parse::<IpAddr>().unwrap()],
            Verdict::OverQuota
        );
    }

    #[test]
    fn rejects_malformed_maps_instead_of_guessing() {
        // Bad value, bad address, and a duplicate are each fatal, and the message names the line.
        for (body, needle) in [
            ("198.51.100.1 3\n", "bad value"),
            ("198.51.100.1\n", "missing value"),
            ("198.51.100.1 1\n198.51.100.1 0\n", "duplicate"),
            ("198.51.100.1 1 extra\n", "too many fields"),
            ("198.18.055.1 1\n", "bad address"),
        ] {
            let error = Classifier::parse_map(body).expect_err(&format!("should reject {body:?}"));
            assert!(
                error.contains(needle),
                "{body:?} -> {error} (want {needle})"
            );
        }
    }

    #[test]
    fn an_allowlisted_address_is_never_tarpitted_by_a_local_detection() {
        // PTN-06: the memo used to be written before the map's explicit allow (`0`) was consulted,
        // so one signature hit on an authorised scanner tarpitted it for the whole memo TTL.
        let mut path = std::env::temp_dir();
        path.push(format!("fleet-filter-gw-allow-{}.map", std::process::id()));
        fs::write(&path, "198.51.100.7 0\n198.51.100.99 1\n").expect("write fixture map");
        let classifier = classifier_with_dir(&path);
        // Load the map the way a request does, then record the detection: the order the gateway
        // actually runs in, and the order the bug was found in.
        assert_eq!(
            classifier.classify("198.51.100.7".parse().unwrap()).verdict,
            Verdict::Normal
        );
        classifier.memoize("198.51.100.7".parse().unwrap(), Verdict::Tarpitted);
        assert_eq!(
            classifier.memo_len(),
            0,
            "an allowlisted address must not be memoised at all"
        );
        assert_eq!(
            classifier.classify("198.51.100.7".parse().unwrap()),
            Classification {
                verdict: Verdict::Normal,
                source: Source::Map
            },
            "the allow entry is the answer, not the local detection"
        );
        // An address with no entry is still memoised normally - the check is for explicit allows only.
        classifier.memoize("198.51.100.1".parse().unwrap(), Verdict::Tarpitted);
        assert_eq!(classifier.memo_len(), 1);
    }

    #[test]
    fn expired_memo_rows_are_removed_instead_of_accumulating() {
        // PTN-11: the memo used to keep every row it ever wrote, because an expired entry was only
        // ever *recognised* as expired on lookup and never removed. A zero TTL makes expiry
        // observable without waiting on a clock.
        let mut path = std::env::temp_dir();
        path.push(format!("fleet-filter-gw-prune-{}.map", std::process::id()));
        fs::write(&path, "198.51.100.99 1\n").expect("write fixture map");
        let classifier = Classifier::new(
            Some(path.to_string_lossy().to_string()),
            Duration::from_secs(60),
            Duration::ZERO,
            Fallback::Allow,
        );
        for octet in 1..=5 {
            classifier.memoize(
                format!("198.51.100.{octet}").parse().unwrap(),
                Verdict::Tarpitted,
            );
        }
        // Looking an address up drops its own expired row immediately, even inside the sweep
        // interval: the answer is known to be stale, so keeping the row costs memory for nothing.
        classifier.classify("198.51.100.1".parse().unwrap());
        assert_eq!(
            classifier.memo_len(),
            4,
            "the queried address is removed; the other four are still inside the sweep interval"
        );
        // The full sweep is rate-limited (see `prune_interval`), so the rest goes once the interval
        // passes and the next request triggers it.
        std::thread::sleep(Duration::from_millis(1_100));
        classifier.classify("203.0.113.7".parse().unwrap());
        assert_eq!(
            classifier.memo_len(),
            0,
            "an expired memo must be emptied, not shadowed by dead rows"
        );
    }

    #[test]
    fn map_and_memo_agree_with_the_documented_order() {
        let classifier = classifier_with("198.51.100.99 1\n");
        // From the map.
        let hit = classifier.classify("198.51.100.99".parse().unwrap());
        assert_eq!(
            hit,
            Classification {
                verdict: Verdict::Tarpitted,
                source: Source::Map
            }
        );
        // Absent from the map means normal, and that is labelled rather than assumed.
        let miss = classifier.classify("198.51.100.1".parse().unwrap());
        assert_eq!(
            miss,
            Classification {
                verdict: Verdict::Normal,
                source: Source::Map
            }
        );
        // A local detection takes over immediately, without waiting for the map to change.
        classifier.memoize("198.51.100.1".parse().unwrap(), Verdict::Tarpitted);
        assert_eq!(
            classifier.classify("198.51.100.1".parse().unwrap()),
            Classification {
                verdict: Verdict::Tarpitted,
                source: Source::Memo
            }
        );
        // The memo never downgrades an entry the map already quarantines more severely.
        classifier.memoize("198.51.100.99".parse().unwrap(), Verdict::Tarpitted);
        assert_eq!(
            classifier.classify("198.51.100.99".parse().unwrap()).source,
            Source::Memo
        );
    }

    #[test]
    fn normal_is_never_memoised() {
        let classifier = classifier_with("198.51.100.99 1\n");
        classifier.memoize("198.51.100.7".parse().unwrap(), Verdict::Normal);
        // If Normal were memoised this would report `memo`; the correct answer is the map's.
        assert_eq!(
            classifier.classify("198.51.100.7".parse().unwrap()).source,
            Source::Map
        );
    }

    #[test]
    fn disabled_classification_is_not_reported_as_a_fallback() {
        for (fallback, want) in [
            (Fallback::Allow, Verdict::Normal),
            (Fallback::Tarpit, Verdict::Tarpitted),
            (Fallback::Reject, Verdict::OverQuota),
        ] {
            let classifier = Classifier::new(
                None,
                Duration::from_secs(0),
                Duration::from_secs(60),
                fallback,
            );
            // `--map` unset means classification is off, which is a distinct answer from a
            // configured-but-unreadable map, so it must not be reported as a fallback.
            assert_eq!(
                classifier.classify("198.51.100.9".parse().unwrap()),
                Classification {
                    verdict: Verdict::Normal,
                    source: Source::Disabled
                }
            );
            // The fallback itself still has to answer with the verdict the operator chose.
            assert_eq!(fallback.verdict(), want);
        }
        assert_eq!(Fallback::parse("tarpit"), Some(Fallback::Tarpit));
        assert_eq!(Fallback::parse("bogus"), None);
    }

    #[test]
    fn unreadable_map_keeps_the_previous_entries_and_is_counted() {
        let mut path = std::env::temp_dir();
        path.push(format!("fleet-filter-gw-drift-{}.map", std::process::id()));
        fs::write(&path, "198.51.100.99 1\n").unwrap();
        let classifier = Classifier::new(
            Some(path.to_string_lossy().to_string()),
            Duration::from_secs(0),
            Duration::from_secs(60),
            Fallback::Reject,
        );
        assert_eq!(
            classifier
                .classify("198.51.100.99".parse().unwrap())
                .verdict,
            Verdict::Tarpitted
        );
        // Replace the file with something unparseable. The TTL is zero, so the next classify()
        // re-reads, fails, and must keep answering from the last good map instead of falling back.
        fs::write(&path, "not a map at all\n").unwrap();
        assert_eq!(
            classifier
                .classify("198.51.100.99".parse().unwrap())
                .verdict,
            Verdict::Tarpitted
        );
        assert!(classifier.status().contains("load_failures=1"));
        let _ = fs::remove_file(&path);
    }

    #[test]
    fn symlinked_map_is_refused_rather_than_followed() {
        let dir = std::env::temp_dir().join(format!("fleet-filter-gw-sym-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        let target = dir.join("real.map");
        fs::write(&target, "198.51.100.99 1\n").unwrap();
        let link = dir.join("link.map");
        std::os::unix::fs::symlink(&target, &link).unwrap();
        let error = read_map_file(&link).expect_err("a symlink must not be treated as a map");
        assert!(error.contains("not a regular file"), "{error}");
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn status_line_reports_every_counter() {
        let classifier = classifier_with("198.51.100.99 1\n198.51.100.1 0\n");
        classifier.memoize("203.0.113.9".parse().unwrap(), Verdict::Tarpitted);
        let status = classifier.status();
        assert!(status.contains("entries=2"), "{status}");
        assert!(status.contains("memo_live=1"), "{status}");
        assert!(status.contains("loads=1"), "{status}");
        assert!(status.contains("fallback=allow"), "{status}");
        // PTN-14: the two ages are different questions and both have to be readable - how long since
        // we read the file, and how long since the controller wrote it.
        assert!(status.contains("stale=no"), "{status}");
        assert!(status.contains("max_age_s=3600"), "{status}");
    }

    /// PTN-14 fixture: a map file whose own write time is pushed `age` into the past, which is what
    /// a controller that stopped rendering leaves behind. `loaded_at` cannot express this - a gateway
    /// re-reading a frozen file keeps refreshing its own timestamp.
    fn classifier_aged_with(body: &str, age: Duration, fallback: Fallback) -> Classifier {
        let path = fixture_path("aged");
        fs::write(&path, body).expect("write fixture map");
        let stamp = SystemTime::now()
            .checked_sub(age)
            .expect("fixture timestamp is still representable");
        fs::OpenOptions::new()
            .write(true)
            .open(&path)
            .and_then(|file| file.set_modified(stamp))
            .expect("set fixture mtime");
        let classifier = Classifier::new(
            Some(path.to_string_lossy().to_string()),
            Duration::from_secs(3600),
            Duration::from_secs(60),
            fallback,
        );
        // Force the load so the assertions below are about staleness, not about a lazily loaded map.
        classifier.classify("198.51.100.1".parse().unwrap());
        classifier
    }

    /// The same fixture with the default `allow` fallback.
    fn classifier_aged(body: &str, age: Duration) -> Classifier {
        classifier_aged_with(body, age, Fallback::Allow)
    }

    #[test]
    fn a_quarantine_entry_in_a_current_map_is_honoured() {
        let classifier = classifier_aged("198.51.100.99 1\n", Duration::from_secs(60));
        let classification = classifier.classify("198.51.100.99".parse().unwrap());
        assert_eq!(classification.verdict, Verdict::Tarpitted);
        assert_eq!(classification.source, Source::Map);
    }

    #[test]
    fn a_map_the_controller_stopped_rendering_stops_quarantining_clients() {
        // PTN-14: the map carries one value per address and no expiry, so without an age bound a
        // dead controller holds every address it ever quarantined hostage forever. Past
        // `map-max-age` the configured fallback answers instead, and the source says so.
        let classifier = classifier_aged("198.51.100.99 1\n", Duration::from_secs(4 * 3600));
        let classification = classifier.classify("198.51.100.99".parse().unwrap());
        assert_eq!(classification.verdict, Verdict::Normal, "fallback is allow");
        assert_eq!(classification.source, Source::StaleMap);
        assert_eq!(
            classification.header_value(),
            "normal;source=stale-map",
            "the header distinguishes a lifted quarantine from a never-quarantined client"
        );
    }

    #[test]
    fn an_allow_entry_survives_a_stale_map() {
        // An allow row is a standing statement about a client we chose to trust, not a lease. Withdrawing
        // it because the file aged out would quarantine an authorised scanner - the PTN-06 failure
        // wearing a new label - so the PTN-06 allow check runs first and the verdict stays normal.
        let classifier = classifier_aged("198.51.100.111 0\n", Duration::from_secs(4 * 3600));
        let classification = classifier.classify("198.51.100.111".parse().unwrap());
        assert_eq!(classification.verdict, Verdict::Normal);
        assert_eq!(classification.source, Source::Map);
    }

    #[test]
    fn a_stale_map_answers_with_whatever_fallback_the_operator_configured() {
        // The staleness rule must not invent its own policy: an operator who set `tarpit` keeps the
        // client quarantined on purpose, and now does so while admitting the map was stale.
        let aged = classifier_aged_with(
            "198.51.100.99 1\n",
            Duration::from_secs(4 * 3600),
            Fallback::Tarpit,
        );
        assert_eq!(aged.map_max_age(), Duration::from_secs(3600));
        let classification = aged.classify("198.51.100.99".parse().unwrap());
        assert_eq!(classification.verdict, Verdict::Tarpitted);
        assert_eq!(classification.source, Source::StaleMap);
    }

    #[test]
    fn a_render_stamp_overrides_a_frozen_file_mtime() {
        // PTN-14: the controller does not rewrite a map whose entries did not change, so the mtime
        // freezes while the controller stays healthy. The sibling stamp is the authority; without it
        // every stable lease set would eventually look like a dead controller and lift its own
        // quarantines.
        static SEQ: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        let mut dir = std::env::temp_dir();
        dir.push(format!(
            "pt-stamp-{}-{}",
            std::process::id(),
            SEQ.fetch_add(1, std::sync::atomic::Ordering::SeqCst)
        ));
        fs::create_dir_all(&dir).unwrap();
        let map = dir.join("tarpit-ips.map");
        fs::write(&map, "198.51.100.99 1\n").unwrap();
        let old = SystemTime::now()
            .checked_sub(Duration::from_secs(30 * 86400))
            .unwrap();
        fs::OpenOptions::new()
            .write(true)
            .open(&map)
            .and_then(|file| file.set_modified(old))
            .unwrap();

        // No stamp: the 30-day-old mtime is all there is, so the map is stale.
        let without = Classifier::new(
            Some(map.to_string_lossy().to_string()),
            Duration::from_secs(3600),
            Duration::from_secs(60),
            Fallback::Allow,
        );
        assert_eq!(
            without.classify("198.51.100.99".parse().unwrap()).source,
            Source::StaleMap,
            "an unstamped old map is not trusted"
        );

        // Stamp from one minute ago: the controller rendered recently, the entries simply did not move.
        fs::write(
            dir.join("tarpit-ips.map.stamp"),
            format!(
                "# fleet-filter render stamp - do not edit by hand.\nrendered_at={}\n",
                SystemTime::now()
                    .checked_sub(Duration::from_secs(60))
                    .unwrap()
                    .duration_since(UNIX_EPOCH)
                    .unwrap()
                    .as_secs()
            ),
        )
        .unwrap();
        let with = Classifier::new(
            Some(map.to_string_lossy().to_string()),
            Duration::from_secs(0),
            Duration::from_secs(60),
            Fallback::Allow,
        );
        let classification = with.classify("198.51.100.99".parse().unwrap());
        assert_eq!(classification.verdict, Verdict::Tarpitted);
        assert_eq!(classification.source, Source::Map);
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn max_age_zero_trusts_a_map_however_old() {
        // The opt-out has to be real: a host on an unusual render cadence should be able to keep the
        // old behaviour without disabling classification entirely.
        let classifier =
            classifier_aged("198.51.100.99 1\n", Duration::from_secs(10 * 365 * 86400))
                .with_max_age(Duration::ZERO);
        let classification = classifier.classify("198.51.100.99".parse().unwrap());
        assert_eq!(classification.verdict, Verdict::Tarpitted);
        assert_eq!(classification.source, Source::Map);
        assert!(
            classifier.status().contains("stale=no"),
            "{}",
            classifier.status()
        );
    }
}
