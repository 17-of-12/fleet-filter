//! Claim submission: the gateway's half of the controller spool contract (Bundle R2).
//!
//! The contract exists because the network-facing process must not hold a write handle on the
//! authoritative SQLite store: a compromised front end should not be able to rewrite its own
//! quarantine history. Instead the gateway drops one JSON file per observation into a spool
//! directory, and the controller's `drain-spool` - run by the existing timer - folds it into the
//! store. The Python responder already produces this format, so both producers have to agree on
//! the schema, the filename, and the durability rules, which is what this module implements.
//!
//! Durability rules, and why each one is here:
//!   * write to `<name>.tmp`, fsync, then rename onto `<name>.json`. A consumer skips `*.tmp`, so
//!     an in-place write would let the controller read (and consume) a half-written claim.
//!   * the temp file is created with `create_new`, so an existing path - including a symlink - is
//!     an error rather than a target to truncate and follow.
//!   * the final file is refused if it exists as anything other than a regular file, so a rename
//!     can never replace a symlink pointing somewhere else in the filesystem.
//!   * mode is set to 0644 on the temp file *before* the rename, so the final name never exists
//!     with a mode that depends on the process umask.
//!   * submissions are rate-limited per (address, claim key) and the queue depth is capped, so one
//!     chatty client cannot fill the filesystem between two controller runs.

use std::collections::HashMap;
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Mutex, PoisonError};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

/// Schema version this producer emits. The controller accepts `1` (and treats a missing field as
/// the legacy v1 responder format) and quarantines anything else, so bumping this without
/// upgrading the controller is a visible failure rather than a silent one.
pub const SCHEMA_VERSION: u32 = 1;

/// One observation of one address, as it will be written to the spool.
///
/// The field set is exactly what `controller/adaptive-tarpit.py::parse_spool_claim` reads, plus
/// `schema_version` and `evidence`. `ttl` is deliberately absent: the producer observes, the
/// controller decides how long a verdict lasts.
pub struct Claim {
    pub subject_ip: String,
    pub verdict: String,
    pub source: String,
    pub author: String,
    pub claim_key: String,
    pub evidence: Vec<(String, String)>,
}

impl Claim {
    /// Build a claim from a detection, filling in the fields the controller requires.
    pub fn new(
        subject_ip: &str,
        verdict: &str,
        source: &str,
        author: &str,
        claim_key: &str,
    ) -> Claim {
        Claim {
            subject_ip: subject_ip.to_string(),
            verdict: verdict.to_string(),
            source: source.to_string(),
            author: author.to_string(),
            claim_key: claim_key.to_string(),
            evidence: Vec::new(),
        }
    }

    /// Add one evidence field. Values are strings so a caller cannot accidentally serialise a
    /// nested object where the controller expects scalars.
    pub fn with_evidence(mut self, key: &str, value: &str) -> Claim {
        self.evidence.push((key.to_string(), value.to_string()));
        self
    }

    /// Serialise to the JSON object the controller parses.
    ///
    /// Hand-rolled rather than a JSON crate: the document is flat and fully controlled, the
    /// gateway's dependency set is part of the artifact's provenance record (ADR-0001 M6), and the
    /// only real risk - string escaping - is covered by tests below.
    pub fn to_json(&self, observed_at: u64) -> String {
        let mut fields = vec![
            format!("\"schema_version\":{SCHEMA_VERSION}"),
            format!("\"subject_ip\":{}", json_string(&self.subject_ip)),
            format!("\"verdict\":{}", json_string(&self.verdict)),
            format!("\"source\":{}", json_string(&self.source)),
            format!("\"author\":{}", json_string(&self.author)),
            format!("\"claim_key\":{}", json_string(&self.claim_key)),
            format!("\"observed_at\":{observed_at}"),
        ];
        let evidence = self
            .evidence
            .iter()
            .map(|(key, value)| format!("{}:{}", json_string(key), json_string(value)))
            .collect::<Vec<String>>()
            .join(",");
        fields.push(format!("\"evidence\":{{{evidence}}}"));
        format!("{{{}}}", fields.join(","))
    }

    /// The spool filename: epoch first (so the controller's oldest-first sort matches submission
    /// order), then both identities, so a queue can be read without opening the files.
    pub fn filename(&self, observed_at: u64) -> String {
        format!(
            "{observed_at}-{}.json",
            safe_component(&format!("{}-{}", self.subject_ip, self.claim_key))
        )
    }
}

/// Escape a Rust string as a JSON string literal.
///
/// Everything outside the printable ASCII range is emitted as `\uXXXX`, which is verbose but
/// removes the whole class of "the file is valid JSON on my machine" bugs (invalid UTF-8 in a
/// header value, a path containing a quote or a backslash, a stray control character).
pub fn json_string(value: &str) -> String {
    let mut out = String::with_capacity(value.len() + 2);
    out.push('"');
    for character in value.chars() {
        match character {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => {
                out.push_str(&format!("\\u{:04x}", c as u32));
            }
            c if (c as u32) < 0x7f => out.push(c),
            c => {
                // Non-ASCII goes through UTF-16 code units, which is what JSON's \u means.
                for unit in c.encode_utf16(&mut [0u16; 2]) {
                    out.push_str(&format!("\\u{unit:04x}"));
                }
            }
        }
    }
    out.push('"');
    out
}

/// Reduce an arbitrary string to characters that are safe in a filename.
///
/// Mirrors the responder's `_safe_filename` so both producers generate comparable names: anything
/// that is not alphanumeric, `.`, `-`, or `_` becomes `_`. Without this, an IPv6 address
/// (`2001:db8::1`) or a claim key containing a slash would produce a path the controller cannot
/// list correctly.
pub fn safe_component(value: &str) -> String {
    value
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '.' || c == '-' || c == '_' {
                c
            } else {
                '_'
            }
        })
        .collect()
}

/// What happened when a claim was offered to the spool.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Submission {
    /// The claim was written and is now queued.
    Written(PathBuf),
    /// Suppressed by the per-(address, claim key) rate limit.
    RateLimited,
    /// Suppressed because the queue is at its configured depth.
    QueueFull,
    /// Spooling is disabled (`--spool` unset).
    Disabled,
    /// The write was attempted and failed; the message is the OS error.
    Failed(String),
}

impl Submission {
    /// Lower-case label for logs.
    pub fn label(&self) -> &'static str {
        match self {
            Submission::Written(_) => "written",
            Submission::RateLimited => "rate-limited",
            Submission::QueueFull => "queue-full",
            Submission::Disabled => "disabled",
            Submission::Failed(_) => "failed",
        }
    }

    /// The failure message for `Failed`, empty for every other outcome.
    pub fn detail(&self) -> &str {
        match self {
            Submission::Failed(detail) => detail.as_str(),
            _ => "",
        }
    }
}

/// The spool writer: rate limiting, depth cap, and the atomic write described in the module docs.
pub struct Spool {
    directory: Option<PathBuf>,
    min_interval: Duration,
    max_entries: usize,
    seen: Mutex<HashMap<String, u64>>,
    /// Cached queue depth: `(observed_at of the count, count)`. See `depth`.
    depth_cache: Mutex<Option<(u64, usize)>>,
    written: AtomicU64,
    failed: AtomicU64,
}

/// Seconds a cached queue-depth reading stays usable (PTN-11).
///
/// The depth used to be recomputed by walking the spool directory while holding the rate-limit
/// mutex, on every claim that was not rate-limited. One second is long enough that a burst of
/// claims shares a single `read_dir`, and short enough that the drift window is smaller than the
/// controller's drain interval.
const DEPTH_REFRESH_SECS: u64 = 1;

impl Spool {
    /// Build a writer. `directory: None` disables submission (the pre-R behaviour).
    pub fn new(directory: Option<String>, min_interval: Duration, max_entries: usize) -> Spool {
        Spool {
            directory: directory.map(PathBuf::from),
            min_interval,
            max_entries,
            seen: Mutex::new(HashMap::new()),
            depth_cache: Mutex::new(None),
            written: AtomicU64::new(0),
            failed: AtomicU64::new(0),
        }
    }

    /// Submit a claim, returning what happened.
    ///
    /// Errors never propagate into the request path: a full, read-only, or badly permissioned
    /// spool must not turn a working proxy response into a 500. The failure is counted and logged
    /// instead, which is the same trade the responder makes.
    pub fn submit(&self, claim: &Claim, observed_at: u64) -> Submission {
        let directory = match self.directory.as_ref() {
            Some(directory) => directory,
            None => return Submission::Disabled,
        };

        // Rate limit before touching the filesystem, so the common "scanner hits 500 paths in a
        // second" case costs one hashmap lookup.
        let key = format!("{}|{}", claim.subject_ip, claim.claim_key);
        {
            let mut seen = self.seen.lock().unwrap_or_else(PoisonError::into_inner);
            if let Some(last) = seen.get(&key) {
                if observed_at.saturating_sub(*last) < self.min_interval.as_secs() {
                    return Submission::RateLimited;
                }
            }
            // Only remember the attempt once it can actually be filed; recording a suppressed
            // attempt would suppress the retry that would have succeeded.
            if self.exceeds_depth(directory, observed_at) {
                return Submission::QueueFull;
            }
            seen.insert(key, observed_at);
            self.prune_seen(&mut seen, observed_at);
        }

        let path = directory.join(claim.filename(observed_at));
        match self.write_atomic(directory, &path, &claim.to_json(observed_at)) {
            Ok(()) => {
                self.written.fetch_add(1, Ordering::Relaxed);
                self.note_written(observed_at);
                Submission::Written(path)
            }
            Err(error) => {
                let count = self.failed.fetch_add(1, Ordering::Relaxed) + 1;
                // Log every distinct failure but keep it to one line; the counter is the signal.
                eprintln!("spool write failed ({count} total): {error}");
                Submission::Failed(error)
            }
        }
    }

    /// Totals for logs: `written=N failed=M`.
    pub fn counts(&self) -> (u64, u64) {
        (
            self.written.load(Ordering::Relaxed),
            self.failed.load(Ordering::Relaxed),
        )
    }

    /// A stable description of the settings, so a reload can reuse this instance's rate-limit memory.
    ///
    /// Rebuilding the writer on every policy reload would reset the per-`(ip, claim_key)` interval
    /// and let the same client file the same claim twice within seconds.
    pub fn fingerprint(&self) -> String {
        format!(
            "dir={}|min_interval={}|max_entries={}",
            self.directory
                .as_ref()
                .map(|d| d.to_string_lossy().to_string())
                .unwrap_or_else(|| "disabled".to_string()),
            self.min_interval.as_secs(),
            self.max_entries
        )
    }

    /// One-line status for the startup banner: where claims go, and how many have been filed.
    pub fn status_line(&self) -> String {
        let (written, failed) = self.counts();
        format!(
            "dir={} written={written} failed={failed} min_interval_s={} max_entries={}",
            self.directory
                .as_ref()
                .map(|d| d.display().to_string())
                .unwrap_or_else(|| "disabled".to_string()),
            self.min_interval.as_secs(),
            self.max_entries
        )
    }

    /// Number of queued claims, from the cache when the cached reading is still fresh.
    ///
    /// A write bumps the cached count directly (`note_written`) so the cap cannot be overshot during
    /// the refresh window; the count can only drift *down* while the cache is fresh, which happens
    /// when the controller drains the spool - and under-counting a drain is the safe direction.
    fn depth(&self, directory: &PathBuf, observed_at: u64) -> usize {
        let mut cache = self
            .depth_cache
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        if let Some((at, count)) = cache.as_ref() {
            if observed_at.saturating_sub(*at) < DEPTH_REFRESH_SECS {
                return *count;
            }
        }
        let count = Self::count_queued(directory);
        *cache = Some((observed_at, count));
        count
    }

    /// Add one to the cached depth after a successful write, if the cached reading is still fresh.
    fn note_written(&self, observed_at: u64) {
        let mut cache = self
            .depth_cache
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        if let Some((at, count)) = cache.as_mut() {
            if observed_at.saturating_sub(*at) < DEPTH_REFRESH_SECS {
                *count += 1;
            }
        }
    }

    /// Count `*.json` files in the spool directory (0 when it does not exist yet).
    fn count_queued(directory: &PathBuf) -> usize {
        let Ok(entries) = fs::read_dir(directory) else {
            // The directory may not exist yet; the write below creates it. Counting it as full
            // would prevent that first write from ever happening.
            return 0;
        };
        entries
            .filter_map(|entry| entry.ok())
            .filter(|entry| entry.file_name().to_string_lossy().ends_with(".json"))
            .count()
    }

    /// Compare the queue depth against the cap. `false` means "room available".
    fn exceeds_depth(&self, directory: &PathBuf, observed_at: u64) -> bool {
        if self.max_entries == 0 {
            return false;
        }
        self.depth(directory, observed_at) >= self.max_entries
    }

    /// PTN-11: forget rate-limit entries that can no longer suppress anything.
    ///
    /// An entry only matters while it is younger than `min_interval`; older rows are dead weight that
    /// used to accumulate forever. Expiry by age is the control the owner asked for instead of a size
    /// cap - a scanning campaign rotates through address pools, and a cap would evict the newest
    /// (most relevant) keys while keeping the oldest. With rate limiting disabled (`min_interval` 0)
    /// nothing ever expires by that rule, so a day of retention keeps the map bounded instead.
    fn prune_seen(&self, seen: &mut HashMap<String, u64>, observed_at: u64) {
        let retention = if self.min_interval.is_zero() {
            86_400
        } else {
            self.min_interval.as_secs()
        };
        seen.retain(|_, last| observed_at.saturating_sub(*last) < retention);
    }

    /// Rate-limit entries currently held - the number the leak was measured in.
    pub fn seen_len(&self) -> usize {
        self.seen
            .lock()
            .map(|seen| seen.len())
            .unwrap_or_else(|poisoned| poisoned.into_inner().len())
    }

    /// Write `body` to `path` atomically: temp file (exclusive create) -> fsync -> rename.
    fn write_atomic(&self, directory: &PathBuf, path: &PathBuf, body: &str) -> Result<(), String> {
        fs::create_dir_all(directory)
            .map_err(|e| format!("create {}: {e}", directory.display()))?;
        let mut temp = directory.join(file_name(path));
        temp.set_extension("json.tmp");
        // `create_new` fails if the path exists at all - including as a symlink - so a staged
        // write can never be tricked into truncating something that is not ours.
        let mut handle = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&temp)
            .map_err(|e| format!("create {}: {e}", temp.display()))?;
        handle
            .write_all(body.as_bytes())
            .map_err(|e| format!("write {}: {e}", temp.display()))?;
        handle
            .sync_all()
            .map_err(|e| format!("fsync {}: {e}", temp.display()))?;
        fs::set_permissions(&temp, fs::Permissions::from_mode(0o644))
            .map_err(|e| format!("chmod {}: {e}", temp.display()))?;

        // Refuse to rename onto anything that is not a regular file: `rename` would happily
        // replace a symlink and thereby write through to its target.
        match fs::symlink_metadata(path) {
            Ok(metadata) if !metadata.file_type().is_file() => {
                let _ = fs::remove_file(&temp);
                return Err(format!(
                    "{}: refusing to replace a non-regular file",
                    path.display()
                ));
            }
            Err(error) if error.kind() != std::io::ErrorKind::NotFound => {
                let _ = fs::remove_file(&temp);
                return Err(format!("{}: {error}", path.display()));
            }
            _ => {}
        }
        fs::rename(&temp, path).map_err(|e| {
            let _ = fs::remove_file(&temp);
            format!("rename {} -> {}: {e}", temp.display(), path.display())
        })
    }
}

/// Extract the file name of a path as an owned String.
fn file_name(path: &Path) -> String {
    path.file_name()
        .map(|name| name.to_string_lossy().to_string())
        .unwrap_or_else(|| "claim".to_string())
}

/// Current unix epoch, used for filenames and rate limiting.
pub fn epoch_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A unique, empty spool directory per test (tests run in parallel, so no shared fixture).
    fn temp_spool(tag: &str) -> PathBuf {
        static SEQ: AtomicU64 = AtomicU64::new(0);
        let path = std::env::temp_dir().join(format!(
            "fleet-filter-gw-spool-{}-{}-{}",
            std::process::id(),
            tag,
            SEQ.fetch_add(1, Ordering::SeqCst)
        ));
        let _ = fs::remove_dir_all(&path);
        fs::create_dir_all(&path).expect("create spool dir");
        path
    }

    /// Read a spool directory the way the controller does: sorted `.json` names, no `.tmp`.
    fn queued(directory: &PathBuf) -> Vec<String> {
        let mut names: Vec<String> = fs::read_dir(directory)
            .map(|entries| {
                entries
                    .filter_map(|entry| entry.ok())
                    .map(|entry| entry.file_name().to_string_lossy().to_string())
                    .filter(|name| name.ends_with(".json"))
                    .collect()
            })
            .unwrap_or_default();
        names.sort();
        names
    }

    #[test]
    fn json_escaping_covers_the_characters_that_break_files() {
        assert_eq!(json_string("plain"), "\"plain\"");
        assert_eq!(json_string("a\"b"), "\"a\\\"b\"");
        assert_eq!(json_string("a\\b"), "\"a\\\\b\"");
        assert_eq!(json_string("a\nb\tc\rd"), "\"a\\nb\\tc\\rd\"");
        assert_eq!(json_string("a\u{1}b"), "\"a\\u0001b\"");
        assert_eq!(json_string("caf\u{e9}"), "\"caf\\u00e9\"");
        // Emoji: a non-BMP character is two UTF-16 code units, which is what JSON requires.
        assert_eq!(json_string("\u{1f600}"), "\"\\ud83d\\ude00\"");
    }

    #[test]
    fn claim_json_carries_every_field_the_controller_reads() {
        let claim = Claim::new(
            "198.51.100.80",
            "confirmed",
            "fleet-filter-gateway",
            "lab-web01",
            "signature:probe_path",
        )
        .with_evidence("method", "GET")
        .with_evidence("path", "/h2probe-12075394");
        let json = claim.to_json(1763100000);
        for needle in [
            "\"schema_version\":1",
            "\"subject_ip\":\"198.51.100.80\"",
            "\"verdict\":\"confirmed\"",
            "\"source\":\"fleet-filter-gateway\"",
            "\"author\":\"lab-web01\"",
            "\"claim_key\":\"signature:probe_path\"",
            "\"observed_at\":1763100000",
            "\"evidence\":{\"method\":\"GET\",\"path\":\"/h2probe-12075394\"}",
        ] {
            assert!(json.contains(needle), "missing {needle} in {json}");
        }
        // `ttl` must be absent: the controller owns the duration, and a producer that sets it
        // pins a lease length the controller can no longer change.
        assert!(!json.contains("\"ttl\""), "{json}");
    }

    #[test]
    fn filenames_sort_in_submission_order_and_survive_ipv6() {
        let claim = Claim::new(
            "2001:db8::1",
            "confirmed",
            "fleet-filter-gateway",
            "h",
            "signature:probe_path",
        );
        assert_eq!(
            claim.filename(1763100000),
            "1763100000-2001_db8__1-signature_probe_path.json"
        );
        let older = Claim::new("198.51.100.1", "confirmed", "s", "h", "k").filename(1763099999);
        let newer = Claim::new("198.51.100.1", "confirmed", "s", "h", "k").filename(1763100001);
        assert!(older < newer, "epoch prefix must sort chronologically");
    }

    #[test]
    fn submit_writes_one_file_and_leaves_no_temporary() {
        let spool = temp_spool("write");
        let writer = Spool::new(
            Some(spool.to_string_lossy().to_string()),
            Duration::from_secs(0),
            0,
        );
        let claim = Claim::new(
            "198.51.100.80",
            "confirmed",
            "fleet-filter-gateway",
            "h",
            "signature:probe_path",
        );
        let result = writer.submit(&claim, 1763100000);
        assert!(matches!(result, Submission::Written(_)), "{result:?}");
        assert_eq!(
            queued(&spool),
            vec!["1763100000-198.51.100.80-signature_probe_path.json".to_string()]
        );
        // No `.tmp` survivor: the controller skips those, so a leftover would be invisible garbage.
        let leftovers: Vec<String> = fs::read_dir(&spool)
            .map(|entries| {
                entries
                    .filter_map(|e| e.ok())
                    .map(|e| e.file_name().to_string_lossy().to_string())
                    .filter(|n| n.ends_with(".tmp"))
                    .collect()
            })
            .unwrap_or_default();
        assert!(
            leftovers.is_empty(),
            "temp files left behind: {leftovers:?}"
        );
        // Mode is explicit, not umask-dependent: the controller must be able to read it, and the
        // file is not a secret, so 0644 is the documented value.
        let mode = fs::metadata(spool.join("1763100000-198.51.100.80-signature_probe_path.json"))
            .expect("metadata")
            .permissions()
            .mode();
        assert_eq!(mode & 0o777, 0o644, "mode is {:o}", mode);
        let _ = fs::remove_dir_all(&spool);
    }

    #[test]
    fn rate_limit_suppresses_the_second_claim_for_the_same_key() {
        let spool = temp_spool("rate");
        let writer = Spool::new(
            Some(spool.to_string_lossy().to_string()),
            Duration::from_secs(60),
            0,
        );
        let claim = Claim::new(
            "198.51.100.80",
            "confirmed",
            "fleet-filter-gateway",
            "h",
            "signature:probe_path",
        );
        assert!(matches!(
            writer.submit(&claim, 1763100000),
            Submission::Written(_)
        ));
        assert!(
            matches!(writer.submit(&claim, 1763100030), Submission::RateLimited),
            "a second claim 30s later must be suppressed by a 60s interval"
        );
        // A different claim key for the same address is a different observation, not a duplicate.
        let other = Claim::new(
            "198.51.100.80",
            "confirmed",
            "fleet-filter-gateway",
            "h",
            "signature:bodyless_ct",
        );
        assert!(matches!(
            writer.submit(&other, 1763100030),
            Submission::Written(_)
        ));
        // Once the interval passes, the same key may be filed again.
        assert!(matches!(
            writer.submit(&claim, 1763100061),
            Submission::Written(_)
        ));
        assert_eq!(queued(&spool).len(), 3);
        let _ = fs::remove_dir_all(&spool);
    }

    #[test]
    fn rate_limit_entries_expire_instead_of_accumulating() {
        // PTN-11: `seen` used to grow for the lifetime of the process. An entry only ever matters
        // inside `min_interval`, so anything older than that is dropped on the next filing.
        let spool = temp_spool("prune");
        let writer = Spool::new(
            Some(spool.to_string_lossy().to_string()),
            Duration::from_secs(60),
            0,
        );
        let first = Claim::new(
            "198.51.100.90",
            "confirmed",
            "fleet-filter-gateway",
            "h",
            "signature:probe_path",
        );
        assert!(matches!(
            writer.submit(&first, 1763100000),
            Submission::Written(_)
        ));
        assert_eq!(writer.seen_len(), 1);
        // An hour later a different address files a claim: the stale entry can no longer suppress
        // anything, so it is removed rather than kept.
        let later = Claim::new(
            "198.51.100.91",
            "confirmed",
            "fleet-filter-gateway",
            "h",
            "signature:probe_path",
        );
        assert!(matches!(
            writer.submit(&later, 1763103600),
            Submission::Written(_)
        ));
        assert_eq!(
            writer.seen_len(),
            1,
            "the hour-old key must be pruned, leaving only the fresh one"
        );
        let _ = fs::remove_dir_all(&spool);
    }

    #[test]
    fn queue_depth_cap_stops_writing_without_losing_the_counter() {
        let spool = temp_spool("depth");
        // Pre-fill to the cap with two queued files.
        for name in ["1763099990-a.json", "1763099991-b.json"] {
            fs::write(spool.join(name), "{}").unwrap();
        }
        let writer = Spool::new(
            Some(spool.to_string_lossy().to_string()),
            Duration::from_secs(0),
            2,
        );
        let claim = Claim::new(
            "198.51.100.81",
            "confirmed",
            "fleet-filter-gateway",
            "h",
            "k",
        );
        assert!(
            matches!(writer.submit(&claim, 1763100000), Submission::QueueFull),
            "a full queue must refuse rather than grow"
        );
        // A refused claim is not remembered as submitted, so the next run can retry it.
        assert_eq!(writer.counts(), (0, 0));
        assert_eq!(queued(&spool).len(), 2);
        let _ = fs::remove_dir_all(&spool);
    }

    #[test]
    fn disabled_spool_reports_disabled_and_writes_nothing() {
        let writer = Spool::new(None, Duration::from_secs(0), 0);
        let claim = Claim::new("198.51.100.80", "confirmed", "s", "h", "k");
        assert_eq!(writer.submit(&claim, 1763100000), Submission::Disabled);
        assert_eq!(writer.counts(), (0, 0));
    }

    #[test]
    fn a_symlinked_target_is_refused_instead_of_being_replaced() {
        let spool = temp_spool("symlink");
        let victim = spool.join("victim.txt");
        fs::write(&victim, "do not clobber").unwrap();
        let claim = Claim::new("198.51.100.80", "confirmed", "s", "h", "k");
        // Craft the exact situation `rename` would hide: the final name is a symlink. The name
        // comes from the claim itself, so the test also pins the filename convention.
        let target_name = claim.filename(1763100000);
        std::os::unix::fs::symlink(&victim, spool.join(&target_name)).unwrap();
        let writer = Spool::new(
            Some(spool.to_string_lossy().to_string()),
            Duration::from_secs(0),
            0,
        );
        // The writer builds `<name>.json` then tries to rename onto it; the symlink must stop it.
        let error = writer
            .write_atomic(&spool, &spool.join(&target_name), "{}")
            .expect_err("must refuse a symlinked target");
        assert!(error.contains("non-regular file"), "{error}");
        assert_eq!(fs::read_to_string(&victim).unwrap(), "do not clobber");
        let _ = fs::remove_dir_all(&spool);
    }

    #[test]
    fn a_failed_write_leaves_no_temporary_behind() {
        let spool = temp_spool("cleanup");
        let writer = Spool::new(
            Some(spool.to_string_lossy().to_string()),
            Duration::from_secs(0),
            0,
        );
        let victim = spool.join("1763100000-x.json");
        std::os::unix::fs::symlink(spool.join("elsewhere"), &victim).unwrap();
        let error = writer
            .write_atomic(&spool, &victim, "{}")
            .expect_err("symlink target must fail");
        assert!(error.contains("non-regular file"), "{error}");
        let temps: Vec<String> = fs::read_dir(&spool)
            .map(|entries| {
                entries
                    .filter_map(|e| e.ok())
                    .map(|e| e.file_name().to_string_lossy().to_string())
                    .filter(|n| n.ends_with(".tmp"))
                    .collect()
            })
            .unwrap_or_default();
        assert!(temps.is_empty(), "failed write left {temps:?}");
        let _ = fs::remove_dir_all(&spool);
    }
}
