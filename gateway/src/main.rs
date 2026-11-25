//! `fleet-filter-gateway` - Stage 2 security gateway front-end for Fleet-Filter.
//!
//! Milestone scope (Bundle O): terminate TLS with ALPN (`h2`, `http/1.1`), serve whichever
//! protocol the client negotiated, and forward the request to a configured HTTP/1.1 backend.
//! That is the whole feature: it exists to prove the h2-in / h1-out claim, and it deliberately
//! does not grow ACME, dashboards, multi-host management, or extra protocol combinations.
//!
//! Design decisions worth knowing before reading the code
//! ------------------------------------------------------
//! * **One response path for both protocols.** `hyper_util::server::conn::auto` sniffs the
//!   connection, so an h2 client and an HTTP/1.1 client are served by the same code and the
//!   response echoes `request.version()`. That makes "which protocol did the gateway actually
//!   serve this on" answerable from the response itself instead of only from a pcap.
//! * **Backend is a routing table entry, not a code path** (ADR-0001 M3 contract item 2): the
//!   upstream is a URL in config, so native / container / remote backends stay swappable.
//! * **Client identity is the socket peer, not a header, until the backend trusts the gateway**
//!   (ADR-0001 boundary B2). The gateway therefore *generates* `X-Forwarded-For` and
//!   `Forwarded` rather than trusting whatever arrived, and it removes hop-by-hop headers.
//! * **Correlation id on every request** (O7): the gateway generates one id per request, puts it
//!   in `X-Request-Id` upstream and in its own log line, so gateway and backend entries can be
//!   joined without guessing by timestamp.
//! * **Bounded before anything else**: connection cap, header count cap, body cap, header read
//!   timeout. A gateway that accepts unbounded work before validating it has converted a
//!   client-side problem into a server-side one.

use std::collections::{BTreeMap, HashMap};
use std::convert::Infallible;
use std::env;
use std::fs::{self, File};
use std::io::BufReader;
use std::net::{IpAddr, SocketAddr};
use std::path::Path;
use std::process::exit;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use http_body_util::{combinators::BoxBody, BodyExt, Full, LengthLimitError, Limited};
use hyper::body::{Body, Bytes, Incoming};
use hyper::header::{HeaderMap, HeaderName, HeaderValue};
use hyper::service::service_fn;
use hyper::{Method, Request, Response, StatusCode, Version};
use hyper_util::rt::{TokioExecutor, TokioIo, TokioTimer};
use hyper_util::server::conn::auto::Builder as AutoBuilder;
use tokio::net::{TcpListener, TcpStream};
use tokio::signal::unix::{signal, SignalKind};
use tokio::sync::Semaphore;

pub mod classify;
pub mod deception;
pub mod policy;
pub mod spool;

const VERSION: &str = env!("CARGO_PKG_VERSION");
const PKG_NAME: &str = env!("CARGO_PKG_NAME");

/// First of the two PTN-02 checks: is the length the client *declared* already over the cap?
///
/// A declared length is a claim, not a measurement, so this can only reject: `None` (a chunked body,
/// or an HTTP/2 stream with no declared length) does not mean "zero bytes", it means "unknown", and
/// the real count comes from `Limited` below. Answering 413 from the claim alone is what stops the
/// gateway reading a 5 GB upload that the policy had already refused.
fn declared_body_over_limit(declared: Option<u64>, max_body_bytes: usize) -> bool {
    declared
        .map(|length| length > max_body_bytes as u64)
        .unwrap_or(false)
}

/// The gateway's single response body type (PTN-03).
///
/// Every answer the gateway produces - a proxied backend body, an inline deception body, a policy
/// rejection, a 413 - is boxed to this one type. Two reasons, one mechanical and one not:
///
/// * `service_fn` requires one concrete response type, so as long as the gateway answered with
///   `Full<Bytes>` it could only ever answer with a body it had fully buffered. That is what made
///   an SSE response impossible (it never completes, so it never produced a response) and what made
///   a 200 MB download cost the gateway 200 MB of RSS.
/// * One alias means a body built in one function and returned from another cannot silently change
///   shape, which is the class of bug where `deception.rs` builds a `Full` and `main.rs` promises
///   something else.
type BoxError = Box<dyn std::error::Error + Send + Sync>;
type GatewayBody = BoxBody<Bytes, BoxError>;

/// Wrap in-memory bytes as the gateway's body type: one allocation, no copy, immediately complete.
fn full_body(bytes: Bytes) -> GatewayBody {
    // `Full<Bytes>`'s error type is `Infallible`; the gateway's body type widens it to `BoxError`
    // so a `Full` and a streamed `Incoming` can be the same type. The mapping can never run.
    Full::new(bytes).map_err(BoxError::from).boxed()
}

/// Stream a backend response body as the gateway's body type (PTN-03).
///
/// The body is not collected: hyper polls it frame by frame with backpressure, so the gateway holds
/// one frame of a large response rather than the whole thing, and a response that streams for an
/// hour (SSE, long polling) reaches the client as it is produced instead of never.
fn streamed_body(body: Incoming) -> GatewayBody {
    body.map_err(BoxError::from).boxed()
}

/// The one backend client the process owns (PTN-17), and the reason the body type has to be shared.
///
/// The proxy path used to build a `Client` inside `proxy_request`, which cannot pool anything: every
/// request paid a fresh connection to the backend and left the previous one to be torn down. That was
/// already wasteful while the gateway buffered the whole response anyway; now that PTN-03 holds a
/// backend response open for as long as the backend takes to stream it, a per-request client would
/// multiply exactly the cost pooling exists to remove. One client means `max_connections` describes
/// real backend connections instead of one per request.
///
/// It is process-wide rather than per-policy because a SIGHUP reload swaps the `Config` (and with it
/// the backend address) while connections already pooled to the old backend are still being streamed
/// from; a client that outlives the policy that created it is the simpler, correct lifetime.
type BackendClient = hyper_util::client::legacy::Client<
    hyper_util::client::legacy::connect::HttpConnector,
    GatewayBody,
>;

fn backend_client() -> &'static BackendClient {
    static CLIENT: OnceLock<BackendClient> = OnceLock::new();
    CLIENT.get_or_init(|| {
        hyper_util::client::legacy::Client::builder(TokioExecutor::new())
            .build_http::<GatewayBody>()
    })
}

/// Runtime configuration, built from argv and, when present, from a policy bundle (Bundle S).
///
/// Every limit is a field rather than a constant so the deployed unit is the source of truth and
/// a change is visible in `systemctl cat` output instead of buried in a rebuild.
struct Config {
    /// Address the gateway listens on (O2: a TEST-NET alias, not the production interface).
    bind: SocketAddr,
    /// Backend the gateway forwards to. HTTP/1.1 always, regardless of what the client used.
    backend: String,
    /// Maximum concurrently served connections; past this a socket is closed, not queued.
    max_connections: usize,
    /// Maximum concurrently served connections from ONE client address.
    ///
    /// The global cap alone is not a control: one client can consume it and starve every other
    /// source, which turns a single abusive host into a fleet-wide outage on a shared front end.
    max_connections_per_source: usize,
    /// PTN-08: in-flight requests per authority, enforcing `[posture] admission_cap_per_authority`.
    ///
    /// The key existed in the schema and in `Profile` but was never consulted on the request path, so
    /// a policy could declare a per-vhost admission limit and get no behaviour from it. Like
    /// `SourceCounts` this is live state rather than configuration, and it is reused across reloads
    /// for the same reason: a fresh map would forget the requests already being served.
    authorities: Arc<AuthorityCounts>,
    /// Maximum bytes buffered for a request body before the body is abandoned.
    max_body_bytes: usize,
    /// Maximum number of header fields accepted on a request (HTTP/1.1).
    max_headers: usize,
    /// Seconds allowed to read a request's headers (HTTP/1.1); 0 disables the timeout.
    ///
    /// Only enforceable together with the `TokioTimer` set in `serve_connection`: hyper panics on a
    /// configured timeout with no timer, so a value here that the connection builder ignores would
    /// be a limit on paper. Keeping both in one place is what keeps the paper and the behaviour
    /// together.
    header_read_timeout_secs: u64,
    /// PTN-08: seconds allowed for a TLS handshake before the connection is dropped; 0 disables.
    tls_handshake_timeout_secs: u64,
    /// PTN-08: seconds to wait for the backend's response head before answering 504; 0 disables.
    upstream_timeout_secs: u64,
    /// PTN-08: concurrent HTTP/2 streams allowed per client connection; 0 keeps hyper's default.
    http2_max_concurrent_streams: u64,
    /// TLS material; `None` means the gateway serves cleartext (the pre-O3 configuration).
    tls: Option<TlsMaterial>,
    /// Prefixes whose forwarding header is believed. Empty means the gateway is the edge, and the
    /// peer address is the client address.
    trusted_proxies: Vec<policy::Cidr>,
    /// Bundle R4: the controller's rendered map plus a memo of this process's own detections.
    ///
    /// Shared behind an `Arc` so a policy reload that does not change the classification settings
    /// reuses the same instance instead of discarding the map cache and the detection memo.
    classifier: Arc<classify::Classifier>,
    /// Bundle R2: where this process files claims; `Spool::new(None, ..)` disables reporting.
    /// Also `Arc` for the same reason: the per-claim rate-limit memory must survive a reload.
    spool: Arc<spool::Spool>,
    /// Request path prefixes that count as a local detection (empty = the gateway detects nothing).
    ///
    /// Full signature matching (regexes from `controller/signatures/signatures.yaml`) is Bundle S;
    /// a prefix list is enough to exercise the memoise-and-report path today without adding a
    /// regex crate to the lockfile.
    detect_prefix: Vec<String>,
    /// Structured request shapes (protocol class); empty means the gateway matches prefixes only.
    detect_shapes: Vec<policy::Shape>,
    /// Literal body markers (engine class); empty means bodies are not inspected.
    detect_body_markers: Vec<String>,
    /// What the gateway does with a request from a client it classifies as quarantined.
    quarantined: Quarantined,
    /// Bundle T1: the inline deception budget, present when the policy declares `[deception]`.
    ///
    /// `Arc` for the same reason as the classifier and the spool: the in-flight drip count is the
    /// thing being enforced, and rebuilding it on every reload would reset it and let a burst
    /// exceed a cap the new bundle did not change.
    deception: Option<Arc<deception::Budget>>,
    /// Value written into a claim's `author` field; defaults to the package name so a deployed
    /// unit can name the host that produced a claim without the process calling gethostname.
    author: String,
    /// Bundle S1: the policy bundle this configuration was built from, when one was supplied.
    ///
    /// `None` means the process is running flag-only (the pre-S deployment shape), which stays
    /// supported so an existing unit file does not have to change to run a new binary.
    policy: Option<Arc<policy::Policy>>,
    /// SHA-256 of the policy file's bytes - the per-host installed-policy identity S4 reports.
    policy_sha: Option<String>,
}

/// Every command-line setting as an `Option`, so a policy bundle can supply what a flag omitted.
///
/// Flags remain the interface for a quick local run, but on a deployed host the bundle is the
/// source of truth (S1) and a flag exists to override one field during an incident without editing
/// the bundle. Precedence is: explicit flag, then bundle, then the built-in default. Keeping the
/// parsed flags as their own type is what makes a reload possible without re-reading argv.
#[derive(Debug, Clone, Default)]
struct Args {
    /// Address to bind (`address:port`).
    bind: Option<String>,
    /// Backend URL to forward to.
    backend: Option<String>,
    /// Global connection cap.
    max_connections: Option<usize>,
    /// Per-client-address connection cap; 0 means unlimited.
    max_connections_per_source: Option<usize>,
    /// Request body byte cap.
    max_body_bytes: Option<usize>,
    /// Header field count cap.
    max_headers: Option<usize>,
    /// Seconds allowed to read a request's headers; 0 disables the timeout.
    header_read_timeout: Option<u64>,
    /// PTN-08: seconds allowed for a TLS handshake; 0 disables the timeout.
    tls_handshake_timeout: Option<u64>,
    /// PTN-08: seconds to wait for the backend's response; 0 disables the timeout.
    upstream_timeout: Option<u64>,
    /// PTN-08: concurrent HTTP/2 streams per client connection; 0 keeps hyper's default.
    http2_max_concurrent_streams: Option<u64>,
    /// TLS certificate path.
    tls_cert: Option<String>,
    /// TLS private key path.
    tls_key: Option<String>,
    /// Rendered RewriteMap to classify clients from.
    map: Option<String>,
    /// Seconds between map re-reads.
    map_ttl: Option<u64>,
    /// Seconds a local detection stays memoised.
    map_memo_ttl: Option<u64>,
    /// PTN-14: seconds a rendered map stays trusted for quarantine decisions (0 = any age).
    map_max_age: Option<u64>,
    /// What to do when the map cannot be read.
    map_fallback: Option<String>,
    /// Claim spool directory.
    spool: Option<String>,
    /// Minimum seconds between two claims for the same `(ip, claim_key)`.
    spool_min_interval: Option<u64>,
    /// Maximum spool entries before the writer stops filing.
    spool_max_entries: Option<usize>,
    /// Path prefixes that count as a detection (repeatable).
    detect_prefix: Vec<String>,
    /// What to do with a request from a quarantined client.
    on_quarantined: Option<String>,
    /// Gap 1: the `Server` header the inline path sends, overriding `[deception] server_banner`.
    deception_server_banner: Option<String>,
    /// Value written into a claim's `author` field.
    author: Option<String>,
    /// Bundle S2: installed policy bundle to run from.
    policy: Option<String>,
    /// Print the installed policy and exit (S4 per-host version reporting).
    show_policy: bool,
    /// Same, as JSON.
    show_policy_json: bool,
}

impl Args {
    /// Parse argv into Args, or return an error string for stderr + exit 2.
    ///
    /// Hand-rolled rather than a CLI crate: the lockfile hash is part of the artifact's provenance
    /// record, so a dependency whose only job is argument parsing is a dependency someone else has
    /// to keep patched.
    fn parse(argv: &[String]) -> Result<Args, String> {
        let mut args = Args::default();
        let mut i = 1usize;
        while i < argv.len() {
            let flag = argv[i].as_str();
            let value = argv.get(i + 1).cloned();
            match flag {
                "--bind" => {
                    args.bind = Some(value.ok_or("--bind requires a value")?);
                    i += 2;
                }
                "--backend" => {
                    args.backend = Some(value.ok_or("--backend requires a value")?);
                    i += 2;
                }
                "--max-connections" => {
                    args.max_connections = Some(parse_usize(flag, value)?);
                    i += 2;
                }
                "--max-connections-per-source" => {
                    args.max_connections_per_source = Some(parse_usize(flag, value)?);
                    i += 2;
                }
                "--max-body-bytes" => {
                    args.max_body_bytes = Some(parse_usize(flag, value)?);
                    i += 2;
                }
                "--max-headers" => {
                    args.max_headers = Some(parse_usize(flag, value)?);
                    i += 2;
                }
                "--header-read-timeout" => {
                    args.header_read_timeout = Some(parse_u64(flag, value)?);
                    i += 2;
                }
                "--tls-handshake-timeout" => {
                    args.tls_handshake_timeout = Some(parse_u64(flag, value)?);
                    i += 2;
                }
                "--upstream-timeout" => {
                    args.upstream_timeout = Some(parse_u64(flag, value)?);
                    i += 2;
                }
                "--http2-max-concurrent-streams" => {
                    args.http2_max_concurrent_streams = Some(parse_u64(flag, value)?);
                    i += 2;
                }
                "--tls-cert" => {
                    args.tls_cert = Some(value.ok_or("--tls-cert requires a value")?);
                    i += 2;
                }
                "--tls-key" => {
                    args.tls_key = Some(value.ok_or("--tls-key requires a value")?);
                    i += 2;
                }
                "--map" => {
                    args.map = Some(value.ok_or("--map requires a value")?);
                    i += 2;
                }
                "--map-ttl" => {
                    args.map_ttl = Some(parse_u64(flag, value)?);
                    i += 2;
                }
                "--map-memo-ttl" => {
                    args.map_memo_ttl = Some(parse_u64(flag, value)?);
                    i += 2;
                }
                "--map-max-age" => {
                    args.map_max_age = Some(parse_u64(flag, value)?);
                    i += 2;
                }
                "--map-fallback" => {
                    args.map_fallback = Some(value.ok_or("--map-fallback requires a value")?);
                    i += 2;
                }
                "--spool" => {
                    args.spool = Some(value.ok_or("--spool requires a value")?);
                    i += 2;
                }
                "--spool-min-interval" => {
                    args.spool_min_interval = Some(parse_u64(flag, value)?);
                    i += 2;
                }
                "--spool-max-entries" => {
                    args.spool_max_entries = Some(parse_usize(flag, value)?);
                    i += 2;
                }
                "--detect-prefix" => {
                    args.detect_prefix
                        .push(value.ok_or("--detect-prefix requires a value")?);
                    i += 2;
                }
                "--on-quarantined" => {
                    args.on_quarantined = Some(value.ok_or("--on-quarantined requires a value")?);
                    i += 2;
                }
                "--deception-server-banner" => {
                    args.deception_server_banner =
                        Some(value.ok_or("--deception-server-banner requires a value")?);
                    i += 2;
                }
                "--author" => {
                    args.author = Some(value.ok_or("--author requires a value")?);
                    i += 2;
                }
                "--policy" => {
                    args.policy = Some(value.ok_or("--policy requires a value")?);
                    i += 2;
                }
                "--show-policy" => {
                    args.show_policy = true;
                    i += 1;
                }
                "--show-policy-json" => {
                    args.show_policy_json = true;
                    i += 1;
                }
                other => return Err(format!("unknown argument: {other}")),
            }
        }
        Ok(args)
    }

    /// Resolve flags + bundle + defaults into a Config, optionally reusing `previous`'s classifier
    /// and spool instances (see [`Config::build_with`]).
    fn build(&self, previous: Option<&Config>) -> Result<Config, String> {
        Config::build_with(self, previous)
    }
}

/// What to do with a request from a client the classifier says is quarantined.
///
/// `Inline` is the default (PTN-13). `Proxy` was the original default because Bundle R's
/// deliverable was the classification and reporting path rather than the response behaviour - but
/// that default meant a policy which omitted the field forwarded the exploit request to the
/// backend it had just been quarantined from, which is the one behaviour the owner rule forbids,
/// and it did so invisibly. `Proxy` stays legal and is now labelled "advisory" wherever the
/// console reports it. `Reject` is the cheap local answer that mirrors what Apache does for an
/// over-quota address.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Quarantined {
    /// Keep proxying, but label the response and log the classification.
    Proxy,
    /// Answer locally without contacting the backend (the cheap over-quota answer).
    Reject,
    /// Answer locally from a static inline profile after a bounded delay (Bundle T1).
    Inline,
}

impl Quarantined {
    /// Parse `--on-quarantined` / the bundle's `on_quarantined` value.
    fn parse(raw: &str) -> Option<Quarantined> {
        match raw {
            "proxy" => Some(Quarantined::Proxy),
            "reject" => Some(Quarantined::Reject),
            "inline" => Some(Quarantined::Inline),
            _ => None,
        }
    }

    /// Lower-case label for logs.
    fn label(&self) -> &'static str {
        match self {
            Quarantined::Proxy => "proxy",
            Quarantined::Reject => "reject",
            Quarantined::Inline => "inline",
        }
    }
}

/// TLS certificate and key, loaded from disk.
struct TlsMaterial {
    cert_path: String,
    key_path: String,
}

impl Config {
    /// Build a Config from parsed flags, a policy bundle, and built-in defaults.
    ///
    /// Precedence per field: explicit flag, then bundle value, then the built-in default. When
    /// `previous` is supplied (a reload), the classifier and spool instances are reused whenever
    /// their settings are unchanged - rebuilding them would throw away the map cache, the detection
    /// memo, and the claim rate-limit memory for a change that had nothing to do with them.
    fn build_with(args: &Args, previous: Option<&Config>) -> Result<Config, String> {
        // The loader returns the policy and the sha256 of the file it parsed; both are kept,
        // because `--show-policy` and the reload log have to name the exact bytes in force.
        let (bundle, bundle_sha) = match &args.policy {
            Some(path) => {
                let (loaded, sha) = policy::Policy::load(Path::new(path))?;
                (Some(Arc::new(loaded)), Some(sha))
            }
            None => (None, None),
        };
        // Shorthand: flag value, else bundle value, else the built-in default.
        let pick_str =
            |flag: &Option<String>, from_bundle: Option<String>, default: &str| -> String {
                flag.clone()
                    .or(from_bundle)
                    .unwrap_or_else(|| default.to_string())
            };
        let pick_usize = |flag: Option<usize>, from_bundle: Option<usize>| -> Option<usize> {
            flag.or(from_bundle)
        };
        let pick_u64 =
            |flag: Option<u64>, from_bundle: Option<u64>| -> Option<u64> { flag.or(from_bundle) };

        let bind = pick_str(
            &args.bind,
            bundle.as_ref().map(|p| p.listener.bind.clone()),
            "127.0.0.1:8080",
        );
        let backend = pick_str(
            &args.backend,
            bundle.as_ref().map(|p| p.routing.default_backend.clone()),
            "http://127.0.0.1:8088",
        );
        let max_connections = pick_usize(
            args.max_connections,
            bundle.as_ref().map(|p| p.limits.max_connections),
        )
        .unwrap_or(512);
        let max_connections_per_source = pick_usize(
            args.max_connections_per_source,
            bundle.as_ref().map(|p| p.limits.max_connections_per_source),
        )
        .unwrap_or(16);
        let max_body_bytes = pick_usize(
            args.max_body_bytes,
            bundle.as_ref().map(|p| p.limits.max_body_bytes),
        )
        .unwrap_or(8 * 1024 * 1024);
        let max_headers = pick_usize(
            args.max_headers,
            bundle.as_ref().map(|p| p.limits.max_headers),
        )
        .unwrap_or(100);
        let header_read_timeout_secs = pick_u64(
            args.header_read_timeout,
            bundle.as_ref().map(|p| p.limits.header_read_timeout_secs),
        )
        .unwrap_or(policy::DEFAULT_HEADER_READ_TIMEOUT_SECS);
        // PTN-08: the two remaining waits in the request path. Both were unbounded before, and both
        // are paid for by the gateway rather than the client - a stalled handshake pins a task and a
        // socket, a silent backend pins a task and an upstream connection.
        let tls_handshake_timeout_secs = pick_u64(
            args.tls_handshake_timeout,
            bundle.as_ref().map(|p| p.limits.tls_handshake_timeout_secs),
        )
        .unwrap_or(policy::DEFAULT_TLS_HANDSHAKE_TIMEOUT_SECS);
        let upstream_timeout_secs = pick_u64(
            args.upstream_timeout,
            bundle.as_ref().map(|p| p.limits.upstream_timeout_secs),
        )
        .unwrap_or(policy::DEFAULT_UPSTREAM_TIMEOUT_SECS);
        let http2_max_concurrent_streams = pick_u64(
            args.http2_max_concurrent_streams,
            bundle
                .as_ref()
                .map(|p| p.limits.http2_max_concurrent_streams),
        )
        .unwrap_or(policy::DEFAULT_HTTP2_MAX_CONCURRENT_STREAMS);
        // TLS is all-or-nothing: a cert without a key (or the reverse) is a misconfiguration that
        // would otherwise silently downgrade the listener to cleartext.
        let cert = args
            .tls_cert
            .clone()
            .or_else(|| bundle.as_ref().and_then(|p| p.listener.tls_cert.clone()));
        let key = args
            .tls_key
            .clone()
            .or_else(|| bundle.as_ref().and_then(|p| p.listener.tls_key.clone()));
        let tls = match (cert, key) {
            (Some(c), Some(k)) => Some(TlsMaterial {
                cert_path: c,
                key_path: k,
            }),
            (None, None) => None,
            (Some(_), None) => return Err("--tls-cert given without --tls-key".to_string()),
            (None, Some(_)) => return Err("--tls-key given without --tls-cert".to_string()),
        };
        let trusted_proxies = bundle
            .as_ref()
            .map(|p| p.listener.trusted_proxies.clone())
            .unwrap_or_default();
        let map = args
            .map
            .clone()
            .or_else(|| bundle.as_ref().and_then(|p| p.quarantine.map.clone()));
        let map_ttl =
            pick_u64(args.map_ttl, bundle.as_ref().map(|p| p.quarantine.map_ttl)).unwrap_or(300);
        let map_memo_ttl = pick_u64(
            args.map_memo_ttl,
            bundle.as_ref().map(|p| p.quarantine.map_memo_ttl),
        )
        .unwrap_or(60);
        // PTN-14: the map format has no per-entry expiry, so the gateway needs its own bound on how
        // old a rendered map may be before its quarantine entries stop being trusted.
        let map_max_age = pick_u64(
            args.map_max_age,
            bundle.as_ref().map(|p| p.quarantine.map_max_age),
        )
        .unwrap_or(policy::DEFAULT_MAP_MAX_AGE_SECS);
        let map_fallback = pick_str(
            &args.map_fallback,
            bundle.as_ref().map(|p| p.quarantine.fallback.clone()),
            "allow",
        );
        let spool_dir = args
            .spool
            .clone()
            .or_else(|| bundle.as_ref().and_then(|p| p.spool.dir.clone()));
        let spool_min_interval = pick_u64(
            args.spool_min_interval,
            bundle.as_ref().map(|p| p.spool.min_interval),
        )
        .unwrap_or(300);
        let spool_max_entries = pick_usize(
            args.spool_max_entries,
            bundle.as_ref().map(|p| p.spool.max_entries),
        )
        .unwrap_or(10_000);
        let detect_prefix = if !args.detect_prefix.is_empty() {
            args.detect_prefix.clone()
        } else {
            bundle
                .as_ref()
                .map(|p| p.detection.prefixes.clone())
                .unwrap_or_default()
        };
        let detect_shapes = bundle
            .as_ref()
            .map(|p| p.detection.shapes.clone())
            .unwrap_or_default();
        let detect_body_markers = bundle
            .as_ref()
            .map(|p| p.detection.body_markers.clone())
            .unwrap_or_default();
        // PTN-13: the fallback used to be `proxy`, so a policy that omitted the field - or a host
        // started from a flag-only command line - forwarded the request that had just been
        // classified to the real backend. That is the one behaviour the owner rule forbids ("if
        // someone sends an exploit, we do not want to be dealing with them at all"), and it was
        // invisible: the console still showed the host as healthy. `inline` is the safe default;
        // `proxy` remains a legal, deliberate choice for testing, and the console now labels it.
        let on_quarantined = pick_str(
            &args.on_quarantined,
            bundle.as_ref().map(|p| p.quarantine.on_quarantined.clone()),
            "inline",
        );
        let author = args.author.clone().unwrap_or_else(|| PKG_NAME.to_string());

        // Validate everything before constructing, so a bad bundle fails the start (or the reload)
        // rather than producing a half-valid configuration.
        let addr = bind
            .parse::<SocketAddr>()
            .map_err(|e| format!("bind {bind}: {e}"))?;
        hyper::Uri::try_from(backend.as_str()).map_err(|e| format!("backend {backend}: {e}"))?;
        let fallback = classify::Fallback::parse(&map_fallback).ok_or_else(|| {
            format!("map-fallback {map_fallback}: expected allow, tarpit or reject")
        })?;
        let quarantined = Quarantined::parse(&on_quarantined).ok_or_else(|| {
            format!("on-quarantined {on_quarantined}: expected proxy, reject or inline")
        })?;
        if map.is_some() && map_ttl == 0 {
            return Err("map-ttl 0 would re-read the map on every request".to_string());
        }
        if detect_prefix.iter().any(|prefix| prefix.is_empty()) {
            return Err("detect-prefix must not be empty".to_string());
        }
        if author.is_empty() {
            return Err("author must not be empty".to_string());
        }
        if max_connections == 0 {
            return Err("max-connections must be greater than 0".to_string());
        }

        // Reuse the stateful pieces when their settings did not change (see the doc above).
        let wanted_classifier = classify::Classifier::new(
            map.clone(),
            Duration::from_secs(map_ttl),
            Duration::from_secs(map_memo_ttl),
            fallback,
        )
        .with_max_age(Duration::from_secs(map_max_age))
        .fingerprint();
        let classifier = match previous {
            Some(prev) if prev.classifier.fingerprint() == wanted_classifier => {
                Arc::clone(&prev.classifier)
            }
            _ => Arc::new(
                classify::Classifier::new(
                    map,
                    Duration::from_secs(map_ttl),
                    Duration::from_secs(map_memo_ttl),
                    fallback,
                )
                .with_max_age(Duration::from_secs(map_max_age)),
            ),
        };
        // PTN-08: per-authority in-flight accounting is live state, not configuration. Reuse the
        // running table across a reload so requests being served under the old configuration keep
        // their slot; a fresh map would report zero and let a burst through the door a reload opened.
        let authorities = match previous {
            Some(prev) => Arc::clone(&prev.authorities),
            None => Arc::new(AuthorityCounts::new()),
        };
        // Bundle T1/T4: the inline deception budget. Settings come from the bundle; a flag-only
        // `--on-quarantined inline` with no bundle installed falls back to the documented defaults
        // rather than erroring, so the pre-S deployment shape keeps working.
        let reuse_or_new = |settings: deception::Settings| -> Arc<deception::Budget> {
            match previous {
                Some(prev)
                    if prev
                        .deception
                        .as_ref()
                        .map(|b| b.fingerprint() == settings.fingerprint())
                        .unwrap_or(false) =>
                {
                    Arc::clone(prev.deception.as_ref().expect("previous deception budget"))
                }
                _ => Arc::new(deception::Budget::new(&settings)),
            }
        };
        let mut settings = match (
            bundle.as_ref().and_then(|p| p.deception.clone()),
            quarantined,
        ) {
            (Some(settings), _) => Some(settings),
            (None, Quarantined::Inline) => Some(deception::Settings::default_inline()),
            (None, _) => None,
        };
        // Gap 1: `--deception-server-banner` overrides the bundle's banner the way every other flag
        // overrides its key. Validated here as well as in `Policy::parse`, because a flag-only run
        // never goes through the policy parser and an illegal banner would otherwise surface as a
        // failed response build on the first quarantined request.
        let deception: Option<Arc<deception::Budget>> = match settings.take() {
            Some(mut settings) => {
                if let Some(banner) = &args.deception_server_banner {
                    settings.server_banner = banner.clone();
                }
                settings
                    .validate()
                    .map_err(|error| format!("deception: {error}"))?;
                Some(reuse_or_new(settings))
            }
            None => None,
        };
        let wanted_spool = spool::Spool::new(
            spool_dir.clone().filter(|dir| !dir.is_empty()),
            Duration::from_secs(spool_min_interval),
            spool_max_entries,
        )
        .fingerprint();
        let spool = match previous {
            Some(prev) if prev.spool.fingerprint() == wanted_spool => Arc::clone(&prev.spool),
            _ => Arc::new(spool::Spool::new(
                spool_dir.filter(|dir| !dir.is_empty()),
                Duration::from_secs(spool_min_interval),
                spool_max_entries,
            )),
        };

        Ok(Config {
            bind: addr,
            backend,
            max_connections,
            max_connections_per_source,
            authorities,
            max_body_bytes,
            max_headers,
            header_read_timeout_secs,
            tls_handshake_timeout_secs,
            upstream_timeout_secs,
            http2_max_concurrent_streams,
            tls,
            trusted_proxies,
            classifier,
            spool,
            deception,
            detect_prefix,
            detect_shapes,
            detect_body_markers,
            quarantined,
            author,
            policy: bundle,
            policy_sha: bundle_sha,
        })
    }

    /// One line describing the active policy - the string `--show-policy` and reload logs print.
    fn policy_line(&self) -> String {
        match (&self.policy, &self.policy_sha) {
            (Some(policy), Some(sha)) => format!("policy {} sha256={}", policy.summary(), sha),
            _ => "policy none (flag-only configuration)".to_string(),
        }
    }

    /// The `--show-policy-json` payload (S4's machine-readable per-host answer).
    fn policy_json(&self) -> String {
        match (&self.policy, &self.policy_sha) {
            (Some(policy), Some(sha)) => policy.to_json(sha),
            _ => format!(
                "\"binary\":\"{PKG_NAME}\",\"binary_version\":\"{VERSION}\",\"policy\":null"
            ),
        }
    }

    /// Machine-readable identity, used by `--version-json` and by artifact verification.    /// Machine-readable identity, used by `--version-json` and by artifact verification.
    fn identity_json() -> String {
        let mut fields = BTreeMap::new();
        fields.insert("name", PKG_NAME);
        fields.insert("version", VERSION);
        fields
            .into_iter()
            .map(|(k, v)| format!("\"{}\":\"{}\"", k, v))
            .collect::<Vec<String>>()
            .join(",")
    }
}

/// Parse a `--flag value` pair as usize with the flag named in the error.
fn parse_usize(flag: &str, value: Option<String>) -> Result<usize, String> {
    let raw = value.ok_or(format!("{flag} requires a value"))?;
    raw.parse::<usize>()
        .map_err(|e| format!("{flag}: {e} (got {raw:?})"))
}

/// Parse a u64 flag value with the same error shape as `parse_usize`.
fn parse_u64(flag: &str, value: Option<String>) -> Result<u64, String> {
    let raw = value.ok_or(format!("{flag} requires a value"))?;
    raw.parse::<u64>()
        .map_err(|e| format!("{flag}: {e} (got {raw:?})"))
}

/// The request target to forward: path and query together (PTN-01).
///
/// `Uri::path()` deliberately excludes the query, so an upstream URI built from it alone turns
/// `GET /search.php?q=abc&page=2` into `GET /search.php`. `path_and_query()` is the accessor that
/// keeps both; it is `None` only for a URI that has an authority and no path (`CONNECT`-style),
/// where `/` is the target to forward rather than an empty string.
fn request_target(parts: &hyper::http::request::Parts) -> String {
    let target = parts
        .uri
        .path_and_query()
        .map(|path_and_query| path_and_query.as_str())
        .unwrap_or_else(|| parts.uri.path());
    if target.is_empty() {
        "/".to_string()
    } else {
        target.to_string()
    }
}

/// Render an HTTP version the way a server logs it.
///
/// `Version`'s Debug format is not stable across hyper releases, and the response protocol is
/// exactly the detail the O8 claims hinge on, so it is spelled out here.
fn version_label(version: Version) -> String {
    match version {
        Version::HTTP_09 => "HTTP/0.9".to_string(),
        Version::HTTP_10 => "HTTP/1.0".to_string(),
        Version::HTTP_11 => "HTTP/1.1".to_string(),
        Version::HTTP_2 => "HTTP/2.0".to_string(),
        Version::HTTP_3 => "HTTP/3.0".to_string(),
        _ => "HTTP/unknown".to_string(),
    }
}

/// Headers that must not be forwarded (RFC 9110 §7.6.1) plus the ones the gateway owns.
///
/// Forwarding `Connection`/`Keep-Alive`/`Transfer-Encoding` from a client across a protocol
/// boundary is the classic gateway corruption: an h2 client has no `Connection` header concept,
/// and `Transfer-Encoding: chunked` is meaningless on an h1 upstream that hyper frames itself.
fn is_hop_byhop(name: &HeaderName) -> bool {
    matches!(
        name.as_str().to_ascii_lowercase().as_str(),
        "connection"
            | "proxy-connection"
            | "keep-alive"
            | "transfer-encoding"
            | "te"
            | "trailer"
            | "upgrade"
            | "x-request-id"
            | "x-forwarded-for"
            | "x-forwarded-proto"
            | "x-forwarded-by"
            | "x-forwarded-version"
            | "forwarded"
    )
}

/// Names this process owns, plus one reason each appears here.
///
/// `x-forwarded-version` and `x-forwarded-by` are additions (2026-11-24): the copy loop runs before
/// the forwarding headers are set, and `Request::builder().header()` *appends* rather than replaces,
/// so a client that sent either name had its own value forwarded alongside the generated one. A
/// backend that reads the first value then believes the client's claim about which protocol the
/// gateway served, which is the one fact the gateway is supposed to be the authority on.
///
/// Header names the request's own `Connection` header declares to be hop-by-hop (PTN-16).
///
/// `Connection: foo` is a statement that `foo` is hop-specific and must not be forwarded, and a
/// fixed deny-list cannot know the names a client invents - `Connection: X-Api-Token` is exactly how
/// a scanner hands its own credential to the next hop. The tokens have to be read from the request
/// itself before its headers are copied, otherwise the gateway forwards a header the sending client
/// said was only for the gateway.
fn connection_tokens(headers: &HeaderMap) -> Vec<HeaderName> {
    let Some(value) = headers.get("connection") else {
        return Vec::new();
    };
    // A header value that is not UTF-8 cannot name a field, and `Connection` is a comma list, so
    // every token has to be parsed on its own: `Connection: a, b` declares two headers, not one
    // named "a, b".
    let Ok(text) = std::str::from_utf8(value.as_bytes()) else {
        return Vec::new();
    };
    text.split(',')
        .map(str::trim)
        .filter(|token| !token.is_empty())
        .filter_map(|token| HeaderName::from_bytes(token.as_bytes()).ok())
        .collect()
}

/// Build a gateway-authored response with an explicit status (PTN-19).
///
/// The body echoes the parsed request line plus the gateway identity, which is what makes a
/// captured response attributable to this binary on a host that also runs Apache on :80/:443.
///
/// The status is an argument because it used to be a constant: every gateway-authored failure went
/// out as `200 OK`, including `upstream_request_build_failed`, so a client reading only the status
/// line recorded success while the body said the gateway had given up. 413 (body over the cap),
/// 400 (body could not be read) and 502 (upstream request could not be built) now each say what
/// they mean.
/// The request body as it reaches the proxy: either still streaming from the client, or already
/// collected because a body marker had to be checked before the inline/proxy decision.
enum RequestBody {
    Incoming(Incoming),
    /// A body already read into memory, with the reservation that accounts for it. Carrying the
    /// guard here rather than dropping it is what keeps the budget truthful: the bytes exist until
    /// the upstream request is finished, so the reservation has to live exactly that long.
    Collected(Bytes, BufferReservation),
}

/// Whether `haystack` contains `needle`. Used for body markers, where the body is already in memory.
fn contains_bytes(haystack: &[u8], needle: &[u8]) -> bool {
    if needle.is_empty() || needle.len() > haystack.len() {
        return false;
    }
    haystack
        .windows(needle.len())
        .any(|window| window == needle)
}

fn gateway_status_response(
    method: &Method,
    path: &str,
    version: Version,
    request_id: &str,
    status: StatusCode,
    note: &str,
) -> Response<GatewayBody> {
    let text = format!(
        "{PKG_NAME} {VERSION}\nrequest={method} {path} {}\nstatus={}\nrequest_id={request_id}\nnote={note}\n",
        version_label(version),
        status.as_u16(),
    );
    Response::builder()
        .status(status)
        .header(hyper::header::SERVER, format!("{PKG_NAME}/{VERSION}"))
        .header(hyper::header::CONTENT_TYPE, "text/plain; charset=utf-8")
        .header("x-request-id", request_id)
        .header("x-fleet-filter", "gateway")
        .body(full_body(Bytes::from(text)))
        // The only failure mode of `Response::builder()` is an invalid status/header pair, and
        // every value here is either a constant or a generated id validated at construction.
        .expect("static response built from valid constants")
}

/// Load and validate the TLS material, then build the rustls server config.
///
/// The crypto provider is passed explicitly (`ring`) rather than taken from the process default:
/// rustls 0.23's default provider is `aws-lc-rs`, so `ServerConfig::builder()` would silently
/// use a provider ADR-0001 rejected. Explicit selection is the difference between a pin and a
/// hope. ALPN advertises `h2` then `http/1.1`, which is what makes "the client negotiated h2
/// with the gateway" observable from the client side.
fn build_server_config(
    material: &TlsMaterial,
    policy: Option<&policy::Policy>,
) -> Result<rustls::ServerConfig, String> {
    let provider = rustls::crypto::ring::default_provider();
    let mut cert_reader = BufReader::new(
        File::open(&material.cert_path).map_err(|e| format!("{}: {e}", material.cert_path))?,
    );
    let certs: Vec<rustls::pki_types::CertificateDer<'static>> =
        rustls_pemfile::certs(&mut cert_reader)
            .collect::<Result<Vec<_>, _>>()
            .map_err(|e| format!("{}: {e}", material.cert_path))?;
    if certs.is_empty() {
        return Err(format!("{}: no certificates found", material.cert_path));
    }

    let mut key_reader = BufReader::new(
        File::open(&material.key_path).map_err(|e| format!("{}: {e}", material.key_path))?,
    );
    let key = rustls_pemfile::private_key(&mut key_reader)
        .map_err(|e| format!("{}: {e}", material.key_path))?
        .ok_or_else(|| format!("{}: no private key found", material.key_path))?;

    // The protocol versions and the ALPN list come from the policy when one is installed, so the
    // TLS floor in a posture profile is what the listener actually offers. Without a policy the
    // pre-S behaviour is kept: TLS 1.2 + 1.3, advertising h2 and http/1.1.
    let versions: &'static [&'static rustls::SupportedProtocolVersion] = match policy {
        Some(policy) => policy.profile.min_tls_version.rustls_versions(),
        None => &policy::TLS12_AND_13,
    };
    let mut config = rustls::ServerConfig::builder_with_provider(provider.into())
        .with_protocol_versions(versions)
        .map_err(|e| format!("builder: {e}"))?
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .map_err(|e| format!("with_single_cert: {e}"))?;
    config.alpn_protocols = match policy {
        Some(policy) => policy
            .listener
            .alpn
            .iter()
            .map(|protocol| protocol.as_bytes().to_vec())
            .collect(),
        None => vec![b"h2".to_vec(), b"http/1.1".to_vec()],
    };
    Ok(config)
}

/// Generate a request correlation id (O7).
///
/// Format is `t<unix-seconds>-<monotonic-counter>`: sortable, cheap, unique per process, and it
/// does not require a UUID crate in the lockfile to answer "which backend log line belongs to
/// this gateway log line".
fn request_id(counter: &AtomicU64) -> String {
    let seconds = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let seq = counter.fetch_add(1, Ordering::Relaxed);
    format!("t{seconds}-{seq}")
}

/// Format an address for use in a `Forwarded`/`X-Forwarded-For` value.
///
/// IPv6 addresses are bracketed per RFC 7239 §6.1 (a bare colon makes the value ambiguous); IPv4
/// is emitted bare. Doing this in one function is what keeps the generated header valid for both
/// address families instead of only the one that was tested.
/// Whether `ip` is a proxy whose forwarding header can be believed.
fn trusted_peer(ip: IpAddr, trusted: &[policy::Cidr]) -> bool {
    trusted.iter().any(|prefix| prefix.contains(ip))
}

/// The address a request is judged by: the peer's, unless the peer is a trusted proxy that supplied
/// one.
///
/// The walk is right-to-left because a proxy appends what it saw. The leftmost entries are whatever
/// the client chose to send - a client that writes `X-Forwarded-For: 1.2.3.4` to get someone else
/// quarantined is sending a wish, and reading from the left would grant it. Entries that are
/// themselves trusted proxies are skipped, because a chain of them appends more than one address and
/// the answer wanted is the first hop that is not part of the chain.
///
/// A trusted peer with no usable header falls back to its own address. That is the safe direction:
/// the alternative - treating it as anonymous-but-normal - would let a broken proxy silently
/// disable classification for everything behind it.
fn effective_source(peer: IpAddr, headers: &hyper::HeaderMap, trusted: &[policy::Cidr]) -> IpAddr {
    if !trusted_peer(peer, trusted) {
        return peer;
    }
    // Every value, in receipt order: `get()` returns only the first header, and a proxy appends to
    // the *last* one. Reading the first lets a client that sends its own `X-Forwarded-For` decide
    // which address the gateway judges - including someone else's, which is a quarantine anyone can
    // aim at a third party.
    let mut values: Vec<&str> = Vec::new();
    for value in headers.get_all("x-forwarded-for").iter() {
        if let Ok(text) = value.to_str() {
            values.push(text);
        }
    }
    if values.is_empty() {
        return peer;
    }
    // Right-to-left across the concatenation, because that is the order the chain was appended in.
    for value in values.iter().rev() {
        for candidate in value.rsplit(',') {
            let Ok(candidate) = candidate.trim().parse::<IpAddr>() else {
                continue;
            };
            if !trusted_peer(candidate, trusted) {
                return candidate;
            }
        }
    }
    peer
}

fn format_forwarded_for(addr: SocketAddr) -> String {
    match addr {
        SocketAddr::V4(v4) => v4.ip().to_string(),
        SocketAddr::V6(v6) => format!("[{}]", v6.ip()),
    }
}

/// Process-wide budget for request bodies held in memory at once.
///
/// `max_body_bytes` bounds one request; nothing bounded their sum, and the two limits multiplied:
/// 512 connections each allowed 8 MiB against a 256 MiB `MemoryMax` is an OOM from one unauthenticated
/// client with enough parallel POSTs. The budget is what turns "each request is fine" into "the
/// process is fine".
///
/// It is a static rather than configuration because it is live state, not a policy setting: a reload
/// must not reset the count while requests are still holding bytes.
static BUFFERED_BYTES: AtomicUsize = AtomicUsize::new(0);

/// How much request body the process may hold at once. Chosen so a burst cannot threaten the
/// unit's `MemoryMax=256M` even with the limit raised, while staying far above the 8 MiB cap of any
/// single request the shipped policies allow.
const MAX_BUFFERED_BYTES: usize = 64 * 1024 * 1024;

/// Held while a collected body is alive; subtracts on drop, including on every error path.
struct BufferReservation {
    bytes: usize,
}

impl Drop for BufferReservation {
    fn drop(&mut self) {
        BUFFERED_BYTES.fetch_sub(self.bytes, Ordering::Relaxed);
    }
}

/// Reserve `bytes` of the budget, or refuse when the reservation would cross it.
///
/// Reserving the declared length when the client states one, and the per-request cap when it does
/// not, is deliberately conservative: an unknown length can grow to the cap, and under-reserving is
/// how the sum slips past the budget.
fn reserve_buffer(bytes: usize, budget: usize) -> Option<BufferReservation> {
    if bytes > budget {
        return None;
    }
    let mut current = BUFFERED_BYTES.load(Ordering::Relaxed);
    loop {
        if current + bytes > budget {
            return None;
        }
        match BUFFERED_BYTES.compare_exchange_weak(
            current,
            current + bytes,
            Ordering::Relaxed,
            Ordering::Relaxed,
        ) {
            Ok(_) => return Some(BufferReservation { bytes }),
            Err(observed) => current = observed,
        }
    }
}

/// Build a HeaderValue from a generated string, falling back to a literal instead of panicking.
///
/// The values here are addresses, protocol labels and generated ids, all of which should be valid;
/// the fallback exists so that an unexpected character degrades one header rather than aborting
/// the connection handler.
fn safe_header(value: &str) -> HeaderValue {
    HeaderValue::from_str(value).unwrap_or_else(|_| HeaderValue::from_static("invalid"))
}

/// Serve one accepted connection: read the request, forward it to the backend, return the result.
///
/// `T` is generic so the same code serves a plain TCP connection and a TLS stream; the caller
/// decides which, and the protocol actually used is reported by `request.version()` rather than
/// assumed from the listener type.
/// PTN-08: complete a TLS handshake, giving up after `timeout_secs` (0 = never time out).
///
/// `TlsAcceptor::accept` has no built-in deadline. A client that finishes the TCP handshake and then
/// stalls mid-TLS therefore holds this task, the socket, and the connection permit acquired for it
/// for as long as the process lives, which converts an idle attacker into gateway memory: the cost of
/// an unfinished request is paid by the front end instead of the client.
async fn accept_tls(
    acceptor: &tokio_rustls::TlsAcceptor,
    stream: TcpStream,
    timeout_secs: u64,
) -> Result<tokio_rustls::server::TlsStream<TcpStream>, std::io::Error> {
    let handshake = acceptor.accept(stream);
    if timeout_secs == 0 {
        return handshake.await;
    }
    match tokio::time::timeout(Duration::from_secs(timeout_secs), handshake).await {
        Ok(result) => result,
        Err(error) => Err(std::io::Error::new(
            std::io::ErrorKind::TimedOut,
            format!("handshake did not complete within {timeout_secs}s ({error})"),
        )),
    }
}

async fn serve_connection<T>(
    stream: T,
    peer: SocketAddr,
    config: Arc<Config>,
    negotiated: Option<policy::TlsFloor>,
) where
    T: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
{
    let io = TokioIo::new(stream);
    let config_for_service = Arc::clone(&config);
    // The peer is the socket peer, which is the only client identity the gateway can state as
    // fact: a client-supplied X-Forwarded-For is removed by the proxy path and replaced with this
    // value, so a backend that trusts XFF is not trusting something the attacker wrote.

    let service = service_fn(move |request: Request<Incoming>| {
        let config = Arc::clone(&config_for_service);
        async move {
            Result::<Response<GatewayBody>, Infallible>::Ok(
                handle_request(request, &config, peer, negotiated).await,
            )
        }
    });

    let mut builder = AutoBuilder::new(TokioExecutor::new());
    // Apache sends title-cased header names; matching that removes a fingerprint difference
    // between the gateway and the backend it fronts. The header-count and header-read-timeout
    // limits are the O6 controls that stop a client from making the gateway parse arbitrarily
    // much work before it is allowed to answer.
    //
    // The timeout and the timer are one setting, not two: hyper represents a configured timeout
    // without a timer as `Dur::Configured(Some(..))` over `Time::Empty`, and reading that
    // combination panics ("timeout `header_read_timeout` set, but no timer set"). An earlier
    // revision left the timeout unconfigured on the belief that no timer existed to set it with;
    // `hyper_util::rt::TokioTimer` has existed the whole time, so the timer is now always set and
    // the configured value decides whether a timeout exists at all (0 = never expire).
    let mut http1 = builder.http1();
    http1.timer(TokioTimer::new());
    http1.title_case_headers(true);
    http1.max_headers(config.max_headers);
    if config.header_read_timeout_secs > 0 {
        http1.header_read_timeout(Duration::from_secs(config.header_read_timeout_secs));
    }
    // h2 settings stay conservative: the gateway exists to limit what the backend has to parse,
    // not to maximise throughput on a test listener. PTN-08: the stream cap is now configurable
    // rather than fixed, because one HTTP/2 client can otherwise open streams without limit and each
    // one is work the gateway proxies (or a drip it holds).
    let mut http2 = builder.http2();
    if config.http2_max_concurrent_streams > 0 {
        http2.max_concurrent_streams(config.http2_max_concurrent_streams as u32);
    }
    http2.max_frame_size(16 * 1024);

    if let Err(error) = builder.serve_connection(io, service).await {
        eprintln!("connection ended: {error}");
    }
}

/// Handle a single request: apply the policy, classify the client, act, then proxy.
///
/// The order is the whole point of Bundles R and S. The policy is consulted first, so a paused
/// gateway or a posture rejection never touches the backend; classification happens before the
/// backend is contacted, so a quarantined client can be answered locally; a detection is memoised
/// and reported before the response is built, so a claim still exists even if the client hangs up
/// before reading the answer.
async fn handle_request(
    request: Request<Incoming>,
    config: &Config,
    peer: SocketAddr,
    negotiated: Option<policy::TlsFloor>,
) -> Response<GatewayBody> {
    let (parts, body) = request.into_parts();
    // PTN-07: the scheme the client reached us over. TLS connections know their floor; a plaintext
    // connection is `http`. This is what X-Forwarded-Proto must carry, and it is not the same fact
    // as the HTTP version, which the proxy path reports separately.
    let scheme = if negotiated.is_some() {
        "https"
    } else {
        "http"
    };

    // Bundle S2/S5: policy first, backend second. `paused` is the kill switch - answer locally,
    // contact no backend, file no claim - and the posture profile refuses requests outside the
    // shape the site declares. Both precede the proxy, because a gateway that has been told to stop
    // must not still show the backend's answer, and a request the policy refuses must not reach the
    // component the policy exists to protect.
    if let Some(policy) = &config.policy {
        if policy.mode == policy::Mode::Paused {
            return policy_response(config, &parts, "paused", StatusCode::SERVICE_UNAVAILABLE);
        }
        if let Some(rejection) =
            policy
                .profile
                .evaluate(&parts.method, &parts.uri, &parts.headers, negotiated)
        {
            return policy_response(config, &parts, rejection.rule, rejection.status);
        }
    }

    // PTN-08: `[posture] admission_cap_per_authority`, which the schema carried and `Profile` parsed
    // but the request path never consulted. The permit is held for the remainder of this function, so
    // the slot covers everything the gateway does to answer; a response body still streaming after
    // this function returns has already been served, which is the honest reading of "in flight" here.
    //
    // Checked after the posture rejection on purpose: a request the policy refuses should not occupy
    // an admission slot, and answering a malformed request with 503 would hide the more useful
    // `posture` answer that explains what was malformed.
    let cap = config
        .policy
        .as_ref()
        .map(|policy| policy.profile.admission_cap_per_authority)
        .unwrap_or(0);
    let _admission: Option<AuthorityPermit> = if cap > 0 {
        match request_authority(&parts) {
            Some(authority) => match config.authorities.try_acquire(&authority, cap) {
                Some(permit) => Some(permit),
                None => {
                    return policy_response(
                        config,
                        &parts,
                        "admission_cap_per_authority",
                        StatusCode::SERVICE_UNAVAILABLE,
                    )
                }
            },
            // Nothing to attribute the request to. hyper has already rejected an HTTP/1.1 request with
            // no `Host`, so this is an HTTP/2 request with no `:authority`; serve it rather than
            // invent a refusal the profile did not ask for.
            None => None,
        }
    } else {
        None
    };

    // The address the request is judged by. Behind a load balancer every request arrives from the
    // balancer, so judging on the peer address would memoise the balancer after one detection and
    // serve deception to every client behind it - a site-wide outage triggered by one probe.
    let source = effective_source(peer.ip(), &parts.headers, &config.trusted_proxies);
    let classification = config.classifier.classify(source);
    // The request *target*, path and query together, because the store's prefixes are projections of
    // a URI as it appears in the access log and some of them carry a query (`/?rest_route=/batch/v1`
    // is the spelling the published WP2Shell exploit used). Matching `uri.path()` alone silently
    // killed every query-bearing prefix: measured 2026-11-24, that request reached the backend in
    // 43 ms and was not detected, while the path-only spelling was. A prefix is matched against what
    // the client asked for, not the part of it that happens to be a path.
    // Body markers need the body before the inline/proxy decision, so it is collected here when a
    // marker is configured. The collected bytes are handed to the proxy afterwards rather than
    // re-read, and the same `Limited` cap applies, so a body over the limit is refused on this path
    // exactly as it is on the streaming one. The two branches each consume `body` once: the compiler
    // will not let this drift into a double read, which is the property that matters here.
    let (body, body_detection) = if !config.detect_body_markers.is_empty() {
        match Limited::new(body, config.max_body_bytes).collect().await {
            Ok(everything) => {
                let bytes = everything.to_bytes();
                let found = config.detect_body_markers.iter().find_map(|marker| {
                    contains_bytes(&bytes, marker.as_bytes()).then(|| format!("body:{marker}"))
                });
                let reservation = match reserve_buffer(bytes.len(), MAX_BUFFERED_BYTES) {
                    Some(reservation) => reservation,
                    None => {
                        return gateway_status_response(
                            &parts.method,
                            parts.uri.path(),
                            parts.version,
                            &new_id(),
                            StatusCode::SERVICE_UNAVAILABLE,
                            "buffer_budget_exhausted",
                        );
                    }
                };
                (RequestBody::Collected(bytes, reservation), found)
            }
            Err(error) if error.downcast_ref::<LengthLimitError>().is_some() => {
                return gateway_status_response(
                    &parts.method,
                    parts.uri.path(),
                    parts.version,
                    &new_id(),
                    StatusCode::PAYLOAD_TOO_LARGE,
                    "body_exceeds_max_body_bytes",
                );
            }
            Err(_) => {
                return gateway_status_response(
                    &parts.method,
                    parts.uri.path(),
                    parts.version,
                    &new_id(),
                    StatusCode::BAD_REQUEST,
                    "body_read_failed",
                );
            }
        }
    } else {
        (RequestBody::Incoming(body), None)
    };

    let detection = match_detection(&config.detect_prefix, &parts.uri)
        .or_else(|| match_shape(&config.detect_shapes, &parts))
        .or(body_detection);

    // A local detection is memoised and filed immediately. Waiting for the controller to drain and
    // render (measured in R5 as minutes) would leave this client classified as normal for the rest
    // of the burst, which is the gap the memo exists to close.
    if let Some(claim_key) = detection {
        config
            .classifier
            .memoize(source, classify::Verdict::Tarpitted);
        let mut claim = spool::Claim::new(
            &source.to_string(),
            classify::Verdict::Tarpitted.claim_verdict(),
            PKG_NAME,
            &config.author,
            &claim_key,
        )
        .with_evidence("method", parts.method.as_str())
        .with_evidence("path", parts.uri.path())
        .with_evidence("protocol", &version_label(parts.version));
        claim.evidence.push(("request_id".to_string(), new_id()));
        let submission = config.spool.submit(&claim, spool::epoch_now());
        if submission.label() != "disabled" {
            eprintln!(
                "detection peer={} source={} claim={} spool={}",
                peer.ip(),
                source,
                claim_key,
                submission.label()
            );
        }
        // T1/T3: with inline deception the gateway answers the detected request itself, from the
        // profile named for detections, and never opens a backend connection.
        if config.quarantined == Quarantined::Inline {
            return serve_inline(config, &parts, Some(classification), true).await;
        }
        return proxy_request(
            parts,
            body,
            config,
            &format_forwarded_for(SocketAddr::new(source, peer.port())),
            &format_forwarded_for(config.bind),
            scheme,
            Some(classification),
        )
        .await;
    }

    // A quarantined client is answered according to the deployed policy: `reject` is the cheap
    // local answer, `inline` is the delayed inline profile (T1), and `proxy` keeps behaviour
    // identical to the pre-R gateway while still labelling the response.
    if classification.verdict != classify::Verdict::Normal {
        match config.quarantined {
            Quarantined::Reject => return local_reject(&parts, classification),
            Quarantined::Inline => {
                return serve_inline(config, &parts, Some(classification), false).await
            }
            Quarantined::Proxy => {}
        }
    }
    // A normal client gets no extra header: an unlabelled response is what keeps the gateway from
    // becoming a fingerprint, the same reasoning as PT-12's opt-in marker in the responder.
    proxy_request(
        parts,
        body,
        config,
        &format_forwarded_for(SocketAddr::new(source, peer.port())),
        &format_forwarded_for(config.bind),
        scheme,
        if classification.verdict == classify::Verdict::Normal {
            None
        } else {
            Some(classification)
        },
    )
    .await
}

/// The string a detection prefix is matched against: the path and the query together.
///
/// A prefix is a projection of the request target as the access log records it, and some of the
/// store's prefixes carry a query (`/?rest_route=/batch/v1` is the spelling the published WP2Shell
/// exploit used). Matching `uri.path()` alone silently killed those - measured 2026-11-24, that
/// request reached the backend in 43 ms while the path-only spelling was detected in 2.6 s.
fn detection_target(uri: &hyper::Uri) -> std::borrow::Cow<'_, str> {
    match uri.query() {
        Some(query) => {
            std::borrow::Cow::Owned(fold_for_matching(&format!("{}?{}", uri.path(), query)))
        }
        None => std::borrow::Cow::Borrowed(uri.path()),
    }
}

/// Fold a request target into the form prefixes are written in: ASCII-lowercased, with percent
/// encodings' hex digits lowercased, and nothing decoded.
///
/// Why not decode, when every imported rule set assumes it? Because decoding is precisely the signal
/// for the traversal class: `.%2e` is interesting *because* it is encoded, and a matcher that decodes
/// it first turns the exploit into `/../` and then has to distinguish an attack from a path that
/// Apache would simply normalise. Keeping the encoded form and folding its case gives the property
/// that matters - `%2E` and `%2e` are the same byte sequence to Apache, so they must be the same
/// string to us - without erasing what we are looking for.
///
/// Measured reason this exists (2026-11-24): the store documented, honestly, that `%2E` uppercase
/// "is not covered" by the gateway projection. That is not a limitation of literal matching; it is a
/// missing fold, and it made every imported corpus half-blind.
fn fold_for_matching(target: &str) -> String {
    let mut out = String::with_capacity(target.len());
    let mut chars = target.chars();
    while let Some(ch) = chars.next() {
        if ch == '%' {
            out.push('%');
            for _ in 0..2 {
                match chars.next() {
                    Some(hex) => out.push(hex.to_ascii_lowercase()),
                    None => break,
                }
            }
        } else {
            out.push(ch.to_ascii_lowercase());
        }
    }
    out
}

/// The first configured prefix matching the request target, as the claim key the spool files.
fn match_detection(prefixes: &[String], uri: &hyper::Uri) -> Option<String> {
    // The no-query case borrows the raw path, so fold it here rather than allocating twice.
    let target = match uri.query() {
        Some(_) => detection_target(uri),
        None => std::borrow::Cow::Owned(fold_for_matching(uri.path())),
    };
    prefixes
        .iter()
        .find(|prefix| target.starts_with(prefix.as_str()))
        .map(|prefix| format!("prefix:{prefix}"))
}

/// The protocol label a shape predicate compares against.
///
/// HTTP/2 over TLS and cleartext h2c are the same version inside the server, so a shape naming
/// either is matched by `h2`; a shape that must distinguish them cannot be expressed here and does
/// not claim to be.
fn protocol_label(version: hyper::Version) -> &'static str {
    match version {
        hyper::Version::HTTP_2 => "h2",
        hyper::Version::HTTP_10 => "http/1.0",
        hyper::Version::HTTP_11 => "http/1.1",
        _ => "other",
    }
}

/// The Content-Length state of a request: absent, a declared zero, or a real length.
fn content_length_state(headers: &hyper::HeaderMap) -> &'static str {
    match headers.get(hyper::header::CONTENT_LENGTH) {
        None => "absent",
        Some(value) if value.as_bytes() == b"0" => "zero",
        Some(_) => "present",
    }
}

/// The first structured shape the request satisfies, as the claim key the spool files.
///
/// Every predicate a shape declares must hold. This is how the protocol-class variants in
/// `controller/signatures/signatures.yaml` become enforceable at the gateway: they are statements
/// about the request that a path prefix cannot carry (protocol version, method, the presence of
/// Content-Type, the state of Content-Length, header count), and all of them are already parsed
/// here. The body is never read.
fn match_shape(shapes: &[policy::Shape], parts: &hyper::http::request::Parts) -> Option<String> {
    let protocol = protocol_label(parts.version);
    let content_length = content_length_state(&parts.headers);
    for shape in shapes {
        if !shape.protocols.is_empty() && !shape.protocols.iter().any(|p| p == protocol) {
            continue;
        }
        if !shape.methods.is_empty() && !shape.methods.iter().any(|m| m == parts.method.as_str()) {
            continue;
        }
        if let Some(wanted) = shape.content_type {
            let present = parts.headers.contains_key(hyper::header::CONTENT_TYPE);
            if present != wanted {
                continue;
            }
        }
        if !shape.content_length.is_empty()
            && !shape
                .content_length
                .iter()
                .any(|state| state == content_length)
        {
            continue;
        }
        if let Some(prefix) = &shape.header_prefix {
            let found = parts
                .headers
                .keys()
                .any(|name| name.as_str().starts_with(prefix.as_str()));
            if !found {
                continue;
            }
        }
        if let Some(minimum) = shape.min_headers {
            if parts.headers.len() < minimum {
                continue;
            }
        }
        return Some(format!("shape:{}", shape.name));
    }
    None
}

/// Serve a quarantined or detected request from an inline profile (T1) instead of the backend.
///
/// Both degradation paths answer locally and neither forwards: with no drip slot the answer is an
/// immediate 503 (`x-fleet-filter-deception: budget-exhausted`), and with no configured budget the
/// request is answered as a plain local reject. Forwarding either one would send a request the
/// gateway already judged hostile to the backend, which is exactly what T5 forbids.
async fn serve_inline(
    config: &Config,
    parts: &hyper::http::request::Parts,
    classification: Option<classify::Classification>,
    detected: bool,
) -> Response<GatewayBody> {
    let Some(budget) = config.deception.as_ref() else {
        // Inline selected without settings: answer locally rather than forward.
        return match classification {
            Some(c) => local_reject(parts, c),
            None => policy_response(
                config,
                parts,
                "deception_unconfigured",
                StatusCode::SERVICE_UNAVAILABLE,
            ),
        };
    };
    let settings = budget.settings();
    let profile = deception::select(
        &settings.detected_profile,
        &settings.quarantined_profile,
        detected,
        parts.uri.path(),
    );
    let Some(permit) = budget.try_acquire() else {
        // T5: budget exhaustion degrades to refusal, never to forwarding and never to queueing.
        let mut response = match classification {
            Some(c) => local_reject(parts, c),
            None => policy_response(
                config,
                parts,
                "deception_budget_exhausted",
                StatusCode::SERVICE_UNAVAILABLE,
            ),
        };
        if let Ok(value) = HeaderValue::from_str("budget-exhausted") {
            response
                .headers_mut()
                .insert(HeaderName::from_static("x-fleet-filter-deception"), value);
        }
        return response;
    };
    // T1 shape: the answer streams in chunks with gaps (see `deception::DripBody`), so there is no
    // sleep here. A pre-sleep wrote the whole body at once, which was a different product from the
    // responder and told a scanner which one answered.
    let mut response = permit.response(profile);
    if let Some(c) = classification {
        if let Ok(value) = HeaderValue::from_str(&c.header_value()) {
            response
                .headers_mut()
                .insert(HeaderName::from_static("x-fleet-filter-class"), value);
        }
    }
    if let Ok(value) = HeaderValue::from_str(&settings.deception_header(profile)) {
        response
            .headers_mut()
            .insert(HeaderName::from_static("x-fleet-filter-deception"), value);
    }
    response
}

/// A local answer that names the policy rule that produced it (S2/S3/S5).
///
/// The rule is in the body and in `X-Fleet-Filter-Posture`, so "why did the gateway answer 405"
/// is answerable from the response alone during an incident, without reading the config.
fn policy_response(
    config: &Config,
    parts: &hyper::http::request::Parts,
    rule: &str,
    status: StatusCode,
) -> Response<GatewayBody> {
    let policy_version = config
        .policy
        .as_ref()
        .map(|p| p.version.as_str())
        .unwrap_or("none");
    let text = format!(
        "{PKG_NAME} {VERSION}\npolicy={}\nrule={}\nstatus={}\nrequest={} {} {}\n",
        policy_version,
        rule,
        status.as_u16(),
        parts.method.as_str(),
        request_target(parts),
        version_label(parts.version),
    );
    Response::builder()
        .status(status)
        .header(hyper::header::SERVER, format!("{PKG_NAME}/{VERSION}"))
        .header(hyper::header::CONTENT_TYPE, "text/plain; charset=utf-8")
        .header("x-fleet-filter-posture", rule)
        .body(full_body(Bytes::from(text)))
        .expect("static response built from valid constants")
}

/// The cheap local answer for a quarantined client when `--on-quarantined reject` is set.
///
/// Mirrors what Apache does for an over-quota address (PT-04): answer locally with a small
/// response instead of spending a worker on a client the controller has already judged.
fn local_reject(
    parts: &hyper::http::request::Parts,
    classification: classify::Classification,
) -> Response<GatewayBody> {
    let text = format!(
        "{PKG_NAME} {VERSION}\nrequest={} {} {}\nclassification={}\n",
        parts.method.as_str(),
        request_target(parts),
        version_label(parts.version),
        classification.verdict.label()
    );
    Response::builder()
        .status(StatusCode::SERVICE_UNAVAILABLE)
        .header(hyper::header::SERVER, format!("{PKG_NAME}/{VERSION}"))
        .header(hyper::header::CONTENT_TYPE, "text/plain; charset=utf-8")
        .header("retry-after", "300")
        .header("x-fleet-filter-class", classification.verdict.label())
        .body(full_body(Bytes::from(text)))
        .expect("static response built from valid constants")
}

/// Forward a parsed request to the backend and translate the response back.
///
/// On a backend failure the gateway returns 502 with the reason rather than a bare reset,
/// because "the gateway could not reach the backend" and "the gateway crashed" must not look the
/// same in an incident.
///
/// `scheme` is the transport the client reached us over (`https` when TLS was negotiated, `http`
/// otherwise) and is what `X-Forwarded-Proto` and `Forwarded;proto=` must carry (PTN-07). The
/// HTTP *version* is a different fact and is carried separately in `X-Forwarded-Version`.
async fn proxy_request(
    parts: hyper::http::request::Parts,
    body: RequestBody,
    config: &Config,
    client: &str,
    by: &str,
    scheme: &str,
    classification: Option<classify::Classification>,
) -> Response<GatewayBody> {
    let request_id = new_id();
    let max_body_bytes = config.max_body_bytes;
    let backend = config.backend.as_str();
    // PTN-01: the request target the backend must see is path *and* query. `parts.uri.path()`
    // alone silently rewrites `GET /search.php?q=abc` into `GET /search.php`, which breaks every
    // query-driven route, callback and signed URL, and leaves the policy having judged a request
    // the backend never received.
    let target = request_target(&parts);

    // PTN-02: bound the body by the bytes actually read, not by the length the client declared.
    // The previous code asked the body's size hint, and if the hint was absent (chunked, HTTP/2
    // without a declared length) or under the cap it called `collect()`, which then read an
    // unbounded amount - and on any read error `unwrap_or_default()` turned a failed body into an
    // empty one that was still forwarded with the client's original Content-Length attached.
    // `Limited` counts real bytes and fails at the first one over the cap, so the gateway can say
    // 413 instead of inventing a request the client did not send.
    let (body_bytes, _reservation): (Bytes, Option<BufferReservation>) = match body {
        RequestBody::Collected(bytes, reservation) => (bytes, Some(reservation)),
        RequestBody::Incoming(body) => {
            let declared = body.size_hint().upper();
            if declared_body_over_limit(declared, max_body_bytes) {
                return gateway_status_response(
                    &parts.method,
                    &target,
                    parts.version,
                    &request_id,
                    StatusCode::PAYLOAD_TOO_LARGE,
                    "body_exceeds_max_body_bytes",
                );
            }
            // The sum matters as much as each term: reserve before reading, so concurrent bodies
            // cannot collectively cross the budget while every one of them looks acceptable.
            let reservation = match reserve_buffer(
                declared.unwrap_or(max_body_bytes as u64) as usize,
                MAX_BUFFERED_BYTES,
            ) {
                Some(reservation) => reservation,
                None => {
                    return gateway_status_response(
                        &parts.method,
                        &target,
                        parts.version,
                        &request_id,
                        StatusCode::SERVICE_UNAVAILABLE,
                        "buffer_budget_exhausted",
                    );
                }
            };
            match Limited::new(body, max_body_bytes).collect().await {
                Ok(collected) => (collected.to_bytes(), Some(reservation)),
                // The two ways `Limited::collect()` fails are distinguishable, and they mean
                // different things to the client: the cap was crossed (413) versus the stream
                // itself broke (400).
                Err(error) if error.downcast_ref::<LengthLimitError>().is_some() => {
                    return gateway_status_response(
                        &parts.method,
                        &target,
                        parts.version,
                        &request_id,
                        StatusCode::PAYLOAD_TOO_LARGE,
                        "body_exceeds_max_body_bytes",
                    );
                }
                Err(error) => {
                    return gateway_status_response(
                        &parts.method,
                        &target,
                        parts.version,
                        &request_id,
                        StatusCode::BAD_REQUEST,
                        &format!("body_read_failed: {error}"),
                    );
                }
            }
        }
    };

    // Build the upstream request: same method and target, filtered headers, plus the forwarding
    // headers the gateway owns.
    let client_protocol = if parts.version == Version::HTTP_2 {
        "h2".to_string()
    } else {
        version_label(parts.version)
    };
    // The upstream `Host` must be the authority the client used, which is what `ProxyPreserveHost
    // On` on the backend means. Over HTTP/1.1 that value is an ordinary header and is copied with
    // the rest; over HTTP/2 it lives in the `:authority` pseudo-header, which hyper exposes as
    // `uri.authority()` and deliberately does NOT put in `parts.headers`. Copying headers alone
    // therefore sends an h2-originated request upstream with no Host at all, and Apache answers
    // redirects with its own address instead of the client's. Measured before the fix: the h1 path
    // produced `Location: http://198.51.100.111:8443/googleapi/` while the h2 path produced
    // `Location: http://198.51.100.110:8088/googleapi/` for the same request.
    let upstream_host = request_authority(&parts);

    let mut builder = Request::builder().method(parts.method.clone()).uri(format!(
        "{}{}",
        backend.trim_end_matches('/'),
        target
    ));
    let forwarded_tokens = connection_tokens(&parts.headers);
    for (name, value) in parts.headers.iter() {
        if is_hop_byhop(name)
            || name == hyper::header::HOST
            || forwarded_tokens.iter().any(|token| token == name)
        {
            continue;
        }
        builder = builder.header(name.clone(), value.clone());
    }
    if let Some(host) = upstream_host {
        builder = builder.header(hyper::header::HOST, safe_header(&host));
    }
    builder = builder
        .header("x-request-id", safe_header(&request_id))
        .header("x-forwarded-for", safe_header(client))
        // PTN-07: `X-Forwarded-Proto` carries a *scheme*, and RFC 9110 §7.6.7 defines the
        // `Forwarded;proto=` parameter the same way. Sending `h2` or `HTTP/1.1` there is not a
        // style choice: a framework that trusts it cannot tell whether the client came in over TLS,
        // so it gets redirects, `Secure` cookie flags and canonical URLs wrong. The version is a
        // separate fact and stays observable in `X-Forwarded-Version`.
        .header("x-forwarded-proto", safe_header(scheme))
        .header("x-forwarded-version", safe_header(&client_protocol))
        .header(
            "forwarded",
            safe_header(&format!("for={client};by={by};proto={scheme}")),
        );

    let upstream = match builder.body(full_body(body_bytes)) {
        Ok(request) => request,
        Err(error) => {
            return gateway_status_response(
                &parts.method,
                &target,
                parts.version,
                &request_id,
                StatusCode::BAD_GATEWAY,
                &format!("upstream_request_build_failed: {error}"),
            )
        }
    };

    // PTN-08: bound the wait for the backend's response head. A backend that accepts the connection
    // and then goes silent used to pin this task and its pooled upstream connection indefinitely, and
    // the client kept waiting on a request the gateway had already decided to serve. `0` opts out.
    // The two failures mean different things and now answer differently: 502 "the backend refused",
    // 504 "the backend did not answer in time".
    let sent: Result<_, (StatusCode, String)> = if config.upstream_timeout_secs > 0 {
        match tokio::time::timeout(
            Duration::from_secs(config.upstream_timeout_secs),
            backend_client().request(upstream),
        )
        .await
        {
            Ok(Ok(response)) => Ok(response),
            Ok(Err(error)) => Err((
                StatusCode::BAD_GATEWAY,
                format!("backend_unreachable: {error}"),
            )),
            Err(_) => Err((
                StatusCode::GATEWAY_TIMEOUT,
                format!("upstream_timeout_after_{}s", config.upstream_timeout_secs),
            )),
        }
    } else {
        backend_client().request(upstream).await.map_err(|error| {
            (
                StatusCode::BAD_GATEWAY,
                format!("backend_unreachable: {error}"),
            )
        })
    };
    match sent {
        Ok(response) => {
            let (resp_parts, resp_body) = response.into_parts();
            // PTN-03: stream the backend's body instead of collecting it. The response type used to
            // be `Response<Full<Bytes>>`, which forced reading the whole body into memory before
            // answering: a 200 MB download cost the gateway 200 MB of RSS, and an SSE stream - a
            // body that by design never completes - never produced any response at all.
            let mut out = Response::builder().status(resp_parts.status);
            for (name, value) in resp_parts.headers.iter() {
                if is_hop_byhop(name) {
                    continue;
                }
                out = out.header(name.clone(), value.clone());
            }
            out = out.header("x-request-id", safe_header(&request_id));
            // Only a non-normal classification adds a header. A normal response from the gateway
            // stays byte-compatible with the backend it fronts, which is the same reasoning as
            // PT-12's opt-in marker in the responder.
            if let Some(classification) = classification {
                out = out.header(
                    "x-fleet-filter-class",
                    safe_header(&classification.header_value()),
                );
            }
            match out.body(streamed_body(resp_body)) {
                Ok(response) => response,
                Err(error) => gateway_status_response(
                    &parts.method,
                    &target,
                    parts.version,
                    &request_id,
                    StatusCode::BAD_GATEWAY,
                    &format!("upstream_response_invalid: {error}"),
                ),
            }
        }
        Err((status, reason)) => {
            // 502/504 with the reason: distinguishable from a gateway crash in both a capture and a
            // log, which is the difference between "backend down" and "gateway bug".
            let text = format!(
                "{PKG_NAME} {VERSION}\nrequest={} {} {}\nrequest_id={request_id}\nerror={reason}\n",
                parts.method.as_str(),
                target,
                version_label(parts.version)
            );
            Response::builder()
                .status(status)
                .header(hyper::header::SERVER, format!("{PKG_NAME}/{VERSION}"))
                .header(hyper::header::CONTENT_TYPE, "text/plain; charset=utf-8")
                .body(full_body(Bytes::from(text)))
                .expect("static response built from valid constants")
        }
    }
}

/// Thread-local-free request id helper: the counter lives in the connection scope.
fn new_id() -> String {
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    request_id(&COUNTER)
}

/// Live connection count per client address, with an RAII permit.
///
/// Counting is behind a `Mutex` rather than per-shard: the gateway holds at most
/// `max_connections` connections, so this map is small and uncontended compared with the I/O it
/// guards. The permit's `Drop` is what guarantees a count is released even if the connection task
/// panics - a leaked count would permanently shrink the per-source budget.
struct SourceCounts {
    inner: Mutex<HashMap<IpAddr, usize>>,
}

impl SourceCounts {
    /// Create an empty table.
    fn new() -> SourceCounts {
        SourceCounts {
            inner: Mutex::new(HashMap::new()),
        }
    }

    /// Reserve one slot for `ip` if it is under `limit`; `None` means the source is at capacity.
    fn try_acquire(self: &Arc<SourceCounts>, ip: IpAddr, limit: usize) -> Option<SourcePermit> {
        let mut table = self.inner.lock().ok()?;
        let entry = table.entry(ip).or_insert(0);
        if *entry >= limit {
            return None;
        }
        *entry += 1;
        Some(SourcePermit {
            ip,
            table: Arc::clone(self),
        })
    }

    /// Release one slot for `ip` (called from `SourcePermit::drop`).
    fn release(&self, ip: IpAddr) {
        if let Ok(mut table) = self.inner.lock() {
            if let Some(count) = table.get_mut(&ip) {
                *count = count.saturating_sub(1);
                if *count == 0 {
                    table.remove(&ip);
                }
            }
        }
    }
}

/// One reserved connection slot for one client address.
struct SourcePermit {
    ip: IpAddr,
    table: Arc<SourceCounts>,
}

impl Drop for SourcePermit {
    /// Return the slot when the connection ends, however it ends.
    fn drop(&mut self) {
        self.table.release(self.ip);
    }
}

/// PTN-08: in-flight request accounting per authority (`Host` on HTTP/1.1, `:authority` on HTTP/2).
///
/// `[posture] admission_cap_per_authority` was parsed into `Profile` but never read on the request
/// path, so a policy could declare a per-vhost admission limit that did nothing. Per-*source* limits
/// (`max_connections_per_source`) stop one client from monopolising the global pool; they do not stop
/// one *vhost* from being buried while its neighbours are idle, which is what an outburst on a single
/// site on a shared front end looks like. Both numbers now mean the same thing they name.
struct AuthorityCounts {
    inner: Mutex<HashMap<String, usize>>,
}

impl AuthorityCounts {
    /// Create an empty table.
    fn new() -> AuthorityCounts {
        AuthorityCounts {
            inner: Mutex::new(HashMap::new()),
        }
    }

    /// Reserve one in-flight slot for `authority` if it is under `limit`; `None` means it is at
    /// capacity and the request is refused without being worked.
    fn try_acquire(
        self: &Arc<AuthorityCounts>,
        authority: &str,
        limit: usize,
    ) -> Option<AuthorityPermit> {
        let mut table = self.inner.lock().ok()?;
        let entry = table.entry(authority.to_string()).or_insert(0);
        if *entry >= limit {
            return None;
        }
        *entry += 1;
        Some(AuthorityPermit {
            authority: authority.to_string(),
            table: Arc::clone(self),
        })
    }

    /// Release one in-flight slot for `authority` (called from `AuthorityPermit::drop`).
    fn release(&self, authority: &str) {
        if let Ok(mut table) = self.inner.lock() {
            if let Some(count) = table.get_mut(authority) {
                *count = count.saturating_sub(1);
                if *count == 0 {
                    table.remove(authority);
                }
            }
        }
    }

    /// Authorities currently holding at least one slot; 0 once every request has completed.
    ///
    /// Test-only: the request path never needs the count, but every assertion about "did the slot
    /// come back" is worthless without a way to observe the table.
    #[cfg(test)]
    fn tracked(&self) -> usize {
        self.inner.lock().map(|table| table.len()).unwrap_or(0)
    }
}

/// One reserved in-flight slot for one authority.
struct AuthorityPermit {
    authority: String,
    table: Arc<AuthorityCounts>,
}

impl Drop for AuthorityPermit {
    /// Return the slot when the request stops being served, however it ends.
    fn drop(&mut self) {
        self.table.release(&self.authority);
    }
}

/// The authority a request was addressed to: `Host` on HTTP/1.1, `:authority` on HTTP/2.
///
/// hyper exposes the HTTP/2 pseudo-header as `uri.authority()` and deliberately does not copy it into
/// `parts.headers`, while an HTTP/1.1 request carries it as an ordinary header - which is why the
/// proxy path already has to look in both places to set the upstream `Host`. Admission is per
/// authority, so the same two-place lookup decides which vhost a request counts against.
fn request_authority(parts: &hyper::http::request::Parts) -> Option<String> {
    parts
        .headers
        .get(hyper::header::HOST)
        .and_then(|value| value.to_str().ok())
        .map(str::to_string)
        .or_else(|| parts.uri.authority().map(|authority| authority.to_string()))
}

/// Print usage and exit; `--help` and a bad argument share this path so a mis-invoked service
/// start is self-explanatory in `journalctl`.
fn usage_and_exit(code: i32) -> ! {
    eprintln!(
        "usage: {PKG_NAME} [--bind ADDR:PORT] [--backend URL] [--max-connections N]
\x20      [--max-connections-per-source N]\n\
         \x20      [--max-body-bytes N] [--max-headers N]\n\
         \x20      [--tls-cert PATH --tls-key PATH] | --version | --version-json\n\
         \x20      [--map PATH --map-ttl S --map-memo-ttl S --map-max-age S --map-fallback allow|tarpit|reject]\n\
         \x20      [--spool DIR --spool-min-interval S --spool-max-entries N]\n\
         \x20      [--detect-prefix PREFIX ...] [--on-quarantined proxy|reject]\n\
         \x20      [--deception-server-banner BANNER]\n\
         \x20      [--policy PATH] [--show-policy | --show-policy-json]"
    );
    exit(code)
}

/// The swappable unit (Bundle S2): a validated configuration plus everything derived from it.
///
/// Everything a reload can change lives behind one `Arc`, so a swap is a single pointer store and a
/// request either sees the whole previous configuration or the whole new one. TLS material and the
/// connection semaphore are part of the unit because a new certificate is only usable once a new
/// acceptor exists, and a new `max_connections` is only meaningful once a new semaphore exists.
///
/// Two things still need a restart, and saying so is cheaper than pretending otherwise:
///   * `listener.bind` - the socket is already bound, and rebinding on reload would drop the
///     listening socket for connections already queued in the kernel backlog;
///   * per-source connection accounting - `SourceCounts` is deliberately outside the unit, so
///     connections accepted under the old configuration are still counted after a reload.
struct Runtime {
    /// The parsed flags, kept so a reload can rebuild the same configuration from a new bundle.
    args: Args,
    /// The resolved configuration (flags + bundle + defaults).
    config: Arc<Config>,
    /// TLS acceptor built from the configuration; `None` for a cleartext listener.
    acceptor: Option<Arc<tokio_rustls::TlsAcceptor>>,
    /// Digest of the certificate and key bytes this acceptor was built from. The bundle digest
    /// cannot see a renewed certificate, so reload compares this too.
    tls_fingerprint: Option<String>,
    /// Global connection cap for connections accepted under this configuration.
    permits: Arc<Semaphore>,
}

impl Runtime {
    /// Build a Runtime, validating TLS before returning so a bad bundle cannot replace a good one.
    ///
    /// `previous` is the running Runtime, used to preserve the classifier and spool instances when
    /// their settings are unchanged (see [`Config::build_with`]).
    fn build(args: &Args, previous: Option<&Runtime>) -> Result<Runtime, String> {
        let config = Config::build_with(args, previous.map(|p| p.config.as_ref()))?;
        let tls_fingerprint = config.tls.as_ref().and_then(tls_fingerprint);
        let acceptor = match &config.tls {
            Some(material) => Some(Arc::new(tokio_rustls::TlsAcceptor::from(Arc::new(
                build_server_config(material, config.policy.as_deref())?,
            )))),
            None => None,
        };
        Ok(Runtime {
            args: args.clone(),
            permits: Arc::new(Semaphore::new(config.max_connections)),
            acceptor,
            tls_fingerprint,
            config: Arc::new(config),
        })
    }

    /// The startup banner: what is listening, which policy is active, and what it does with
    /// quarantined clients.
    fn banner(&self) -> String {
        let mode = match &self.config.tls {
            Some(material) => format!("tls(cert={})", material.cert_path),
            None => "cleartext".to_string(),
        };
        // The policy line comes second because everything after it only means something next to
        // "which rules are live": classification and spool settings are part of that policy.
        format!(
            "{PKG_NAME} {VERSION} listening on {} [{}]\n{}\nclassify {}\nspool {}\npolicy on-quarantined={}",
            self.config.bind,
            mode,
            self.config.policy_line(),
            if self.config.detect_prefix.is_empty() && self.config.detect_shapes.is_empty() {
                "detection=none".to_string()
            } else {
                // Shapes are named rather than counted: an operator asking "is the protocol shape
                // loaded on this host" should be able to read it off the startup line.
                format!(
                    "detection={}{}{}",
                    self.config.detect_prefix.join(","),
                    if self.config.detect_body_markers.is_empty() {
                        String::new()
                    } else {
                        format!(
                            " body=[{}]",
                            self.config.detect_body_markers.join(",")
                        )
                    },
                    if self.config.detect_shapes.is_empty() {
                        String::new()
                    } else {
                        format!(
                            " shapes=[{}]",
                            self.config
                                .detect_shapes
                                .iter()
                                .map(|shape| shape.name.as_str())
                                .collect::<Vec<_>>()
                                .join(",")
                        )
                    }
                )
            },
            self.config.spool.status_line(),
            self.config.quarantined.label(),
        )
    }
}

/// What a SIGHUP should do, decided from what actually changed rather than assumed.
///
/// The bundle digest covers the policy file only; the certificate and key are named in it, not
/// carried in it. So a renewed certificate dropped in place left the bundle line identical, the
/// reload reported "unchanged", and the gateway kept serving the old certificate until someone
/// restarted it. A renewal that does not take effect is worse than no renewal procedure, because
/// the operator has a log line saying it worked.
#[derive(Debug, PartialEq)]
enum ReloadAction {
    Unchanged,
    Swap(&'static str),
}

fn reload_action(current: (&str, Option<&str>), next: (&str, Option<&str>)) -> ReloadAction {
    if current.0 == next.0 && current.1 == next.1 {
        return ReloadAction::Unchanged;
    }
    if current.0 != next.0 {
        return ReloadAction::Swap("policy");
    }
    ReloadAction::Swap("tls material")
}

/// Digest of the certificate and key bytes, so a renewal is visible to [`reload_action`].
///
/// Key bytes are hashed as well as the certificate: a key rotation without a certificate change is
/// unusual but legal, and a comparison that only noticed certificates would call that unchanged.
fn tls_fingerprint(material: &TlsMaterial) -> Option<String> {
    let cert = fs::read(&material.cert_path).ok()?;
    let key = fs::read(&material.key_path).ok()?;
    let mut context = ring::digest::Context::new(&ring::digest::SHA256);
    context.update(&cert);
    context.update(&key);
    Some(
        context
            .finish()
            .as_ref()
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect(),
    )
}

/// Re-read the installed bundle and swap it in, keeping the previous one on any failure (S2).
///
/// The candidate is fully built and validated (parsed, schema-checked, and its TLS material
/// loaded) before the swap, so a corrupt update cannot replace a working policy. The log line
/// names both versions on success and the surviving one on failure, which is what makes "did my
/// reload take effect?" answerable from the journal.
fn reload(slot: &Arc<Mutex<Arc<Runtime>>>) {
    let current = Arc::clone(&slot.lock().expect("runtime lock poisoned"));
    let current_line = current.config.policy_line();
    match Runtime::build(&current.args, Some(&current)) {
        Ok(next) => {
            let next_line = next.config.policy_line();
            match reload_action(
                (&current_line, current.tls_fingerprint.as_deref()),
                (&next_line, next.tls_fingerprint.as_deref()),
            ) {
                ReloadAction::Unchanged => {
                    println!("policy reload: unchanged ({next_line})");
                    return;
                }
                ReloadAction::Swap("tls material") => {
                    // The bundle is identical, so naming both lines would print the same string
                    // twice; what changed is the material, and the fingerprint prefix is what
                    // makes a renewal checkable from the journal.
                    println!(
                        "policy reload ok: {next_line} (tls material changed, now {})",
                        next.tls_fingerprint
                            .as_deref()
                            .map(|digest| &digest[..12])
                            .unwrap_or("none")
                    );
                }
                ReloadAction::Swap(_) => {
                    println!("policy reload ok: {current_line} -> {next_line}")
                }
            }
            *slot.lock().expect("runtime lock poisoned") = Arc::new(next);
        }
        Err(error) => eprintln!("policy reload rejected: {error} (keeping {current_line})"),
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let argv: Vec<String> = env::args().collect();
    if argv.iter().any(|a| a == "--help") {
        usage_and_exit(0);
    }
    if argv.iter().any(|a| a == "--version") {
        println!("{PKG_NAME} {VERSION}");
        return Ok(());
    }
    if argv.iter().any(|a| a == "--version-json") {
        println!("{{{}}}", Config::identity_json());
        return Ok(());
    }
    let args = match Args::parse(&argv) {
        Ok(parsed) => parsed,
        Err(error) => {
            eprintln!("error: {error}");
            usage_and_exit(2);
        }
    };

    // `--show-policy` answers S4's per-host question without starting a listener, so a fleet report
    // can collect installed policy versions over SSH whether or not the service is running here.
    if args.show_policy || args.show_policy_json {
        let config = args
            .build(None)
            .map_err(|e| -> Box<dyn std::error::Error> { e.into() })?;
        if args.show_policy_json {
            println!("{{{}}}", config.policy_json());
        } else {
            println!("{}", config.policy_line());
        }
        return Ok(());
    }

    // The first runtime is built BEFORE the socket is bound. Building it afterwards means a bad key
    // or a bad policy briefly binds the listener and then exits, which under Restart=on-failure
    // looks like a flapping service with a port that is intermittently open; building first means
    // "the listener exists" always implies "the configuration was usable".
    let first =
        Runtime::build(&args, None).map_err(|e| -> Box<dyn std::error::Error> { e.into() })?;
    println!("{}", first.banner());
    let bind = first.config.bind;
    let slot: Arc<Mutex<Arc<Runtime>>> = Arc::new(Mutex::new(Arc::new(first)));

    let listener = TcpListener::bind(bind).await?;
    let sources = Arc::new(SourceCounts::new());
    let in_flight = Arc::new(AtomicU64::new(0));
    let mut terminate = signal(SignalKind::terminate())?;
    let mut interrupt = signal(SignalKind::interrupt())?;
    let mut hangup = signal(SignalKind::hangup())?;

    loop {
        // The current runtime is re-read on every iteration, so a swap only affects connections
        // accepted after it; a connection already being served keeps the configuration it was
        // accepted with. That is the atomic-swap semantics S2 asks for, and it is why an in-flight
        // response is never served by a half-applied configuration.
        let runtime = Arc::clone(&slot.lock().expect("runtime lock poisoned"));
        let (stream, peer) = tokio::select! {
            result = listener.accept() => match result {
                Ok(pair) => pair,
                Err(error) => {
                    eprintln!("accept failed: {error}");
                    continue;
                }
            },
            _ = terminate.recv() => { println!("signal: SIGTERM"); break; }
            _ = interrupt.recv() => { println!("signal: SIGINT"); break; }
            _ = hangup.recv() => { reload(&slot); continue; }
        };

        // Bounded concurrency, twice over: the global cap protects the process, the per-source cap
        // stops one client from consuming it. Past either limit the socket is closed rather than
        // queued, so a flood cannot turn the gateway into an unbounded backlog.
        let Ok(permit) = runtime.permits.clone().try_acquire_owned() else {
            drop(stream);
            continue;
        };
        // A trusted proxy is one peer carrying every client, so the per-source cap would throttle
        // the whole site at `max_connections_per_source`. It is exempt; the global cap still holds.
        // `0` means "no per-source limit" in the policy documentation, and the guard in
        // `SourceCounts::try_acquire` compares against it directly - so an explicit 0 used to refuse
        // every connection while `--show-policy` and the reload line both reported success.
        let configured_cap = runtime.config.max_connections_per_source;
        let per_source_cap =
            if configured_cap == 0 || trusted_peer(peer.ip(), &runtime.config.trusted_proxies) {
                usize::MAX
            } else {
                configured_cap
            };
        let Some(source_permit) = sources.try_acquire(peer.ip(), per_source_cap) else {
            drop(stream);
            continue;
        };

        let config = Arc::clone(&runtime.config);
        let counter = Arc::clone(&in_flight);
        match runtime.acceptor.clone() {
            Some(tls_acceptor) => {
                tokio::spawn(async move {
                    counter.fetch_add(1, Ordering::Relaxed);
                    // A failed handshake is normal noise (bad SNI, protocol mismatch, a scanner
                    // probing with the wrong TLS version) and is logged, not treated as a fault.
                    // PTN-08: the handshake itself now has a deadline. hyper's accept future is
                    // unbounded, so a client that completes TCP and then stalls mid-handshake used to
                    // hold this task, the socket, and its connection permit for the life of the
                    // process - a slow-loris cost paid by the gateway, not the client.
                    let handshake =
                        accept_tls(&tls_acceptor, stream, config.tls_handshake_timeout_secs);
                    match handshake.await {
                        Ok(tls_stream) => {
                            // The negotiated version is what the posture profile's TLS floor is
                            // checked against; reporting it costs one field read and makes a
                            // "403 tls_below_floor" answer verifiable from the client side.
                            let negotiated = tls_stream
                                .get_ref()
                                .1
                                .protocol_version()
                                .and_then(policy::TlsFloor::from_rustls);
                            serve_connection(tls_stream, peer, config, negotiated).await;
                        }
                        Err(error) => eprintln!("handshake failed from {peer}: {error}"),
                    }
                    counter.fetch_sub(1, Ordering::Relaxed);
                    drop(source_permit);
                    drop(permit);
                });
            }
            None => {
                tokio::spawn(async move {
                    counter.fetch_add(1, Ordering::Relaxed);
                    serve_connection(stream, peer, config, None).await;
                    counter.fetch_sub(1, Ordering::Relaxed);
                    drop(source_permit);
                    drop(permit);
                });
            }
        }
    }

    // Let in-flight responses finish so a reload does not truncate a partly-written response.
    let mut waited = 0u64;
    while in_flight.load(Ordering::Relaxed) > 0 && waited < 5 {
        tokio::time::sleep(Duration::from_secs(1)).await;
        waited += 1;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    //! Unit tests for the pure helpers every response is built from: `request_target` (PTN-01, the
    //! query string), `declared_body_over_limit` (PTN-02, the declared-length half of the body
    //! bound) and `full_body` (PTN-03, the single response body type). The proxy path itself needs a
    //! live backend, which is what `tests/gateway/parity_matrix.sh` measures on a host; these cover
    //! the decisions that can be answered without one.

    use super::*;

    use super::{detection_target, match_detection};

    /// Regression for the bug measured on 2026-11-24: the matcher used `uri.path()`, so a prefix
    /// carrying a query never matched and the published WP2Shell spelling walked through.
    #[test]
    fn a_query_bearing_prefix_matches_the_request_target() {
        let uri: hyper::Uri = "/?rest_route=/batch/v1".parse().unwrap();
        let prefixes = vec!["/?rest_route=/batch/v1".to_string()];
        assert_eq!(
            match_detection(&prefixes, &uri).as_deref(),
            Some("prefix:/?rest_route=/batch/v1")
        );
        assert_eq!(detection_target(&uri), "/?rest_route=/batch/v1");
    }

    /// The other half: the query must not make a path prefix match something it should not, and a
    /// bare path prefix must still match a request that carries a query.
    #[test]
    fn a_path_prefix_still_matches_and_the_query_does_not_widen_it() {
        let prefixes = vec![
            "/h2probe-".to_string(),
            "/?rest_route=/batch/v1".to_string(),
        ];
        let with_query: hyper::Uri = "/h2probe-1234?x=1".parse().unwrap();
        assert_eq!(
            match_detection(&prefixes, &with_query).as_deref(),
            Some("prefix:/h2probe-")
        );
        let different: hyper::Uri = "/?rest_route=/wp/v2/posts".parse().unwrap();
        assert_eq!(match_detection(&prefixes, &different), None);
        let plain: hyper::Uri = "/index.html".parse().unwrap();
        assert_eq!(match_detection(&prefixes, &plain), None);
    }

    /// The protocol-class detection: a body-less h2 request that carries Content-Type and no
    /// Content-Length is the CVE-2026-119618 trigger shape, and no URI prefix can express it.
    #[test]
    fn a_bodyless_h2_request_with_content_type_matches_the_shape() {
        let shape = policy::Shape::parse(
            "CVE-2026-119618:bodyless_ct protocol=h2,h2c method=GET ct=present cl=absent,zero",
        )
        .expect("shape parses");
        let request = Request::builder()
            .method(Method::GET)
            .version(hyper::Version::HTTP_2)
            .uri("/")
            .header("content-type", "application/x-www-form-urlencoded")
            .body(())
            .unwrap();
        let (parts, _) = request.into_parts();
        assert_eq!(
            match_shape(std::slice::from_ref(&shape), &parts).as_deref(),
            Some("shape:CVE-2026-119618:bodyless_ct")
        );
    }

    /// The negative half matters as much: ordinary traffic must not satisfy the shape.
    #[test]
    fn the_bodyless_shape_does_not_fire_on_ordinary_traffic() {
        let shape = policy::Shape::parse(
            "CVE-2026-119618:bodyless_ct protocol=h2,h2c method=GET ct=present cl=absent,zero",
        )
        .expect("shape parses");

        let with_length = Request::builder()
            .method(Method::GET)
            .version(hyper::Version::HTTP_2)
            .uri("/")
            .header("content-type", "text/plain")
            .header("content-length", "5")
            .body(())
            .unwrap();
        let (parts, _) = with_length.into_parts();
        assert_eq!(
            match_shape(std::slice::from_ref(&shape), &parts),
            None,
            "a real body is not the shape"
        );

        let without_type = Request::builder()
            .method(Method::GET)
            .version(hyper::Version::HTTP_2)
            .uri("/")
            .body(())
            .unwrap();
        let (parts, _) = without_type.into_parts();
        assert_eq!(
            match_shape(std::slice::from_ref(&shape), &parts),
            None,
            "no Content-Type is not the shape"
        );

        let http1 = Request::builder()
            .method(Method::GET)
            .version(hyper::Version::HTTP_11)
            .uri("/")
            .header("content-type", "text/plain")
            .body(())
            .unwrap();
        let (parts, _) = http1.into_parts();
        assert_eq!(
            match_shape(&[shape], &parts),
            None,
            "HTTP/1.1 cannot reach mod_http2"
        );
    }

    /// A shape with no predicates would match every request; the parser refuses it.
    #[test]
    fn a_shape_with_no_predicates_is_refused() {
        assert!(policy::Shape::parse("CVE-2026-119618:everything").is_err());
        assert!(
            policy::Shape::parse("x method=GTE").is_err(),
            "a typo must not become a no-op"
        );
    }

    /// Apache decodes percent escapes case-insensitively, so `%2E` and `%2e` are the same request.
    /// Before this fold the store had to admit that the uppercase spelling walked past the gateway.
    #[test]
    fn an_uppercase_percent_escape_matches_the_lowercase_prefix() {
        let prefixes = vec!["/cgi-bin/.%2e".to_string()];
        for target in [
            "/cgi-bin/.%2E/.%2E/etc/passwd",
            "/cgi-bin/.%2e/.%2e/etc/passwd",
        ] {
            let uri: hyper::Uri = target.parse().unwrap();
            assert_eq!(
                match_detection(&prefixes, &uri).as_deref(),
                Some("prefix:/cgi-bin/.%2e"),
                "target {target} must match"
            );
        }
        // A path segment that merely looks similar must still miss.
        let plain: hyper::Uri = "/cgi-bin/.2e/etc/passwd".parse().unwrap();
        assert_eq!(match_detection(&prefixes, &plain), None);
    }

    /// Folding is case-insensitive for the path too, and it must not decode: the encoded form is the
    /// signal, so `.%2e` must survive as `.%2e` rather than becoming `/../`.
    #[test]
    fn folding_keeps_encodings_and_matches_case_insensitively() {
        assert_eq!(
            super::fold_for_matching("/CGI-BIN/.%2E/x"),
            "/cgi-bin/.%2e/x"
        );
        assert_eq!(super::fold_for_matching("/CGI-BIN/x"), "/cgi-bin/x");
        let prefixes = vec!["/cgi-bin/.%2e".to_string()];
        let uri: hyper::Uri = "/CGI-BIN/.%2E/%2E%2E/etc/passwd".parse().unwrap();
        assert_eq!(
            match_detection(&prefixes, &uri).as_deref(),
            Some("prefix:/cgi-bin/.%2e")
        );
    }

    #[test]
    fn a_renewed_certificate_is_not_reported_as_unchanged() {
        // The bundle digest is the same in every arm below: only the material differs, which is
        // exactly the renewal case that used to be swallowed.
        let line = "policy lab sha256=abc";
        assert_eq!(
            super::reload_action((line, Some("cert1")), (line, Some("cert1"))),
            super::ReloadAction::Unchanged
        );
        assert_eq!(
            super::reload_action((line, Some("cert1")), (line, Some("cert2"))),
            super::ReloadAction::Swap("tls material")
        );
        assert_eq!(
            super::reload_action(
                (line, Some("cert1")),
                ("policy lab sha256=def", Some("cert1"))
            ),
            super::ReloadAction::Swap("policy")
        );
        // Adding TLS to a cleartext listener is a change, not an unchanged line.
        assert_eq!(
            super::reload_action((line, None), (line, Some("cert2"))),
            super::ReloadAction::Swap("tls material")
        );
    }

    #[test]
    fn a_trusted_proxy_supplies_the_client_and_an_untrusted_one_does_not() {
        let trusted: Vec<policy::Cidr> = vec!["10.0.0.0/8".parse().unwrap()];
        let mut headers = hyper::HeaderMap::new();
        // A client can write anything on the left; the proxy appends what it saw on the right.
        headers.insert("x-forwarded-for", "1.2.3.4, 203.0.113.9".parse().unwrap());
        assert_eq!(
            effective_source("10.1.2.3".parse().unwrap(), &headers, &trusted),
            "203.0.113.9".parse::<IpAddr>().unwrap(),
            "the rightmost untrusted entry is the client"
        );
        assert_eq!(
            effective_source("198.51.100.7".parse().unwrap(), &headers, &trusted),
            "198.51.100.7".parse::<IpAddr>().unwrap(),
            "a peer outside the trusted set cannot name itself"
        );
        // Two proxies in a chain: both are skipped, the client is still found.
        headers.insert("x-forwarded-for", "203.0.113.9, 10.2.0.1".parse().unwrap());
        assert_eq!(
            effective_source("10.1.2.3".parse().unwrap(), &headers, &trusted),
            "203.0.113.9".parse::<IpAddr>().unwrap()
        );
        // A trusted peer with no header falls back to itself rather than to "unknown".
        assert_eq!(
            effective_source(
                "10.1.2.3".parse().unwrap(),
                &hyper::HeaderMap::new(),
                &trusted
            ),
            "10.1.2.3".parse::<IpAddr>().unwrap()
        );
    }

    #[test]
    fn a_second_forwarded_for_header_cannot_name_the_client() {
        // The load balancer appends to the last header. Reading only the first - which is what
        // `get()` does - hands a client that sends its own header the power to choose the address
        // the gateway judges, including a third party's.
        let trusted: Vec<policy::Cidr> = vec!["10.0.0.0/8".parse().unwrap()];
        let mut headers = hyper::HeaderMap::new();
        headers.append("x-forwarded-for", "203.0.113.66".parse().unwrap());
        headers.append("x-forwarded-for", "198.51.100.7".parse().unwrap());
        assert_eq!(
            effective_source("10.1.2.3".parse().unwrap(), &headers, &trusted),
            "198.51.100.7".parse::<IpAddr>().unwrap(),
            "the last header is the one the trusted proxy appended"
        );
    }

    #[test]
    fn the_buffer_budget_refuses_the_request_that_would_cross_it() {
        // The per-request cap bounded one body; nothing bounded their sum, and 512 connections x
        // 8 MiB against a 256 MiB unit is an OOM from one unauthenticated client.
        let budget = 1024;
        let first = reserve_buffer(700, budget).expect("first reservation fits");
        assert!(
            reserve_buffer(700, budget).is_none(),
            "second must not cross the budget"
        );
        drop(first);
        assert!(
            reserve_buffer(700, budget).is_some(),
            "released bytes are reusable"
        );
        assert!(
            reserve_buffer(2048, budget).is_none(),
            "a single oversized body is refused"
        );
    }

    fn parts_for(uri: &str) -> hyper::http::request::Parts {
        Request::builder()
            .method(Method::GET)
            .uri(uri)
            .body(())
            .expect("test uri parses")
            .into_parts()
            .0
    }

    #[test]
    fn the_query_string_survives_into_the_upstream_uri() {
        // PTN-01: this used to be forwarded as `/search.php`, dropping everything after `?`.
        assert_eq!(
            request_target(&parts_for("/search.php?q=abc&page=2")),
            "/search.php?q=abc&page=2"
        );
    }

    #[test]
    fn a_percent_encoded_target_is_forwarded_without_being_re_encoded() {
        assert_eq!(
            request_target(&parts_for("/a%20b?x=1%3F2&x=2")),
            "/a%20b?x=1%3F2&x=2"
        );
    }

    #[test]
    fn a_bare_path_and_an_empty_query_are_both_preserved() {
        assert_eq!(request_target(&parts_for("/ai.html")), "/ai.html");
        assert_eq!(request_target(&parts_for("/ai.html?")), "/ai.html?");
    }

    #[test]
    fn an_authority_only_uri_forwards_a_root_path() {
        // A CONNECT-style URI has an authority and no path; forwarding "" would produce a request
        // line with no target, so the helper answers "/" instead.
        assert_eq!(request_target(&parts_for("http://example.com")), "/");
    }

    #[test]
    fn a_declared_length_over_the_cap_is_refused_before_reading() {
        assert!(declared_body_over_limit(Some(101), 100));
        assert!(!declared_body_over_limit(Some(100), 100));
        assert!(!declared_body_over_limit(Some(0), 100));
        // `None` means "unknown", not "empty": the cap is then enforced by counting real bytes,
        // which is the half the old implementation never did.
        assert!(!declared_body_over_limit(None, 100));
    }

    /// The PHP2Shell marker sits mid-body, so the search must find an interior match; a
    /// sub-8-byte marker is refused at parse time because it would match ordinary traffic.
    #[test]
    fn body_markers_are_found_and_short_ones_are_refused() {
        assert!(super::contains_bytes(
            b"xxPHP_SESSION_UPLOAD_PROGRESSyy",
            b"PHP_SESSION_UPLOAD_PROGRESS"
        ));
        // A needle longer than the haystack cannot fit, and an empty needle would match every
        // body, so both directions are refusals.
        assert!(!super::contains_bytes(
            b"PHP_SESS",
            b"PHP_SESSION_UPLOAD_PROGRESS"
        ));
        assert!(!super::contains_bytes(b"PHP_SESSION_UPLOAD_PROGRESS", b""));

        // The rest of the bundle is minimal but valid, so the only thing that can fail is the
        // marker check itself: a 3-byte marker is refused at policy-parse time.
        let bundle = "[policy]\n\
            schema_version = 1\n\
            version = \"test\"\n\
            generated_at = \"2026-01-01T00:00:00Z\"\n\
            source_commit = \"0000000\"\n\
            mode = \"serve\"\n\
            \n\
            [listener]\n\
            bind = \"127.0.0.1:8443\"\n\
            alpn = [\"http/1.1\"]\n\
            \n\
            [limits]\n\
            max_connections = 16\n\
            max_connections_per_source = 4\n\
            max_body_bytes = 65536\n\
            max_headers = 64\n\
            \n\
            [routing]\n\
            default_backend = \"http://127.0.0.1:8080\"\n\
            \n\
            [quarantine]\n\
            map_ttl = 60\n\
            map_memo_ttl = 300\n\
            fallback = \"allow\"\n\
            on_quarantined = \"proxy\"\n\
            \n\
            [spool]\n\
            min_interval = 60\n\
            max_entries = 100\n\
            \n\
            [detection]\n\
            prefixes = []\n\
            signatures = []\n\
            body_markers = [\"abc\"]\n\
            \n\
            [posture]\n\
            active = \"standard\"\n\
            methods = [\"GET\"]\n\
            header_names = []\n\
            content_types = []\n\
            max_path_bytes = 4096\n\
            max_query_bytes = 4096\n\
            max_path_segments = 128\n\
            min_tls_version = \"1.2\"\n\
            admission_cap_per_authority = 0\n";
        let error = policy::Policy::parse(bundle)
            .expect_err("a 3-byte body marker is refused at parse time");
        assert!(
            error.contains("shorter than 8 bytes"),
            "the refusal names the rule, not a generic error: {error}"
        );

        // The same bundle with the real marker parses and carries it: the document is valid
        // apart from the marker, which is what makes the refusal above the marker's.
        let ok = policy::Policy::parse(
            &bundle.replace("[\"abc\"]", "[\"PHP_SESSION_UPLOAD_PROGRESS\"]"),
        )
        .expect("the same bundle with a real marker parses");
        assert_eq!(
            ok.detection.body_markers,
            vec!["PHP_SESSION_UPLOAD_PROGRESS"]
        );
    }

    #[test]
    fn connection_header_tokens_are_treated_as_hop_by_hop() {
        // PTN-16: `Connection: X-Api-Token` means X-Api-Token was for this hop only. A fixed
        // deny-list cannot know that name, so the token list has to come from the request.
        let mut headers = HeaderMap::new();
        headers.insert(
            "connection",
            HeaderValue::from_static("X-Api-Token, Keep-Alive"),
        );
        headers.insert("x-api-token", HeaderValue::from_static("secret"));
        let tokens = connection_tokens(&headers);
        assert!(tokens.contains(&HeaderName::from_static("x-api-token")));
        assert!(tokens.contains(&HeaderName::from_static("keep-alive")));
        assert_eq!(
            tokens.len(),
            2,
            "each comma-separated token is its own header name"
        );
    }

    #[test]
    fn an_unparsable_or_absent_connection_header_names_nothing() {
        assert!(connection_tokens(&HeaderMap::new()).is_empty());
        let mut headers = HeaderMap::new();
        // A token with a space inside it is not a header name; dropping it is the only safe read.
        headers.insert(
            "connection",
            HeaderValue::from_static("ok header, , X-Good"),
        );
        let tokens = connection_tokens(&headers);
        assert_eq!(tokens, vec![HeaderName::from_static("x-good")]);
    }

    /// PTN-08: the per-authority counter has to actually count, actually refuse past the cap, and
    /// actually give the slot back - a cap that leaks is worse than no cap, because it eventually
    /// refuses every request to a vhost whose connections ended abnormally.
    #[test]
    fn authority_permits_are_counted_refused_and_returned() {
        let counts = Arc::new(AuthorityCounts::new());
        let first = counts
            .try_acquire("lab-web01.lab", 2)
            .expect("the first request to an authority gets a slot");
        assert_eq!(counts.tracked(), 1);
        let second = counts
            .try_acquire("lab-web01.lab", 2)
            .expect("the second request fits the cap of 2");
        assert_eq!(counts.tracked(), 1, "two in-flight requests, one authority");
        assert!(
            counts.try_acquire("lab-web01.lab", 2).is_none(),
            "the third request to the same authority is over the cap"
        );
        // A different authority is not charged for this one's traffic - that is the whole point of
        // the key existing separately from max_connections_per_source.
        let other = counts
            .try_acquire("other.example.edu", 2)
            .expect("another vhost still has its own budget");
        assert_eq!(counts.tracked(), 2);

        drop(second);
        assert_eq!(
            counts.tracked(),
            2,
            "one slot freed, but the authority is still tracked"
        );
        assert!(
            counts.try_acquire("lab-web01.lab", 2).is_some_and(|slot| {
                // Hold it, otherwise the drop below empties the table before the assertion runs.
                let held = slot;
                // Still two authorities in the table: `tracked()` counts authorities, not slots,
                // and this one was already present through `first`.
                assert_eq!(counts.tracked(), 2);
                drop(held);
                true
            }),
            "a released slot is available again"
        );

        drop(first);
        drop(other);
        assert_eq!(
            counts.tracked(),
            0,
            "an authority with no in-flight requests leaves the table entirely - no unbounded growth"
        );
    }

    #[test]
    fn a_flag_only_runtime_resolves_the_ptn08_bounds_from_their_defaults() {
        // The policy layer default and the runtime default are one number, asserted the same way
        // PTN-13's default is pinned: a flag-only `Config::build_with` is what a host runs when it has
        // no bundle installed, and it must not silently run with unbounded waits.
        let args = Args {
            bind: Some("127.0.0.1:8443".to_string()),
            backend: Some("http://127.0.0.1:8080".to_string()),
            ..Args::default()
        };
        let config = Config::build_with(&args, None).expect("a flag-only configuration builds");
        assert_eq!(
            config.tls_handshake_timeout_secs,
            policy::DEFAULT_TLS_HANDSHAKE_TIMEOUT_SECS
        );
        assert_eq!(
            config.upstream_timeout_secs,
            policy::DEFAULT_UPSTREAM_TIMEOUT_SECS
        );
        assert_eq!(
            config.http2_max_concurrent_streams,
            policy::DEFAULT_HTTP2_MAX_CONCURRENT_STREAMS
        );

        let overridden = Args {
            tls_handshake_timeout: Some(3),
            upstream_timeout: Some(4),
            http2_max_concurrent_streams: Some(5),
            ..args
        };
        let config = Config::build_with(&overridden, None).expect("the flags build");
        assert_eq!(config.tls_handshake_timeout_secs, 3);
        assert_eq!(config.upstream_timeout_secs, 4);
        assert_eq!(config.http2_max_concurrent_streams, 5);
    }

    #[test]
    fn a_configuration_that_names_no_quarantine_mode_answers_inline() {
        // PTN-13: the built-in fallback used to be `proxy`, so a flag-only run - or a bundle that
        // omitted the field - forwarded the request that had just been classified to the real
        // backend. The safe answer is the default, and the risky one has to be chosen on purpose.
        let args = Args {
            bind: Some("127.0.0.1:8443".to_string()),
            backend: Some("http://127.0.0.1:8080".to_string()),
            ..Args::default()
        };
        let config = Config::build_with(&args, None).expect("a flag-only configuration builds");
        assert_eq!(config.quarantined, Quarantined::Inline);
        assert_eq!(config.quarantined.label(), "inline");
    }

    #[test]
    fn every_quarantine_action_stays_selectable_and_nonsense_is_refused() {
        // `proxy` remains legal: it is how the owner simulates "this exploit exists and we are not
        // blocking it yet". It is a chosen testing mode now, not the silent default.
        for raw in ["proxy", "reject", "inline"] {
            let args = Args {
                bind: Some("127.0.0.1:8443".to_string()),
                backend: Some("http://127.0.0.1:8080".to_string()),
                on_quarantined: Some(raw.to_string()),
                ..Args::default()
            };
            let config = Config::build_with(&args, None).expect("each action builds");
            assert_eq!(config.quarantined.label(), raw);
        }
        let bad = Args {
            bind: Some("127.0.0.1:8443".to_string()),
            backend: Some("http://127.0.0.1:8080".to_string()),
            on_quarantined: Some("shrink".to_string()),
            ..Args::default()
        };
        assert!(
            Config::build_with(&bad, None).is_err(),
            "an unrecognised action is refused rather than quietly falling back"
        );
    }

    #[tokio::test]
    async fn full_body_yields_exactly_the_bytes_it_was_given() {
        // The property that matters is not the type but the bytes: a response body built from
        // `Bytes` must deliver those bytes and nothing else, whether it answers a policy rejection
        // or a proxied response. `is_end_stream()` is deliberately not asserted - `MapErr` does not
        // forward it, so asserting it would test a combinator detail instead of our code.
        let body = full_body(Bytes::from_static(b"fleet-filter"));
        assert_eq!(body.size_hint().exact(), Some(12));
        let collected = body.collect().await.expect("body yields without error");
        assert_eq!(collected.to_bytes().as_ref(), b"fleet-filter");
    }
}
