//! Bundle S1/S2 - the policy bundle: schema, validation, identity, and reload semantics.
//!
//! A bundle is the unit that gets shipped to a host. It carries the listener, the limits, the
//! routing table, the quarantine settings, the detection set, and the active posture profile in
//! one file, so "what is this host enforcing" has exactly one answer: the file's `version` plus its
//! SHA-256. That pairing is what makes S4's question ("which hosts are on policy v37") answerable
//! without trusting a human inventory, and what makes S2's keep-last-known-good rule possible: a
//! candidate bundle that fails validation here is never installed, so a working policy cannot be
//! replaced by a broken one.
//!
//! Relationship to the rest of the project (ADR-0001 M3):
//!   * the file lives in `gateway/policies/*.toml` in the repo and `/etc/fleet-filter-gateway/policy.toml`
//!     on a host - the ADR's layout, one file per policy;
//!   * signatures are referenced by id (`CVE-2026-119618:probe_path`), never re-declared, because
//!     `controller/signatures/signatures.yaml` is the single classification vocabulary;
//!   * the quarantine settings point at the controller's rendered map and the gateway's own spool,
//!     which is the Bundle R contract, restated as data instead of flags.

pub mod evaluate;
pub mod toml;

use std::fs;
use std::net::{IpAddr, SocketAddr};
use std::path::Path;
use std::sync::Arc;

use crate::deception;
use ring::digest;

pub use evaluate::{Profile, Rejection};

/// The only schema version this binary understands.
pub const SCHEMA_VERSION: i64 = 1;

/// The header-read timeout a bundle gets when it does not state one.
///
/// Named rather than inline because hyper's own default is also 30 s and is documented as "do not
/// depend on that": naming it here means the policy layer and the binary cannot end up enforcing
/// different numbers for the same deployed bundle.
pub const DEFAULT_HEADER_READ_TIMEOUT_SECS: u64 = 30;

/// PTN-14: how many seconds a rendered map stays trustworthy for quarantine decisions.
///
/// The controller re-renders every 300 s, so 3600 s is twelve missed renders: long enough that one
/// slow or skipped cycle cannot lift a quarantine, short enough that a controller which died stops
/// holding addresses hostage forever. Named here so the policy layer and the classifier cannot end up
/// enforcing different numbers for the same deployed bundle; `0` disables the check.
pub const DEFAULT_MAP_MAX_AGE_SECS: u64 = 3600;

/// PTN-08: seconds a TLS handshake may take before the gateway drops the connection.
///
/// `header_read_timeout_secs` bounds reading HTTP/1.1 headers, but on a TLS listener the handshake
/// happens before any header exists, and hyper's accept future has no built-in deadline: a client that
/// completes TCP and then stalls mid-handshake holds a task, a socket, and a connection permit for as
/// long as the process lives. That is a slow-loris attack paid for by the gateway rather than the
/// client, and it is the one wait in the accept path that was still unbounded.
pub const DEFAULT_TLS_HANDSHAKE_TIMEOUT_SECS: u64 = 10;

/// PTN-08: seconds the gateway waits for the backend's response head before answering 504.
///
/// Without it, a backend that accepts the connection but never answers pins a gateway task and an
/// upstream connection for the whole lifetime of that hang, and the client waits forever on a request
/// the gateway already decided to serve.
pub const DEFAULT_UPSTREAM_TIMEOUT_SECS: u64 = 30;

/// PTN-08: concurrent HTTP/2 streams the gateway will open on one client connection (0 = hyper's
/// own default). A single h2 client can otherwise open streams without limit, and each one is work
/// the gateway proxies and, for a quarantined client, a drip it has to hold.
pub const DEFAULT_HTTP2_MAX_CONCURRENT_STREAMS: u64 = 100;

/// Tables a bundle may contain. Anything else is rejected: a misspelled table would otherwise
/// silently contribute nothing, which is the quietest possible way to deploy the wrong policy.
pub const KNOWN_TABLES: [&str; 9] = [
    "policy",
    "listener",
    "limits",
    "routing",
    "quarantine",
    "spool",
    "detection",
    "posture",
    "deception",
];

/// Whether the gateway is serving traffic (S5 kill switch, reloadable without a restart).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mode {
    /// Normal operation: classify, detect, proxy.
    Serve,
    /// Kill switch: answer every request locally, contact no backend, file no claim.
    Paused,
}

impl Mode {
    /// Parse `mode`; `None` for anything unrecognised so the caller can name the bad value.
    pub fn parse(value: &str) -> Option<Mode> {
        match value {
            "serve" => Some(Mode::Serve),
            "paused" => Some(Mode::Paused),
            _ => None,
        }
    }

    /// The label used in logs, responses, and `--show-policy` output.
    pub fn label(&self) -> &'static str {
        match self {
            Mode::Serve => "serve",
            Mode::Paused => "paused",
        }
    }
}

/// The lowest TLS version the gateway will accept (owned by the posture profile, S3).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TlsFloor {
    /// TLS 1.0.
    Tls10,
    /// TLS 1.1.
    Tls11,
    /// TLS 1.2.
    Tls12,
    /// TLS 1.3.
    Tls13,
}

/// The protocol-version sets rustls exposes, named so they can be handed out as `&'static`.
///
/// rustls 0.23 implements only TLS 1.2 and 1.3. These are `static` rather than inline array
/// literals because callers need a slice with a `'static` lifetime, and an inline literal in a
/// `match` arm is a temporary that dies at the end of the statement.
pub static TLS12_AND_13: [&rustls::SupportedProtocolVersion; 2] =
    [&rustls::version::TLS12, &rustls::version::TLS13];

/// TLS 1.3 only - the set a `1.3` floor permits.
pub static TLS13_ONLY: [&rustls::SupportedProtocolVersion; 1] = [&rustls::version::TLS13];

impl TlsFloor {
    /// Parse a `1.2`-style version; `None` for anything unrecognised.
    pub fn parse(value: &str) -> Option<TlsFloor> {
        match value {
            "1.0" => Some(TlsFloor::Tls10),
            "1.1" => Some(TlsFloor::Tls11),
            "1.2" => Some(TlsFloor::Tls12),
            "1.3" => Some(TlsFloor::Tls13),
            _ => None,
        }
    }

    /// Map a negotiated rustls protocol version onto a floor (used to apply the profile's TLS
    /// check to a live connection).
    pub fn from_rustls(version: rustls::ProtocolVersion) -> Option<TlsFloor> {
        // `rustls::ProtocolVersion` is the wire version; anything rustls cannot name (DTLS,
        // Unknown) has no floor to report and is treated as "not measured" rather than guessed.
        match version {
            rustls::ProtocolVersion::TLSv1_0 => Some(TlsFloor::Tls10),
            rustls::ProtocolVersion::TLSv1_1 => Some(TlsFloor::Tls11),
            rustls::ProtocolVersion::TLSv1_2 => Some(TlsFloor::Tls12),
            rustls::ProtocolVersion::TLSv1_3 => Some(TlsFloor::Tls13),
            _ => None,
        }
    }

    /// The label used in output.
    pub fn label(&self) -> &'static str {
        match self {
            TlsFloor::Tls10 => "1.0",
            TlsFloor::Tls11 => "1.1",
            TlsFloor::Tls12 => "1.2",
            TlsFloor::Tls13 => "1.3",
        }
    }

    /// The rustls protocol constant this maps to.
    ///
    /// rustls 0.23 only implements TLS 1.2 and 1.3, so a declared 1.0/1.1 floor is accepted by the
    /// schema and reported honestly as `1.2 (declared 1.0)` rather than silently pretending the
    /// older versions are offered.
    pub fn rustls_versions(&self) -> &'static [&'static rustls::SupportedProtocolVersion] {
        match self {
            TlsFloor::Tls13 => &TLS13_ONLY,
            _ => &TLS12_AND_13,
        }
    }
}

/// A network prefix a load balancer's address must fall inside before its forwarding header is
/// believed.
///
/// Written here rather than pulled from a crate because the matching rule is ten lines and the
/// parsing rule is the part that has to be right: a mistyped prefix that silently matched nothing
/// would leave the gateway trusting no proxy, which is the state that tarpits every client behind
/// one, and a prefix that matched everything would let a client name itself.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Cidr {
    net: IpAddr,
    bits: u8,
}

impl Cidr {
    /// Does `ip` fall inside this prefix? Address families never cross.
    pub fn contains(&self, ip: IpAddr) -> bool {
        match (self.net, ip) {
            (IpAddr::V4(net), IpAddr::V4(candidate)) if self.bits <= 32 => {
                let mask = if self.bits == 0 {
                    0
                } else {
                    u32::MAX << (32 - self.bits)
                };
                u32::from(net) & mask == u32::from(candidate) & mask
            }
            (IpAddr::V6(net), IpAddr::V6(candidate)) if self.bits <= 128 => {
                let mask = if self.bits == 0 {
                    0
                } else {
                    u128::MAX << (128 - self.bits)
                };
                u128::from(net) & mask == u128::from(candidate) & mask
            }
            _ => false,
        }
    }
}

impl std::str::FromStr for Cidr {
    type Err = String;

    /// Accepts `10.0.0.0/8`, `2001:db8::/32`, and a bare address (`10.1.2.3`, meaning `/32`).
    fn from_str(text: &str) -> Result<Cidr, String> {
        let (address, bits) = match text.split_once('/') {
            Some((address, bits)) => (address, Some(bits)),
            None => (text, None),
        };
        let net: IpAddr = address
            .parse()
            .map_err(|_| format!("`{text}` is not an address or address/prefix"))?;
        let width = match net {
            IpAddr::V4(_) => 32,
            IpAddr::V6(_) => 128,
        };
        let bits = match bits {
            None => width,
            Some(bits) => bits
                .parse::<u8>()
                .ok()
                .filter(|bits| *bits <= width)
                .ok_or_else(|| format!("`{text}` prefix length must be 0..={width}"))?,
        };
        Ok(Cidr { net, bits })
    }
}

/// What the gateway listens on and how it terminates TLS.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Listener {
    /// `address:port` the gateway binds.
    pub bind: String,
    /// PEM certificate chain; `None` means cleartext.
    pub tls_cert: Option<String>,
    /// PEM private key; required whenever `tls_cert` is present.
    pub tls_key: Option<String>,
    /// ALPN protocols advertised (validated against what the binary actually implements).
    pub alpn: Vec<String>,
    /// Prefixes whose `X-Forwarded-For` is believed. Empty means the gateway is the edge and the
    /// peer address is the client address.
    pub trusted_proxies: Vec<Cidr>,
}

/// Connection and request size limits (the O6 surface, expressed as data).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Limits {
    /// Global concurrent connection cap; 0 means unlimited (not recommended, but expressible).
    pub max_connections: usize,
    /// Per-client-address concurrent connection cap; 0 means unlimited.
    pub max_connections_per_source: usize,
    /// Request body byte cap.
    pub max_body_bytes: usize,
    /// Header field count cap (HTTP/1.1).
    pub max_headers: usize,
    /// Seconds allowed to read a full request header set; `0` disables the timeout.
    ///
    /// This is the control that makes a slow-loris style request cost the client something: without
    /// it, a connection that never finishes sending headers is held open indefinitely and the
    /// gateway has paid a socket for a request it cannot yet answer.
    ///
    /// Optional in the schema. Requiring it would invalidate every bundle written before the key
    /// existed, and an unparseable policy stops the gateway from starting - so a *required*
    /// additive key turns a feature addition into a restart-time outage on any host that has not
    /// been updated yet. Omitting it now yields the same 30 s hyper would have used anyway.
    ///
    /// `u64` seconds, matching the other duration-typed keys (`quarantine.map_ttl`); the
    /// `usize` fields in this table are counts, not durations.
    pub header_read_timeout_secs: u64,
    /// PTN-08: seconds allowed for a TLS handshake before the connection is dropped; `0` disables.
    pub tls_handshake_timeout_secs: u64,
    /// PTN-08: seconds to wait for the backend's response head before answering 504; `0` disables.
    pub upstream_timeout_secs: u64,
    /// PTN-08: concurrent HTTP/2 streams allowed per client connection; `0` keeps hyper's default.
    pub http2_max_concurrent_streams: u64,
}

/// Where requests go.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Routing {
    /// Default upstream URL (HTTP/1.1 upstream, always, per the milestone scope).
    pub default_backend: String,
    /// Whether to add `X-Forwarded-For` / `Forwarded` / `X-Request-Id` upstream.
    pub forward_headers: bool,
}

/// The Bundle R surface: which map the gateway reads and where it writes claims.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Quarantine {
    /// Path to the controller's rendered RewriteMap.
    pub map: Option<String>,
    /// Seconds between map re-reads.
    pub map_ttl: u64,
    /// Seconds a local detection stays memoised.
    pub map_memo_ttl: u64,
    /// PTN-14: seconds a rendered map stays trustworthy for quarantine decisions; `0` trusts any age.
    ///
    /// The map format carries one value per address and no per-entry expiry, so a map the controller
    /// stopped regenerating would otherwise hold addresses quarantined long after their leases lapsed.
    /// Optional in the policy file: existing bundles keep working and get `DEFAULT_MAP_MAX_AGE_SECS`.
    pub map_max_age: u64,
    /// What to do when the map cannot be read (`allow` / `tarpit` / `reject`).
    pub fallback: String,
    /// What to do with a request from a quarantined client (`proxy` / `reject`).
    pub on_quarantined: String,
}

/// The claim-spool settings.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SpoolSettings {
    /// Spool directory; `None` disables claim submission.
    pub dir: Option<String>,
    /// Minimum seconds between two claims for the same `(ip, claim_key)`.
    pub min_interval: u64,
    /// Maximum entries retained before the writer stops filing.
    pub max_entries: usize,
}

/// What the gateway treats as a detection, and which signature ids it claims to implement.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Detection {
    /// Path prefixes that count as a detection (the interim surface until Bundle S consumes
    /// rendered signature rules).
    pub prefixes: Vec<String>,
    /// Structured request shapes: the protocol-class variants a path prefix cannot express.
    ///
    /// Added 2026-11-24 after CVE-2026-119618 was measured passing through the gateway untouched.
    /// The store already said what the shape is (`protocol`, `method`, `content_type_present`,
    /// `content_length_in`) and Apache's own inline rules already enforced it, but the gateway could
    /// only match URI prefixes - so the one component that fronts the traffic could not act on the
    /// one vulnerability class that matters most. These are predicates over request properties the
    /// gateway already parses; no model, no body, no buffering.
    pub shapes: Vec<Shape>,
    /// Literal markers that identify a hostile request *body*, e.g. `PHP_SESSION_UPLOAD_PROGRESS`.
    ///
    /// Added 2026-11-24 for PHP2Shell: its trigger is a multipart field parsed before application
    /// code runs, so it is invisible to any URI or header predicate - and the gateway already holds
    /// the body in memory (bounded by `max_body_bytes`), so the check costs a byte search, not a new
    /// architecture. Measured: the published chain A carries the marker at offset 332 of a 514-byte
    /// body, and a 200 MB body-only OOM attempt is already refused at 8 MB before PHP sees it.
    pub body_markers: Vec<String>,
    /// Signature ids from `controller/signatures/signatures.yaml` this policy references.
    pub signatures: Vec<String>,
}

/// One structured shape, rendered from a store variant by `bin/render-gateway-detection.py`.
///
/// The wire form is one line per shape in a TOML string array, because the policy parser is a
/// minimal one and does not support arrays of tables:
///
///     shapes = [
///       "CVE-2026-119618:bodyless_ct protocol=h2,h2c method=GET ct=present cl=absent,zero",
///     ]
///
/// Every predicate present must hold; a shape with no predicates matches nothing, which is refused
/// at parse time rather than becoming a rule that silently fires on everything.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Shape {
    /// Claim key sent to the controller, `<signature>:<variant>`.
    pub name: String,
    /// Protocol labels this shape applies to (`h2`, `h2c`, `http/1.1`); empty means any.
    pub protocols: Vec<String>,
    /// Methods this shape applies to; empty means any.
    pub methods: Vec<String>,
    /// Whether `Content-Type` must be present (`Some(true)`), absent (`Some(false)`), or unchecked.
    pub content_type: Option<bool>,
    /// Content-Length states that qualify: `absent`, `zero`, `present`.
    pub content_length: Vec<String>,
    /// A header name prefix that must be present, for header-amplification shapes.
    pub header_prefix: Option<String>,
    /// Minimum number of request headers.
    pub min_headers: Option<usize>,
}

impl Shape {
    /// Parse one rendered shape line.
    ///
    /// Unknown keys are an error rather than ignored: a policy that says `method=GTE` must not
    /// deploy as a rule that matches nothing.
    pub fn parse(line: &str) -> Result<Shape, String> {
        let mut parts = line.split_whitespace();
        let name = parts
            .next()
            .ok_or_else(|| "[detection] `shapes` contains an empty entry".to_string())?
            .to_string();
        if name.is_empty() {
            return Err("[detection] `shapes` contains an empty entry".to_string());
        }
        let mut shape = Shape {
            name,
            protocols: Vec::new(),
            methods: Vec::new(),
            content_type: None,
            content_length: Vec::new(),
            header_prefix: None,
            min_headers: None,
        };
        let mut predicates = 0usize;
        for token in parts {
            let (key, value) = token
                .split_once('=')
                .ok_or_else(|| format!("[detection] shape {token:?} is not key=value"))?;
            match key {
                "protocol" => {
                    shape.protocols = split_list(value);
                    for label in &shape.protocols {
                        if !matches!(label.as_str(), "h2" | "h2c" | "http/1.1" | "http/1.0") {
                            return Err(format!(
                                "[detection] shape protocol={label:?} is not h2|h2c|http/1.1|http/1.0"
                            ));
                        }
                    }
                    predicates += 1;
                }
                "method" => {
                    shape.methods = split_list(value);
                    // A method nobody sends is a rule that matches nothing, and a rule that matches
                    // nothing looks exactly like a rule that is working. Refuse the typo.
                    for method in &shape.methods {
                        if !KNOWN_METHODS.contains(&method.as_str()) {
                            return Err(format!(
                                "[detection] shape method={method:?} is not a known HTTP method"
                            ));
                        }
                    }
                    predicates += 1;
                }
                "ct" => {
                    shape.content_type = match value {
                        "present" => Some(true),
                        "absent" => Some(false),
                        other => {
                            return Err(format!(
                                "[detection] shape ct={other:?} is not present|absent"
                            ))
                        }
                    };
                    predicates += 1;
                }
                "cl" => {
                    shape.content_length = split_list(value);
                    for state in &shape.content_length {
                        if !matches!(state.as_str(), "absent" | "zero" | "present") {
                            return Err(format!(
                                "[detection] shape cl={state:?} is not absent|zero|present"
                            ));
                        }
                    }
                    predicates += 1;
                }
                "header_prefix" => {
                    shape.header_prefix = Some(value.to_string());
                    predicates += 1;
                }
                "min_headers" => {
                    shape.min_headers = Some(value.parse::<usize>().map_err(|_| {
                        format!("[detection] shape min_headers={value:?} is not a number")
                    })?);
                    predicates += 1;
                }
                other => return Err(format!("[detection] shape has unknown predicate {other:?}")),
            }
        }
        if predicates == 0 {
            // A shape with no predicates is "match everything", which is a self-inflicted outage.
            return Err(format!(
                "[detection] shape {:?} has no predicates; it would match every request",
                shape.name
            ));
        }
        Ok(shape)
    }
}

/// Methods a shape may name. Deliberately a closed list: a typo must fail to parse rather than
/// deploy as a predicate no request can satisfy.
const KNOWN_METHODS: [&str; 10] = [
    "GET", "HEAD", "POST", "PUT", "DELETE", "OPTIONS", "CONNECT", "TRACE", "PATCH", "PRI",
];

/// Split a comma-separated predicate value, dropping empty entries.
fn split_list(value: &str) -> Vec<String> {
    value
        .split(',')
        .map(|item| item.trim().to_string())
        .filter(|item| !item.is_empty())
        .collect()
}

/// A complete policy bundle.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Policy {
    /// Schema version of the bundle format (must equal [`SCHEMA_VERSION`]).
    pub schema_version: i64,
    /// Operator-visible version string (e.g. `lab-web01-s1`). Reported by `--show-policy`.
    pub version: String,
    /// When the bundle was generated (ISO-8601 string; validated as non-empty, not as a date).
    pub generated_at: String,
    /// The git commit the bundle was rendered from.
    pub source_commit: String,
    /// Kill switch (S5).
    pub mode: Mode,
    /// Listener settings.
    pub listener: Listener,
    /// Limits.
    pub limits: Limits,
    /// Routing.
    pub routing: Routing,
    /// Quarantine integration.
    pub quarantine: Quarantine,
    /// Spool settings.
    pub spool: SpoolSettings,
    /// Detection surface.
    pub detection: Detection,
    /// The active posture profile (S3).
    pub profile: Profile,
    /// Inline deception settings (Bundle T1), present when `on_quarantined = inline`.
    pub deception: Option<deception::Settings>,
}

/// Compute the bundle's identity hash (SHA-256 over the exact file bytes).
///
/// The hash - not the version string - is what proves two hosts run the same policy, because a
/// version string can be edited without changing behaviour while the bytes cannot.
pub fn sha256_hex(text: &str) -> String {
    let digest = digest::digest(&digest::SHA256, text.as_bytes());
    digest
        .as_ref()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>()
}

impl Policy {
    /// Parse and schema-validate a bundle's text.
    pub fn parse(text: &str) -> Result<Policy, String> {
        let doc = toml::Document::parse(text)?;
        validate_tables(&doc)?;

        // [policy]
        let schema_version = doc.require_int("policy", "schema_version")?;
        if schema_version != SCHEMA_VERSION {
            return Err(format!(
                "[policy] schema_version {schema_version} is not supported (this binary reads {SCHEMA_VERSION})"
            ));
        }
        let version = doc.require_str("policy", "version")?;
        if version.trim().is_empty() {
            return Err("[policy] `version` must not be empty".to_string());
        }
        let generated_at = doc.require_str("policy", "generated_at")?;
        if generated_at.trim().is_empty() {
            return Err("[policy] `generated_at` must not be empty".to_string());
        }
        let source_commit = doc.require_str("policy", "source_commit")?;
        if source_commit.trim().is_empty() {
            return Err("[policy] `source_commit` must not be empty".to_string());
        }
        let mode = Mode::parse(&doc.require_str("policy", "mode")?)
            .ok_or_else(|| "[policy] `mode` must be `serve` or `paused`".to_string())?;

        // [listener]
        let bind = doc.require_str("listener", "bind")?;
        bind.parse::<SocketAddr>()
            .map_err(|e| format!("[listener] `bind` {bind}: {e}"))?;
        let tls_cert = doc.opt_str("listener", "tls_cert")?;
        let tls_key = doc.opt_str("listener", "tls_key")?;
        match (&tls_cert, &tls_key) {
            (Some(_), Some(_)) | (None, None) => {}
            (Some(_), None) => {
                return Err("[listener] `tls_cert` given without `tls_key`".to_string())
            }
            (None, Some(_)) => {
                return Err("[listener] `tls_key` given without `tls_cert`".to_string())
            }
        }
        let alpn = doc.require_strs("listener", "alpn")?;
        if alpn.is_empty() {
            return Err("[listener] `alpn` must list at least one protocol".to_string());
        }
        for protocol in &alpn {
            // The binary implements h2 and HTTP/1.1 over TLS, and HTTP/1.1 in cleartext. An
            // advertised protocol it cannot serve would be a lie on the wire.
            match (protocol.as_str(), &tls_cert) {
                ("h2", Some(_)) | ("http/1.1", _) => {}
                ("h2", None) => return Err(
                    "[listener] `alpn` lists h2 without TLS; h2 is only negotiated over TLS here"
                        .to_string(),
                ),
                (other, _) => {
                    return Err(format!(
                        "[listener] `alpn` lists unsupported protocol `{other}`"
                    ))
                }
            }
        }

        // A malformed prefix is a hard error: a trusted-proxy list that silently matches nothing
        // puts the gateway back in the state where one client's detection tarpits every client
        // behind the load balancer, and that is not a state to reach by typo.
        let mut trusted_proxies = Vec::new();
        for entry in doc
            .opt_strs("listener", "trusted_proxies")?
            .unwrap_or_default()
        {
            trusted_proxies.push(
                entry
                    .parse::<Cidr>()
                    .map_err(|e| format!("[listener] `trusted_proxies`: {e}"))?,
            );
        }

        // [limits]
        let limits = Limits {
            max_connections: positive_int(&doc, "limits", "max_connections")?,
            max_connections_per_source: non_negative_int(
                &doc,
                "limits",
                "max_connections_per_source",
            )?,
            max_body_bytes: positive_int(&doc, "limits", "max_body_bytes")?,
            max_headers: positive_int(&doc, "limits", "max_headers")?,
            header_read_timeout_secs: optional_non_negative_int(
                &doc,
                "limits",
                "header_read_timeout_secs",
                DEFAULT_HEADER_READ_TIMEOUT_SECS,
            )?,
            // PTN-08: every remaining wait in the request path, each optional so a bundle written
            // before the keys existed still starts (an unparseable policy is a failed start).
            tls_handshake_timeout_secs: optional_non_negative_int(
                &doc,
                "limits",
                "tls_handshake_timeout_secs",
                DEFAULT_TLS_HANDSHAKE_TIMEOUT_SECS,
            )?,
            upstream_timeout_secs: optional_non_negative_int(
                &doc,
                "limits",
                "upstream_timeout_secs",
                DEFAULT_UPSTREAM_TIMEOUT_SECS,
            )?,
            http2_max_concurrent_streams: optional_non_negative_int(
                &doc,
                "limits",
                "http2_max_concurrent_streams",
                DEFAULT_HTTP2_MAX_CONCURRENT_STREAMS,
            )?,
        };

        // [routing]
        let default_backend = doc.require_str("routing", "default_backend")?;
        let uri = hyper::Uri::try_from(default_backend.as_str())
            .map_err(|e| format!("[routing] `default_backend` {default_backend}: {e}"))?;
        // https is refused rather than accepted-and-broken: the client the gateway builds is an
        // HTTP connector, so a policy naming https would validate, log "reload ok", and then answer
        // 502 to every request. A parser that cannot see the failure should not approve the config.
        if uri.scheme_str() != Some("http") {
            return Err(format!(
                "[routing] `default_backend` {default_backend}: scheme must be http; the gateway \
                 has no upstream TLS connector"
            ));
        }
        let routing = Routing {
            forward_headers: doc.opt_bool("routing", "forward_headers")?.unwrap_or(true),
            default_backend,
        };

        // [quarantine]
        let fallback = doc.require_str("quarantine", "fallback")?;
        if !matches!(fallback.as_str(), "allow" | "tarpit" | "reject") {
            return Err(format!(
                "[quarantine] `fallback` {fallback}: expected allow, tarpit or reject"
            ));
        }
        let on_quarantined = doc.require_str("quarantine", "on_quarantined")?;
        if !matches!(on_quarantined.as_str(), "proxy" | "reject" | "inline") {
            return Err(format!(
                "[quarantine] `on_quarantined` {on_quarantined}: expected proxy, reject or inline"
            ));
        }
        let quarantine = Quarantine {
            map: doc.opt_str("quarantine", "map")?,
            map_ttl: positive_int(&doc, "quarantine", "map_ttl")? as u64,
            map_memo_ttl: positive_int(&doc, "quarantine", "map_memo_ttl")? as u64,
            map_max_age: optional_non_negative_int(
                &doc,
                "quarantine",
                "map_max_age",
                DEFAULT_MAP_MAX_AGE_SECS,
            )?,
            fallback,
            on_quarantined,
        };

        // [spool]
        let spool = SpoolSettings {
            dir: doc.opt_str("spool", "dir")?,
            min_interval: non_negative_int(&doc, "spool", "min_interval")? as u64,
            max_entries: positive_int(&doc, "spool", "max_entries")?,
        };

        // [detection]
        let prefixes = doc.require_strs("detection", "prefixes")?;
        for prefix in &prefixes {
            if prefix.is_empty() {
                return Err("[detection] `prefixes` contains an empty entry".to_string());
            }
        }
        let shapes = match doc.opt_strs("detection", "shapes")? {
            Some(lines) => lines
                .iter()
                .map(|line| Shape::parse(line))
                .collect::<Result<Vec<Shape>, String>>()?,
            None => Vec::new(),
        };
        let body_markers = doc
            .opt_strs("detection", "body_markers")?
            .unwrap_or_default();
        for marker in &body_markers {
            if marker.is_empty() {
                return Err("[detection] `body_markers` contains an empty entry".to_string());
            }
            if marker.len() < 8 {
                // A short literal matches ordinary traffic; the check exists to catch a name, not a
                // syllable.
                return Err(format!(
                    "[detection] body marker {marker:?} is shorter than 8 bytes and would match                      ordinary bodies"
                ));
            }
        }
        let signatures = doc.require_strs("detection", "signatures")?;
        for signature in &signatures {
            validate_signature_reference(signature)?;
        }
        let detection = Detection {
            prefixes,
            shapes,
            body_markers,
            signatures,
        };

        // [posture] - the active profile, inlined so the bundle is self-describing.
        let profile = Profile::from_document(&doc)?;

        // [deception] - required by `on_quarantined = inline`, optional otherwise.
        //
        // The requirement is deliberate. If `inline` silently fell back to built-in defaults, a
        // bundle that omitted the table (or misspelled a profile name) would still start, and the
        // only way to discover what a quarantined client is served would be to send a quarantined
        // client. T4's point is that the gateway must not invent a fourth quarantine policy, so the
        // answer has to be written down.
        let has_deception = doc.table_names().iter().any(|t| t == "deception");
        let deception = if has_deception {
            let mut settings = deception::Settings {
                detected_profile: deception::DEFAULT_DETECTED_PROFILE.to_string(),
                quarantined_profile: deception::DEFAULT_QUARANTINED_PROFILE.to_string(),
                max_concurrent_drips: deception::DEFAULT_MAX_CONCURRENT_DRIPS,
                max_drip_ms: deception::DEFAULT_MAX_DRIP_MS,
                chunk_size: deception::DEFAULT_CHUNK_SIZE,
                chunk_delay_ms: deception::DEFAULT_CHUNK_DELAY_MS,
                per_connection_max_bytes: deception::DEFAULT_PER_CONNECTION_MAX_BYTES,
                server_banner: deception::DEFAULT_SERVER_BANNER.to_string(),
            };
            if let Some(v) = doc.opt_str("deception", "detected_profile")? {
                settings.detected_profile = v;
            }
            if let Some(v) = doc.opt_str("deception", "quarantined_profile")? {
                settings.quarantined_profile = v;
            }
            settings.max_concurrent_drips =
                positive_int(&doc, "deception", "max_concurrent_drips")?;
            settings.max_drip_ms = positive_int(&doc, "deception", "max_drip_ms")? as u64;
            settings.per_connection_max_bytes =
                positive_int(&doc, "deception", "per_connection_max_bytes")?;
            // Gap 1 in the responder interface: the inline `Server` used to be hardcoded to the
            // package id, which told a client it was being served by the tarpit. Optional, so every
            // bundle written before the key keeps the previous banner.
            if let Some(v) = doc.opt_str("deception", "server_banner")? {
                settings.server_banner = v;
            }
            settings.validate()?;
            Some(settings)
        } else if quarantine.on_quarantined == "inline" {
            return Err("[quarantine] on_quarantined = inline requires a [deception] table;                         inline deception without named profiles would be a fourth undocumented policy"
                .to_string());
        } else {
            None
        };

        Ok(Policy {
            schema_version,
            version,
            generated_at,
            source_commit,
            mode,
            listener: Listener {
                bind,
                tls_cert,
                tls_key,
                alpn,
                trusted_proxies,
            },
            limits,
            routing,
            quarantine,
            spool,
            detection,
            profile,
            deception,
        })
    }

    /// Read a bundle from disk and return it with the hash of the bytes that were read.
    ///
    /// The hash is computed from the same read that produced the parse, so a file that changed
    /// between validation and install cannot be reported under a hash it no longer matches.
    pub fn load(path: &Path) -> Result<(Policy, String), String> {
        let text = fs::read_to_string(path).map_err(|e| format!("{}: {e}", path.display()))?;
        let policy = Policy::parse(&text)?;
        Ok((policy, sha256_hex(&text)))
    }

    /// One-line description for the startup banner, `--show-policy`, and reload logs.
    pub fn summary(&self) -> String {
        format!(
            "version={} mode={} posture={} bind={} backend={} tls={} alpn={} on_quarantined={} {}",
            self.version,
            self.mode.label(),
            self.profile.name,
            self.listener.bind,
            self.routing.default_backend,
            if self.listener.tls_cert.is_some() {
                "yes"
            } else {
                "no"
            },
            self.listener.alpn.join("+"),
            self.quarantine.on_quarantined,
            self.deception_summary(),
        )
    }

    /// The deception half of the summary: what a quarantined client is answered with, or `off`.
    fn deception_summary(&self) -> String {
        match &self.deception {
            Some(d) => format!(
                "deception=inline(detected={},quarantined={},drips={})",
                d.detected_profile, d.quarantined_profile, d.max_concurrent_drips
            ),
            None => "deception=off".to_string(),
        }
    }

    /// The `--show-policy-json` payload: identity plus the fields an operator audits.
    pub fn to_json(&self, sha256: &str) -> String {
        let mut fields: Vec<(String, String)> = Vec::new();
        fields.push(("schema_version".into(), self.schema_version.to_string()));
        fields.push(("version".into(), self.version.clone()));
        fields.push(("generated_at".into(), self.generated_at.clone()));
        fields.push(("source_commit".into(), self.source_commit.clone()));
        fields.push(("sha256".into(), sha256.to_string()));
        fields.push(("mode".into(), self.mode.label().to_string()));
        fields.push(("posture".into(), self.profile.name.clone()));
        fields.push(("bind".into(), self.listener.bind.clone()));
        fields.push(("backend".into(), self.routing.default_backend.clone()));
        fields.push(("alpn".into(), self.listener.alpn.join(",")));
        fields.push((
            "tls_floor".into(),
            self.profile.min_tls_version.label().to_string(),
        ));
        fields.push((
            "max_connections".into(),
            self.limits.max_connections.to_string(),
        ));
        fields.push((
            "max_connections_per_source".into(),
            self.limits.max_connections_per_source.to_string(),
        ));
        fields.push((
            "max_body_bytes".into(),
            self.limits.max_body_bytes.to_string(),
        ));
        fields.push(("max_headers".into(), self.limits.max_headers.to_string()));
        fields.push((
            "header_read_timeout_secs".into(),
            self.limits.header_read_timeout_secs.to_string(),
        ));
        fields.push(("quarantine_map".into(), {
            self.quarantine.map.clone().unwrap_or_default()
        }));
        fields.push((
            "quarantine_fallback".into(),
            self.quarantine.fallback.clone(),
        ));
        fields.push((
            "on_quarantined".into(),
            self.quarantine.on_quarantined.clone(),
        ));
        if let Some(d) = &self.deception {
            fields.push(("deception_mode".into(), "inline".into()));
            fields.push((
                "deception_detected_profile".into(),
                d.detected_profile.clone(),
            ));
            fields.push((
                "deception_quarantined_profile".into(),
                d.quarantined_profile.clone(),
            ));
            fields.push((
                "deception_max_concurrent_drips".into(),
                d.max_concurrent_drips.to_string(),
            ));
            fields.push(("deception_max_drip_ms".into(), d.max_drip_ms.to_string()));
            fields.push((
                "deception_per_connection_max_bytes".into(),
                d.per_connection_max_bytes.to_string(),
            ));
        } else {
            fields.push(("deception_mode".into(), "off".into()));
        }
        fields.push((
            "spool_dir".into(),
            self.spool.dir.clone().unwrap_or_default(),
        ));
        fields.push((
            "spool_min_interval".into(),
            self.spool.min_interval.to_string(),
        ));
        fields.push((
            "spool_max_entries".into(),
            self.spool.max_entries.to_string(),
        ));
        fields.push(("detect_prefixes".into(), self.detection.prefixes.join(",")));
        fields.push(("signatures".into(), self.detection.signatures.join(",")));
        fields.push(("methods".into(), self.profile.methods.join(",")));
        fields.push(("header_names".into(), self.profile.header_names.join(",")));
        fields.push(("content_types".into(), self.profile.content_types.join(",")));
        fields.push((
            "max_path_bytes".into(),
            self.profile.max_path_bytes.to_string(),
        ));
        fields.push((
            "max_query_bytes".into(),
            self.profile.max_query_bytes.to_string(),
        ));
        fields.push((
            "max_path_segments".into(),
            self.profile.max_path_segments.to_string(),
        ));
        fields
            .into_iter()
            .map(|(k, v)| format!("\"{}\":\"{}\"", k, json_escape(&v)))
            .collect::<Vec<String>>()
            .join(",")
    }
}

/// Reject tables the schema does not define (a typo must not silently change the policy).
fn validate_tables(doc: &toml::Document) -> Result<(), String> {
    for name in doc.table_names() {
        // `[posture.profile.<name>]` style sub-tables are not part of the schema; the active
        // profile is inlined under [posture], so any sub-table is a leftover from an older layout.
        if !KNOWN_TABLES.contains(&name.as_str()) {
            return Err(format!("unknown table `[{name}]` in policy bundle"));
        }
    }
    Ok(())
}

/// A required int that must be > 0.
fn positive_int(doc: &toml::Document, table: &str, key: &str) -> Result<usize, String> {
    let raw = doc.require_int(table, key)?;
    if raw <= 0 {
        return Err(format!(
            "[{table}] `{key}` must be greater than 0 (got {raw})"
        ));
    }
    usize::try_from(raw).map_err(|e| format!("[{table}] `{key}`: {e}"))
}

/// A required int that may be 0 (0 meaning "no limit" where the schema allows it).
fn non_negative_int(doc: &toml::Document, table: &str, key: &str) -> Result<usize, String> {
    let raw = doc.require_int(table, key)?;
    if raw < 0 {
        return Err(format!(
            "[{table}] `{key}` must be 0 or greater (got {raw})"
        ));
    }
    usize::try_from(raw).map_err(|e| format!("[{table}] `{key}`: {e}"))
}

/// An int a bundle may omit, falling back to `default`; still rejects a negative value.
///
/// Exists for keys added after schema 1 shipped. `require_int` on a new key rejects every older
/// bundle, and because an unparseable policy prevents startup, that converts an additive change
/// into an outage on any host whose bundle has not been refreshed in the same deploy.
fn optional_non_negative_int(
    doc: &toml::Document,
    table: &str,
    key: &str,
    default: u64,
) -> Result<u64, String> {
    match doc.opt_int(table, key)? {
        None => Ok(default),
        Some(raw) if raw < 0 => Err(format!(
            "[{table}] `{key}` must be 0 or greater (got {raw})"
        )),
        Some(raw) => u64::try_from(raw).map_err(|e| format!("[{table}] `{key}`: {e}")),
    }
}

/// A signature reference must look like `<id>:<variant>` or a bare id, matching the vocabulary in
/// `controller/signatures/signatures.yaml` (ADR-0001 M3 forbids a policy re-declaring a regex).
fn validate_signature_reference(reference: &str) -> Result<(), String> {
    let ok = reference
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-' | b':'));
    if !ok || reference.is_empty() {
        return Err(format!(
            "[detection] invalid signature reference `{reference}` (expected `ID` or `ID:variant`)"
        ));
    }
    if reference.split(':').count() > 2 {
        return Err(format!(
            "[detection] invalid signature reference `{reference}` (expected `ID` or `ID:variant`)"
        ));
    }
    Ok(())
}

/// Minimal JSON string escaping for the hand-rolled JSON emitters in this crate.
fn json_escape(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for ch in value.chars() {
        match ch {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out
}

/// An installed-policy slot: the active bundle plus the bytes it was loaded from.
///
/// The slot exists so a reload can be atomic from a reader's point of view: a request either sees
/// the whole previous bundle or the whole new one, never a half-applied mix. That is what S2 asks
/// for, and it is why the reload path builds and validates a complete candidate before swapping.
#[derive(Debug, Clone)]
pub struct Slot {
    /// The active bundle.
    pub policy: Arc<Policy>,
    /// SHA-256 of the file the bundle was loaded from.
    pub sha256: String,
    /// Where the bundle is installed (used by reload to re-read the same file).
    pub path: String,
}

impl Slot {
    /// Load a bundle from `path` into a slot.
    pub fn load(path: &str) -> Result<Slot, String> {
        let (policy, sha256) = Policy::load(Path::new(path))?;
        Ok(Slot {
            policy: Arc::new(policy),
            sha256,
            path: path.to_string(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A complete, valid bundle used by most tests - one place, so a schema change shows up as
    /// failing tests rather than as a fixture that quietly stopped exercising the schema.
    pub fn sample() -> String {
        String::from(
            "[policy]\n\
             schema_version = 1\n\
             version = \"lab-web01-s1\"\n\
             generated_at = \"2026-11-14T18:40:00Z\"\n\
             source_commit = \"8bccbac\"\n\
             mode = \"serve\"\n\
             \n\
             [listener]\n\
             bind = \"198.51.100.111:8443\"\n\
             tls_cert = \"/etc/fleet-filter-gateway/tls/lab-web01.crt\"\n\
             tls_key = \"/etc/fleet-filter-gateway/tls/lab-web01.key\"\n\
             alpn = [\"h2\", \"http/1.1\"]\n\
             \n\
             [limits]\n\
             max_connections = 512\n\
             max_connections_per_source = 16\n\
             max_body_bytes = 8388608\n\
             max_headers = 100\n\
             header_read_timeout_secs = 30\n\
             \n\
             [routing]\n\
             default_backend = \"http://198.51.100.110:8088\"\n\
             forward_headers = true\n\
             \n\
             [quarantine]\n\
             map = \"/etc/httpd/tarpit-ips.map\"\n\
             map_ttl = 60\n\
             map_memo_ttl = 300\n\
             fallback = \"allow\"\n\
             on_quarantined = \"proxy\"\n\
             \n\
             [spool]\n\
             dir = \"/var/lib/fleet-filter-gateway/spool\"\n\
             min_interval = 300\n\
             max_entries = 10000\n\
             \n\
             [detection]\n\
             prefixes = [\"/h2probe-\"]\n\
             signatures = [\"CVE-2026-119618:probe_path\"]\n\
             \n\
             [posture]\n\
             active = \"standard\"\n\
             methods = [\"GET\", \"HEAD\", \"POST\", \"PUT\", \"DELETE\", \"OPTIONS\", \"PATCH\"]\n\
             header_names = []\n\
             content_types = []\n\
             max_path_bytes = 4096\n\
             max_query_bytes = 4096\n\
             max_path_segments = 128\n\
             min_tls_version = \"1.2\"\n\
             admission_cap_per_authority = 0\n\
             \n\
             [deception]\n\
             detected_profile = \"exploit-probe\"\n\
             quarantined_profile = \"generic\"\n\
             max_concurrent_drips = 32\n\
             max_drip_ms = 8000\n\
             per_connection_max_bytes = 65536\n",
        )
    }

    /// Bundle T1/T4: the `[deception]` table is parsed, validated, and reported.
    #[test]
    fn deception_settings_are_parsed_and_reported() {
        let policy = Policy::parse(&sample()).expect("sample parses");
        let deception = policy.deception.clone().expect("[deception] present");
        assert_eq!(deception.detected_profile, "exploit-probe");
        assert_eq!(deception.quarantined_profile, "generic");
        assert_eq!(deception.max_concurrent_drips, 32);
        assert_eq!(deception.max_drip_ms, 8000);
        assert_eq!(deception.per_connection_max_bytes, 65536);
        assert!(policy.summary().contains("deception=inline("));
        assert!(policy
            .to_json("00")
            .contains("\"deception_detected_profile\":\"exploit-probe\""));
    }

    /// Gap 1 in the responder interface: the inline `Server` header is now policy, not a constant.
    /// The key is optional so every bundle written before it keeps answering with the previous
    /// banner, and a value hyper cannot represent is refused at load rather than at request time.
    #[test]
    fn the_inline_server_banner_is_optional_configurable_and_validated() {
        let omitted = Policy::parse(&sample()).expect("sample parses");
        assert_eq!(
            omitted.deception.clone().unwrap().server_banner,
            deception::DEFAULT_SERVER_BANNER,
            "omitting the key must reproduce the banner the gateway has always sent"
        );

        let with_banner = Policy::parse(&sample().replace(
            "detected_profile = \"exploit-probe\"",
            "detected_profile = \"exploit-probe\"\nserver_banner = \"Apache/2.4.37 (Oracle Linux Server)\"",
        ))
        .expect("a bundle naming a banner parses");
        assert_eq!(
            with_banner.deception.unwrap().server_banner,
            "Apache/2.4.37 (Oracle Linux Server)"
        );

        // A newline in the value is header injection, not a typo: it would let the policy author add
        // arbitrary headers, or split the response, from a field meant to hold one token.
        assert!(
            Policy::parse(&sample().replace(
                "detected_profile = \"exploit-probe\"",
                "detected_profile = \"exploit-probe\"\nserver_banner = \"Apache\\nX-Injected: yes\""
            ))
            .is_err(),
            "a banner containing a control character must not load"
        );
    }

    /// A profile name that does not exist must fail at load, not on the first quarantined request.
    #[test]
    fn an_unknown_deception_profile_is_rejected() {
        let text = sample().replace(
            "detected_profile = \"exploit-probe\"",
            "detected_profile = \"exploit-prob\"",
        );
        let error = match Policy::parse(&text) {
            Ok(_) => panic!("a misspelled profile must not load"),
            Err(e) => e,
        };
        assert!(
            error.contains("detected_profile") && error.contains("no such profile"),
            "{error}"
        );
    }

    /// `on_quarantined = inline` without a `[deception]` table would leave the answer to a
    /// quarantined client undefined; the schema refuses it instead of inventing a default.
    #[test]
    fn inline_quarantine_requires_a_deception_table() {
        // [deception] is the last table in the fixture, so dropping it is a split, not a
        // whitespace-sensitive replace that would silently stop matching if the fixture is reformatted.
        let without = sample().split("\n[deception]").next().unwrap().to_string();
        assert!(!without.contains("[deception]"), "fixture layout changed");

        // proxy without the table is legal: deception only needs to be named when it is used.
        Policy::parse(&without).expect("proxy without [deception] is valid");

        let inline = without.replace("on_quarantined = \"proxy\"", "on_quarantined = \"inline\"");
        let error = match Policy::parse(&inline) {
            Ok(_) => panic!("inline without [deception] must not load"),
            Err(e) => e,
        };
        assert!(error.contains("requires a [deception] table"), "{error}");
    }

    /// Assert a bundle text fails validation and return the message for the assertion.
    fn reject(text: &str) -> String {
        match Policy::parse(text) {
            Ok(_) => panic!("expected the bundle to be rejected:\n{text}"),
            Err(e) => e,
        }
    }

    #[test]
    fn accepts_a_complete_bundle() {
        let policy = Policy::parse(&sample()).expect("sample bundle must parse");
        assert_eq!(policy.version, "lab-web01-s1");
        assert_eq!(policy.mode, Mode::Serve);
        assert_eq!(policy.profile.name, "standard");
        assert_eq!(policy.listener.bind, "198.51.100.111:8443");
        assert_eq!(policy.routing.default_backend, "http://198.51.100.110:8088");
        assert_eq!(policy.detection.prefixes, vec!["/h2probe-".to_string()]);
        assert_eq!(
            policy.detection.signatures,
            vec!["CVE-2026-119618:probe_path".to_string()]
        );
        // The summary is what the banner and `--show-policy` print, so it must name the essentials.
        let summary = policy.summary();
        for fragment in [
            "version=lab-web01-s1",
            "mode=serve",
            "posture=standard",
            "bind=198.51.100.111:8443",
            "backend=http://198.51.100.110:8088",
        ] {
            assert!(
                summary.contains(fragment),
                "summary missing {fragment}: {summary}"
            );
        }
    }

    #[test]
    fn hash_is_stable_and_content_addressed() {
        let text = sample();
        assert_eq!(sha256_hex(&text), sha265_hex_reference(&text));
        // One byte of change must change the identity, or "same version, different bytes" is
        // undetectable.
        assert_ne!(sha256_hex(&text), sha256_hex(&format!("{text}\n")));
    }

    /// Independent SHA-256 for the test above, computed with the same ring call the code uses.
    fn sha265_hex_reference(text: &str) -> String {
        let d = digest::digest(&digest::SHA256, text.as_bytes());
        d.as_ref()
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<String>()
    }

    #[test]
    fn rejects_schema_and_identity_problems() {
        let mut text = sample();
        text = text.replace("schema_version = 1", "schema_version = 2");
        assert!(reject(&text).contains("schema_version 2"));

        text = sample().replace("version = \"lab-web01-s1\"", "version = \"\"");
        assert!(reject(&text).contains("`version` must not be empty"));

        text = sample().replace("mode = \"serve\"", "mode = \"turbo\"");
        assert!(reject(&text).contains("`mode` must be `serve` or `paused`"));

        text = sample().replace("mode = \"serve\"", "");
        assert!(reject(&text).contains("`mode`"));
    }

    #[test]
    fn rejects_listener_combinations_the_binary_cannot_serve() {
        let mut text = sample().replace(
            "bind = \"198.51.100.111:8443\"",
            "bind = \"not-an-address\"",
        );
        assert!(reject(&text).contains("`bind`"));

        // h2 without TLS cannot be negotiated here (ALPN only exists over TLS in this binary).
        text = sample().replace(
            "tls_cert = \"/etc/fleet-filter-gateway/tls/lab-web01.crt\"\n",
            "",
        );
        assert!(reject(&text).contains("tls_key` given without `tls_cert"));

        text = sample().replace("alpn = [\"h2\", \"http/1.1\"]", "alpn = [\"h3\"]");
        assert!(reject(&text).contains("unsupported protocol `h3`"));

        text = sample().replace("alpn = [\"h2\", \"http/1.1\"]", "alpn = []");
        assert!(reject(&text).contains("at least one protocol"));
    }

    #[test]
    fn rejects_bad_limits_enums_and_urls() {
        let mut text = sample().replace("max_connections = 512", "max_connections = 0");
        assert!(reject(&text).contains("max_connections` must be greater than 0"));

        text = sample().replace("fallback = \"allow\"", "fallback = \"maybe\"");
        assert!(reject(&text).contains("`fallback` maybe"));

        text = sample().replace("on_quarantined = \"proxy\"", "on_quarantined = \"queue\"");
        assert!(reject(&text).contains("`on_quarantined` queue"));

        text = sample().replace(
            "default_backend = \"http://198.51.100.110:8088\"",
            "default_backend = \"ftp://198.51.100.110:8088\"",
        );
        let https = reject(&text);
        assert!(https.contains("scheme must be http"), "{https}");
        assert!(https.contains("no upstream TLS connector"), "{https}");

        // 0 is legal here and means "no per-source cap" - the schema must not reject expressible
        // configurations the operator may legitimately want.
        Policy::parse(&sample().replace(
            "max_connections_per_source = 16",
            "max_connections_per_source = 0",
        ))
        .expect("0 per-source connections must be accepted as 'unlimited'");
    }

    /// The header-read timeout is the control that makes a half-sent request cost the sender
    /// something (O6), and it is only meaningful if the schema can express both states: a number,
    /// and "no timeout" (0). An omitted key must also resolve to a defined value, because the
    /// binary refuses to start on a policy it cannot fully resolve.
    #[test]
    fn header_read_timeout_is_configurable_and_defaults_when_omitted() {
        let with_value = Policy::parse(&sample().replace(
            "header_read_timeout_secs = 30",
            "header_read_timeout_secs = 45",
        ))
        .expect("an explicit header-read timeout must parse");
        assert_eq!(with_value.limits.header_read_timeout_secs, 45);

        let zero = Policy::parse(&sample().replace(
            "header_read_timeout_secs = 30",
            "header_read_timeout_secs = 0",
        ))
        .expect("0 must parse as 'timeout disabled', not as an invalid value");
        assert_eq!(zero.limits.header_read_timeout_secs, 0);

        let omitted = Policy::parse(&sample().replace("header_read_timeout_secs = 30\n", ""))
            .expect("a bundle predating the key must still parse");
        assert_eq!(
            omitted.limits.header_read_timeout_secs,
            DEFAULT_HEADER_READ_TIMEOUT_SECS
        );

        assert!(reject(&sample().replace(
            "header_read_timeout_secs = 30",
            "header_read_timeout_secs = -1"
        ))
        .contains("`header_read_timeout_secs` must be 0 or greater"));
    }

    /// PTN-14: the map's trust window has to be expressible, and a bundle written before the key
    /// existed must still parse - an additive schema change that forced a redeploy of every bundle
    /// would be its own outage. `0` is a real value here: "trust a map however old it is".
    #[test]
    fn map_max_age_is_configurable_and_defaults_when_omitted() {
        let with_value = Policy::parse(&sample().replace(
            "map_memo_ttl = 300\n",
            "map_memo_ttl = 300\nmap_max_age = 7200\n",
        ))
        .expect("an explicit map trust window must parse");
        assert_eq!(with_value.quarantine.map_max_age, 7200);

        let zero = Policy::parse(&sample().replace(
            "map_memo_ttl = 300\n",
            "map_memo_ttl = 300\nmap_max_age = 0\n",
        ))
        .expect("0 must parse as 'no age limit', not as an invalid value");
        assert_eq!(zero.quarantine.map_max_age, 0);

        let omitted =
            Policy::parse(&sample()).expect("a bundle predating the key must still parse");
        assert_eq!(
            omitted.quarantine.map_max_age, DEFAULT_MAP_MAX_AGE_SECS,
            "the policy layer and the classifier must enforce the same default"
        );

        assert!(
            reject(&sample().replace(
                "map_memo_ttl = 300\n",
                "map_memo_ttl = 300\nmap_max_age = -1\n"
            ))
            .contains("`map_max_age` must be 0 or greater"),
            "a negative trust window is refused rather than clamped"
        );
    }

    /// PTN-08: the three remaining bounds must be expressible, must default to something sane, and
    /// each must accept `0` as "no bound" rather than rejecting it - a bundle that wants the old
    /// unbounded behaviour should have to say so on purpose.
    #[test]
    fn request_path_timeouts_are_configurable_and_default_when_omitted() {
        let with_values = Policy::parse(&sample().replace(
            "header_read_timeout_secs = 30\n",
            "header_read_timeout_secs = 30\n\
             tls_handshake_timeout_secs = 7\n\
             upstream_timeout_secs = 12\n\
             http2_max_concurrent_streams = 250\n",
        ))
        .expect("the PTN-08 limits must parse");
        assert_eq!(with_values.limits.tls_handshake_timeout_secs, 7);
        assert_eq!(with_values.limits.upstream_timeout_secs, 12);
        assert_eq!(with_values.limits.http2_max_concurrent_streams, 250);

        let omitted =
            Policy::parse(&sample()).expect("a bundle predating the keys must still parse");
        assert_eq!(
            omitted.limits.tls_handshake_timeout_secs,
            DEFAULT_TLS_HANDSHAKE_TIMEOUT_SECS
        );
        assert_eq!(
            omitted.limits.upstream_timeout_secs,
            DEFAULT_UPSTREAM_TIMEOUT_SECS
        );
        assert_eq!(
            omitted.limits.http2_max_concurrent_streams,
            DEFAULT_HTTP2_MAX_CONCURRENT_STREAMS
        );

        let zeroed = Policy::parse(&sample().replace(
            "header_read_timeout_secs = 30\n",
            "header_read_timeout_secs = 30\n\
             tls_handshake_timeout_secs = 0\n\
             upstream_timeout_secs = 0\n\
             http2_max_concurrent_streams = 0\n",
        ))
        .expect("0 must parse as 'no bound' for each of them");
        assert_eq!(zeroed.limits.tls_handshake_timeout_secs, 0);
        assert_eq!(zeroed.limits.upstream_timeout_secs, 0);
        assert_eq!(zeroed.limits.http2_max_concurrent_streams, 0);

        assert!(
            reject(&sample().replace(
                "header_read_timeout_secs = 30\n",
                "header_read_timeout_secs = 30\ntls_handshake_timeout_secs = -1\n"
            ))
            .contains("`tls_handshake_timeout_secs` must be 0 or greater"),
            "a negative handshake budget is refused rather than clamped"
        );
    }

    #[test]
    fn rejects_unknown_tables_and_bad_signature_references() {
        let text = format!("{}[bogus]\nx = 1\n", sample());
        assert!(reject(&text).contains("unknown table `[bogus]`"));

        let text = sample().replace(
            "signatures = [\"CVE-2026-119618:probe_path\"]",
            "signatures = [\"CVE 2026/119618\"]",
        );
        assert!(reject(&text).contains("invalid signature reference"));

        // A bare id (no variant) is valid; three parts is not.
        Policy::parse(&sample().replace(
            "signatures = [\"CVE-2026-119618:probe_path\"]",
            "signatures = [\"CVE-2026-119618\"]",
        ))
        .expect("a bare signature id must be accepted");
        let text = sample().replace(
            "signatures = [\"CVE-2026-119618:probe_path\"]",
            "signatures = [\"a:b:c\"]",
        );
        assert!(reject(&text).contains("invalid signature reference"));
    }

    #[test]
    fn json_output_is_parseable_and_carries_the_identity() {
        let policy = Policy::parse(&sample()).expect("sample parses");
        let sha = sha256_hex(&sample());
        let json = format!("{{{}}}", policy.to_json(&sha));
        // Structural checks rather than a JSON parser dependency in the test path.
        assert!(json.starts_with('{') && json.ends_with('}'));
        assert!(json.contains(&format!("\"sha256\":\"{sha}\"")));
        assert!(json.contains("\"version\":\"lab-web01-s1\""));
        assert!(json.contains("\"posture\":\"standard\""));
        assert_eq!(
            json.matches('"').count() % 2,
            0,
            "unbalanced quotes in {json}"
        );
    }

    #[test]
    fn slot_records_the_hash_it_was_loaded_from() {
        let dir = std::env::temp_dir().join(format!("pt-policy-{}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("temp dir");
        let path = dir.join("policy.toml");
        std::fs::write(&path, sample()).expect("write bundle");
        let slot = Slot::load(path.to_str().unwrap()).expect("slot loads");
        assert_eq!(slot.sha256, sha256_hex(&sample()));
        assert_eq!(slot.path, path.to_str().unwrap());
        // A corrupt file must not produce a slot, so the caller keeps the previous one.
        std::fs::write(&path, "[policy]\n").expect("write corrupt bundle");
        assert!(Slot::load(path.to_str().unwrap())
            .err()
            .unwrap()
            .contains("schema_version"));
        std::fs::remove_dir_all(&dir).ok();
    }
}

#[cfg(test)]
mod cidr_tests {
    use super::Cidr;

    #[test]
    fn prefixes_match_inside_and_refuse_outside() {
        let net: Cidr = "10.0.0.0/8".parse().unwrap();
        assert!(net.contains("10.255.1.2".parse().unwrap()));
        assert!(!net.contains("11.0.0.1".parse().unwrap()));
        let host: Cidr = "192.0.2.7".parse().unwrap();
        assert!(host.contains("192.0.2.7".parse().unwrap()));
        assert!(!host.contains("192.0.2.8".parse().unwrap()));
        let v6: Cidr = "2001:db8::/32".parse().unwrap();
        assert!(v6.contains("2001:db8::1".parse().unwrap()));
        assert!(!v6.contains("2001:db9::1".parse().unwrap()));
        // Families never cross, and a bad prefix is an error rather than a /0.
        assert!(!net.contains("2001:db8::1".parse().unwrap()));
        assert!("10.0.0.0/33".parse::<Cidr>().is_err());
        assert!("not-an-address".parse::<Cidr>().is_err());
    }
}
