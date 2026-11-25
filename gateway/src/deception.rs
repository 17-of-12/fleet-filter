//! Inline deception responses (Bundle T1) and the budget that keeps them from endangering the
//! gateway.
//!
//! # Why this module exists
//!
//! The owner's hybrid decision was explicit: the gateway may serve *lightweight* deception itself,
//! but the full deception engine stays outside the process that protects legitimate traffic,
//! because a stateful responder that leaks memory or blocks a task takes the front end down with
//! it. So this module is deliberately not a deception engine. It answers a request from a
//! compile-time static profile after a bounded delay, and it refuses to answer at all once its
//! budget is gone.
//!
//! # The failure this prevents
//!
//! The naive version of "tarpit inside a proxy" is an unbounded `sleep` per request. With 512
//! connections and an 8-second drip, every quarantined client pins a task and a response buffer
//! for eight seconds; a scanner doing 50 connections a second turns a cheap trick into a
//! memory-and-task explosion that degrades service for the legitimate clients the gateway exists to
//! protect. `DripBudget` makes the cost explicit and capped: at most `max_concurrent_drips`
//! responses are ever delayed at once, and the surplus is refused immediately instead of queued or
//! forwarded. Refusal is the correct degradation, not forwarding: forwarding a request from a
//! quarantined client to the backend is what the quarantine exists to prevent (T5).
//!
//! # Relationship to the external responder
//!
//! `docs/spec/responder-interface.md` defines the contract the Python responder satisfies. That
//! contract has two halves and this module used to meet only one of them:
//!
//! * **Shape.** The responder drips 1-3 bytes at a time, 20-60 ms apart, capped at 5 s. The inline
//!   path used to `sleep()` the whole profile delay and then write the body in one go - a latency
//!   tarpit, not a drip, and something a scanner can tell apart from the responder in one request.
//!   Fixed 2026-11-24: the answer streams in `chunk_size` pieces with `chunk_delay_ms` between them,
//!   scaled down so the total stays inside the profile's budget.
//! * **Content.** Still divergent, and still a known gap: the bodies here are short and compile-time
//!   static, while the responder serves the reviewed bodies in `/opt/tarpit/responses/` (the Apache
//!   test page for 403, not this 150-byte one). Closing it needs the gateway's bodies generated from
//!   `tarpit/profiles/catalogue.yaml` at build time, the way `bin/render-gateway-detection.py`
//!   generates the detection table. Until then a client can tell the responders apart by body, and
//!   the interface doc says so instead of claiming otherwise.

use http_body_util::BodyExt;
use hyper::body::{Body, Bytes, Frame, SizeHint};
use hyper::{Response, StatusCode};
use std::convert::Infallible;
use std::future::Future;
use std::pin::Pin;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Duration;

/// A single inline answer. Every field is static so serving a profile allocates nothing beyond the
/// response itself, which is the property that makes inline deception cheap.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Profile {
    /// Name referenced by the policy (`detected_profile` / `quarantined_profile`).
    pub name: &'static str,
    /// Status the client receives.
    pub status: u16,
    /// `Content-Type` of the body.
    pub content_type: &'static str,
    /// The whole body. Static, so the size is known at compile time and checked at load time.
    pub body: &'static str,
    /// Requested delay before the answer is returned.
    pub delay_ms: u64,
    /// Why this profile exists, in one line - surfaced in `--show-policy` so the answer an
    /// adversary receives is documented in the same place as the rules that produced it.
    pub intent: &'static str,
}

/// The built-in profiles.
///
/// Three, not thirty: the gateway only needs to answer differently for the classes it can actually
/// distinguish (see `select`). A richer library belongs in the responder, which is the point of
/// T2's pluggable interface.
pub const PROFILES: &[Profile] = &[
    Profile {
        name: "generic",
        status: 403,
        content_type: "text/html; charset=UTF-8",
        body: "<!DOCTYPE html><html><head><title>403 Forbidden</title></head>\
               <body><h1>Forbidden</h1><p>You don't have permission to access this resource.</p>\
               </body></html>\n",
        delay_ms: 5000,
        intent: "default answer to a quarantined client; indistinguishable from the Apache 403",
    },
    Profile {
        name: "exploit-probe",
        status: 404,
        content_type: "text/html; charset=UTF-8",
        body: "<!DOCTYPE html><html><head><title>404 Not Found</title></head>\
               <body><h1>Not Found</h1><p>The requested URL was not found on this server.</p>\
               </body></html>\n",
        delay_ms: 3000,
        intent: "answer to a request matching an exploit signature: the probe 'fails' slowly \
                 instead of returning the real resource",
    },
    Profile {
        name: "api-probe",
        status: 200,
        content_type: "application/json",
        body: "{\"status\":\"ok\",\"service\":\"api\",\"version\":\"1.4.2\",\"request_id\":null}\n",
        delay_ms: 4000,
        intent: "answer to a probe against an API path: a real-looking envelope, so a scanner \
                 records the endpoint as alive and moves on",
    },
];

/// Default `detected_profile` when `[deception]` does not name one.
pub const DEFAULT_DETECTED_PROFILE: &str = "exploit-probe";
/// Default `quarantined_profile` when `[deception]` does not name one.
pub const DEFAULT_QUARANTINED_PROFILE: &str = "generic";
/// Default cap on simultaneously-delayed inline responses.
pub const DEFAULT_MAX_CONCURRENT_DRIPS: usize = 32;
/// Default bytes per body chunk: the catalogue's `stream_defaults.max_chunk_bytes`.
pub const DEFAULT_CHUNK_SIZE: usize = 3;
/// Default inter-chunk delay: the middle of the catalogue's 20-60 ms band.
pub const DEFAULT_CHUNK_DELAY_MS: u64 = 50;
/// Default ceiling applied to any profile's delay.
pub const DEFAULT_MAX_DRIP_MS: u64 = 8_000;
/// Default largest body the gateway will answer with, per connection.
pub const DEFAULT_PER_CONNECTION_MAX_BYTES: usize = 65_536;

/// The `Server` value the inline path sends when a policy does not name one.
///
/// Gap 1 in `docs/spec/responder-interface.md`: an inline answer that says
/// `fleet-filter-gateway/0.1.0` tells the adversary they are being served by the tarpit, which is
/// the one piece of feedback that teaches a scanner to stop probing. The banner is now configurable
/// rather than hardcoded, but the default keeps the existing text on purpose - changing what a live
/// host answers is a behaviour change, and the interface doc records that it deserves its own
/// measurement instead of riding in with a refactor.
pub const DEFAULT_SERVER_BANNER: &str =
    concat!(env!("CARGO_PKG_NAME"), " ", env!("CARGO_PKG_VERSION"));

/// Look up a profile by name.
pub fn lookup(name: &str) -> Option<&'static Profile> {
    PROFILES.iter().find(|p| p.name == name)
}

/// Which profile answers a request, given what the gateway knows about it.
///
/// T3's requirement is that an exploit probe and an ordinary quarantined request do not receive the
/// same answer. The gateway distinguishes exactly two classes at this point - a request that
/// triggered a detection (a signature or prefix match) and one that did not - so the selection is
/// two-valued and honest. An API path is recognised by extension because a JSON envelope on an HTML
/// path is a fingerprint, while on a `.json`/`/api/` path it is what the client expects.
pub fn select(
    configured_detected: &str,
    configured_quarantined: &str,
    detected: bool,
    path: &str,
) -> &'static Profile {
    if detected {
        if looks_like_api(path) {
            if let Some(api) = lookup("api-probe") {
                return api;
            }
        }
        return lookup(configured_detected).unwrap_or(&PROFILES[0]);
    }
    lookup(configured_quarantined).unwrap_or(&PROFILES[0])
}

/// True when the client would reasonably expect JSON, so an HTML answer would be the tell.
fn looks_like_api(path: &str) -> bool {
    let lower = path.to_ascii_lowercase();
    lower.starts_with("/api/")
        || lower.ends_with(".json")
        || lower.ends_with(".yaml")
        || lower.ends_with(".yml")
}

/// Inline deception settings from `[deception]`, validated by the policy loader.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Settings {
    /// Profile used when the request itself triggered a detection.
    pub detected_profile: String,
    /// Profile used for a quarantined client whose request matched nothing.
    pub quarantined_profile: String,
    /// Hard cap on simultaneously-delayed responses; the surplus is refused, never queued.
    pub max_concurrent_drips: usize,
    /// Ceiling applied to any profile's `delay_ms`, so a profile cannot stall a connection forever.
    pub max_drip_ms: u64,
    /// Bytes per body chunk. Both responders write small pieces with gaps; one write would make this
    /// a latency tarpit rather than a drip, which is a different observable product.
    pub chunk_size: usize,
    /// Inter-chunk delay ceiling in milliseconds. Scaled down when a budget needs it, never up.
    pub chunk_delay_ms: u64,
    /// Largest body this gateway will answer with; a bigger profile is a policy error at load time.
    pub per_connection_max_bytes: usize,
    /// The `Server` header the inline path sends (gap 1: it used to be hardcoded to the package id).
    pub server_banner: String,
}

impl Settings {
    /// The settings implied when `[deception]` is absent but `on_quarantined = inline` is set.
    pub fn default_inline() -> Settings {
        Settings {
            detected_profile: DEFAULT_DETECTED_PROFILE.to_string(),
            quarantined_profile: DEFAULT_QUARANTINED_PROFILE.to_string(),
            max_concurrent_drips: DEFAULT_MAX_CONCURRENT_DRIPS,
            max_drip_ms: DEFAULT_MAX_DRIP_MS,
            chunk_size: DEFAULT_CHUNK_SIZE,
            chunk_delay_ms: DEFAULT_CHUNK_DELAY_MS,
            per_connection_max_bytes: DEFAULT_PER_CONNECTION_MAX_BYTES,
            server_banner: DEFAULT_SERVER_BANNER.to_string(),
        }
    }

    /// Stable identity of these settings, used to decide whether an existing [`Budget`] can be
    /// reused across a policy reload.
    ///
    /// The banner is part of the identity on purpose: a reload that changed only the `Server` header
    /// would otherwise hit the reuse path and keep serving the old value from a cached `Budget`, so
    /// the change would read as applied in the policy file while the wire kept the previous answer.
    pub fn fingerprint(&self) -> String {
        format!(
            "{}/{}/{}/{}/{}/{}/{}#{}",
            self.detected_profile,
            self.quarantined_profile,
            self.max_concurrent_drips,
            self.max_drip_ms,
            self.chunk_size,
            self.chunk_delay_ms,
            self.per_connection_max_bytes,
            self.server_banner
        )
    }

    /// Validate the two named profiles exist and every referenced body fits the byte budget.
    ///
    /// A typo in a profile name used to be invisible until the first quarantined request arrived;
    /// here it is a load-time error, which is what makes an atomic reload meaningful.
    pub fn validate(&self) -> Result<(), String> {
        for (field, name) in [
            ("detected_profile", self.detected_profile.as_str()),
            ("quarantined_profile", self.quarantined_profile.as_str()),
        ] {
            let profile = lookup(name)
                .ok_or_else(|| format!("[deception] `{field}` = \"{name}\": no such profile"))?;
            if profile.body.len() > self.per_connection_max_bytes {
                return Err(format!(
                    "[deception] profile \"{name}\" is {} bytes, over per_connection_max_bytes {}",
                    profile.body.len(),
                    self.per_connection_max_bytes
                ));
            }
        }
        if self.max_concurrent_drips == 0 {
            return Err("[deception] `max_concurrent_drips` must be at least 1".to_string());
        }
        if self.chunk_size == 0 {
            return Err("[deception] `chunk_size` must be at least 1 byte".to_string());
        }
        if self.chunk_size > self.per_connection_max_bytes {
            return Err(format!(
                "[deception] `chunk_size` = {} is larger than `per_connection_max_bytes` = {}",
                self.chunk_size, self.per_connection_max_bytes
            ));
        }
        // A banner with a control character or a non-ASCII byte is not a legal header value, and
        // hyper would fail the response build at request time - the same class of defect as PTN-19,
        // where a status the code could not represent only surfaced when a client asked for it.
        if hyper::header::HeaderValue::from_str(&self.server_banner).is_err() {
            return Err(format!(
                "[deception] `server_banner` = {:?} is not a valid HTTP header value",
                self.server_banner
            ));
        }
        Ok(())
    }

    /// The budget a profile's response has to fit inside: its own delay, clamped to `max_drip_ms`.
    ///
    /// This is a ceiling on the whole response, not a pause before it. The field keeps its old name
    /// for policy and wire compatibility; the meaning is "how long the client is made to spend on
    /// this answer".
    pub fn delay_for(&self, profile: &Profile) -> Duration {
        Duration::from_millis(profile.delay_ms.min(self.max_drip_ms))
    }

    /// How many pieces the body is written in, and how long the gaps between them are.
    ///
    /// The gap is `chunk_delay_ms` unless that would break the profile's budget, in which case it is
    /// scaled down to fit: a 1 s ceiling on a 3 s drip must shorten the gaps, not the other way
    /// round. Zero gaps still means several pieces written back to back, which is what a
    /// zero-budget diagnostic run should look like.
    pub fn drip_plan(&self, profile: &Profile) -> (usize, Duration) {
        let chunk = self.chunk_size.max(1);
        let chunks = profile.body.len().div_ceil(chunk);
        let gaps = chunks.saturating_sub(1) as u64;
        if gaps == 0 {
            return (chunks, Duration::ZERO);
        }
        let budget_ms = self.delay_for(profile).as_millis() as u64;
        let gap_ms = self.chunk_delay_ms.min(budget_ms / gaps);
        (chunks, Duration::from_millis(gap_ms))
    }

    /// Time from first byte to last byte for this profile, under the current pacing.
    pub fn drip_total(&self, profile: &Profile) -> Duration {
        let (chunks, gap) = self.drip_plan(profile);
        gap * chunks.saturating_sub(1) as u32
    }

    /// The `X-Fleet-Filter-Deception` value: profile, planned response duration and piece count, so
    /// a captured response documents its own shape without the policy file. `drip_ms` is
    /// first-byte-to-last-byte, not a pause before the answer - the header said `delay_ms` while the
    /// gateway did no such thing, which is how the shape divergence stayed invisible.
    pub fn deception_header(&self, profile: &Profile) -> String {
        let (chunks, _) = self.drip_plan(profile);
        format!(
            "{};drip_ms={};chunks={}",
            profile.name,
            self.drip_total(profile).as_millis(),
            chunks
        )
    }
}

/// The live budget: the settings it enforces plus how many delayed responses are in flight.
///
/// Settings and counter live in one `Arc` because a reload must not reset the counter while the
/// settings are unchanged: dropping the `Arc` would forget in-flight drips and let a burst exceed
/// the cap the new bundle did not even change. Same reasoning as the classifier and spool
/// fingerprints in Bundle S.
#[derive(Debug)]
pub struct Budget {
    settings: Settings,
    in_use: AtomicUsize,
}

/// A held drip slot. Dropping it is what releases the slot, so an early connection close, a panic in
/// the serving task, or a client that stops reading cannot leak capacity.
pub struct Permit {
    budget: Arc<Budget>,
}

impl Drop for Permit {
    fn drop(&mut self) {
        self.budget.in_use.fetch_sub(1, Ordering::AcqRel);
    }
}

impl Permit {
    /// Build the response this permit was taken for, streaming its body in pieces.
    ///
    /// The permit moves into the body, so the slot is held for as long as the client is being
    /// served rather than released the instant the response object is built. That difference is
    /// invisible with a `Full` body (written immediately) and is the whole point once the body takes
    /// seconds: a permit released early would let a burst exceed `max_concurrent_drips` while every
    /// one of those responses is still in flight.
    ///
    /// The body is a slice of the static profile, so the per-chunk cost is one small allocation and
    /// no copy of the whole body - the property that keeps inline deception cheap next to proxying,
    /// which buffers the backend's response.
    pub fn response(self, profile: &'static Profile) -> Response<crate::GatewayBody> {
        // Copy what the headers need before `self` moves into the body: `settings()` borrows the
        // budget that the `Permit` inside the body owns, and the borrow cannot outlive the move.
        let (chunk_size, gap, banner) = {
            let settings = self.budget.settings();
            let (_, gap) = settings.drip_plan(profile);
            let banner = hyper::header::HeaderValue::from_str(&settings.server_banner)
                .unwrap_or_else(|_| hyper::header::HeaderValue::from_static(crate::PKG_NAME));
            (settings.chunk_size.max(1), gap, banner)
        };
        let body = DripBody {
            body: profile.body.as_bytes(),
            offset: 0,
            chunk_size,
            gap,
            sleep: None,
            _permit: self,
        };
        Response::builder()
            .status(StatusCode::from_u16(profile.status).unwrap_or(StatusCode::OK))
            // Gap 1: the banner comes from the policy, not from a constant. Falls back through
            // `Settings::default_inline()` semantics only via validation, so an empty or illegal
            // value can never reach here - `validate()` refused it at load time.
            .header(hyper::header::SERVER, banner)
            .header(hyper::header::CONTENT_TYPE, profile.content_type)
            .body(body.map_err(crate::BoxError::from).boxed())
            .expect("static response built from valid constants")
    }
}

/// A static deception body delivered in pieces with gaps between them.
///
/// This type exists because the inline path used to `sleep()` and then write the whole body, while
/// the Python responder drips. Two responders that answer the same client in two different shapes
/// make the deception fingerprintable in one request, which defeats the reason there is a single
/// fake application at all. The shape is now shared: the same chunk/queue discipline on both paths,
/// derived from the same catalogue defaults.
///
/// The clock is `tokio::time`, so a gap is cancelled with the task when a client disconnects - a
/// dropped connection refunds the permit through `Permit::drop` instead of leaving a sleeper behind.
pub struct DripBody {
    /// The profile's body, borrowed from the static table for the life of the response.
    body: &'static [u8],
    /// How many bytes have been written already.
    offset: usize,
    /// Bytes per frame; at least 1 (validated at load time).
    chunk_size: usize,
    /// The gap to leave before the *next* frame.
    gap: Duration,
    /// The pending gap, if one is in progress.
    sleep: Option<Pin<Box<tokio::time::Sleep>>>,
    /// Held from first byte to last. Dropping the body is what frees the drip slot, which is why
    /// this is named with the underscore: it is never read, only kept alive.
    _permit: Permit,
}

impl Body for DripBody {
    type Data = Bytes;
    type Error = Infallible;

    /// Write one piece per poll, sleeping between pieces but never before the first one.
    ///
    /// The first frame goes out immediately on purpose: a client measuring time-to-first-byte should
    /// see a server that started answering, and the cost imposed is the time it spends waiting for
    /// the rest. Sleeping before the first byte would make the drip a timeout, which is the failure
    /// this change removes.
    fn poll_frame(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
        let this = self.get_mut();
        if this.offset >= this.body.len() {
            return Poll::Ready(None);
        }
        if this.offset > 0 && !this.gap.is_zero() {
            if this.sleep.is_none() {
                this.sleep = Some(Box::pin(tokio::time::sleep(this.gap)));
            }
            if let Some(sleep) = this.sleep.as_mut() {
                if sleep.as_mut().poll(cx).is_pending() {
                    return Poll::Pending;
                }
            }
            this.sleep = None;
        }
        let end = (this.offset + this.chunk_size).min(this.body.len());
        let chunk = Bytes::copy_from_slice(&this.body[this.offset..end]);
        this.offset = end;
        Poll::Ready(Some(Ok(Frame::data(chunk))))
    }

    /// Declare the exact length, because the responder does.
    ///
    /// A known length means hyper sends `Content-Length` rather than chunked framing, so a client
    /// observes "N declared bytes arriving over T seconds" on both responders instead of a known
    /// length from one and chunked framing from the other.
    fn size_hint(&self) -> SizeHint {
        SizeHint::with_exact(self.body.len() as u64)
    }
}

impl Budget {
    /// Build a budget from validated settings.
    pub fn new(settings: &Settings) -> Budget {
        Budget {
            settings: settings.clone(),
            in_use: AtomicUsize::new(0),
        }
    }

    /// The settings this budget enforces (profiles, delay ceiling, byte cap).
    pub fn settings(&self) -> &Settings {
        &self.settings
    }

    /// Identity of the settings behind this budget, for reload reuse.
    pub fn fingerprint(&self) -> String {
        self.settings.fingerprint()
    }

    /// Take a drip slot, or `None` when the budget is exhausted.
    ///
    /// `None` is the T5 degradation path: the caller answers immediately instead of delaying, and
    /// must not forward the request to the backend.
    pub fn try_acquire(self: &Arc<Self>) -> Option<Permit> {
        // compare_exchange rather than fetch_add-then-rollback: with fetch_add, two racing callers
        // can both observe the over-limit value and both roll back, and in the window between them
        // a third caller sees a count that never existed.
        loop {
            let current = self.in_use.load(Ordering::Acquire);
            if current >= self.limit() {
                return None;
            }
            match self.in_use.compare_exchange_weak(
                current,
                current + 1,
                Ordering::AcqRel,
                Ordering::Acquire,
            ) {
                Ok(_) => {
                    return Some(Permit {
                        budget: Arc::clone(self),
                    })
                }
                Err(_) => continue,
            }
        }
    }

    /// Current in-flight count (for the `--show-runtime` style diagnostics and for tests).
    pub fn in_use(&self) -> usize {
        self.in_use.load(Ordering::Acquire)
    }

    /// The configured cap.
    pub fn limit(&self) -> usize {
        self.settings.max_concurrent_drips
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Gap 1: the `Server` header on an inline answer comes from the policy, and a policy that names
    /// a different banner must be observable on the response - not only in `--show-policy`.
    #[test]
    fn the_configured_banner_is_the_header_the_client_receives() {
        let mut settings = Settings::default_inline();
        settings.server_banner = "Apache/2.4.37 (Oracle Linux Server)".to_string();
        let budget = std::sync::Arc::new(Budget::new(&settings));
        let permit = budget
            .try_acquire()
            .expect("a budget with capacity issues a permit");
        let response = permit.response(lookup("generic").expect("generic profile exists"));
        assert_eq!(
            response
                .headers()
                .get(hyper::header::SERVER)
                .unwrap()
                .to_str()
                .unwrap(),
            "Apache/2.4.37 (Oracle Linux Server)",
            "the header must carry the configured value verbatim"
        );
        assert_eq!(
            response.status().as_u16(),
            403,
            "the profile still decides the status"
        );

        // The default is the package identity the gateway has always sent, so a host that does not
        // opt in sees no change from this change.
        let default_budget = std::sync::Arc::new(Budget::new(&Settings::default_inline()));
        let default_permit = default_budget
            .try_acquire()
            .expect("a fresh budget has capacity");
        assert_eq!(
            default_permit
                .response(lookup("generic").unwrap())
                .headers()
                .get(hyper::header::SERVER)
                .unwrap()
                .to_str()
                .unwrap(),
            DEFAULT_SERVER_BANNER
        );
    }

    /// A banner change has to change the `Budget` fingerprint, or the reload path reuses the cached
    /// budget and the new banner never reaches the wire while the policy file says it did.
    #[test]
    fn a_banner_change_changes_the_fingerprint() {
        let base = Settings::default_inline();
        let mut changed = Settings::default_inline();
        changed.server_banner = "nginx".to_string();
        assert_ne!(
            base.fingerprint(),
            changed.fingerprint(),
            "fingerprint must include the banner"
        );
        assert!(changed.fingerprint().ends_with("#nginx"));
    }

    #[test]
    fn profile_names_are_unique_and_usable() {
        let mut seen = std::collections::BTreeSet::new();
        for profile in PROFILES {
            assert!(
                seen.insert(profile.name),
                "duplicate profile name {}",
                profile.name
            );
            assert!(
                !profile.body.is_empty(),
                "{} has an empty body",
                profile.name
            );
            assert!(
                !profile.content_type.is_empty(),
                "{} has no content type",
                profile.name
            );
            assert_eq!(lookup(profile.name).map(|p| p.name), Some(profile.name));
        }
        assert_eq!(lookup("does-not-exist"), None);
    }

    #[test]
    fn default_settings_validate_against_the_catalog() {
        let settings = Settings::default_inline();
        assert!(settings.validate().is_ok());
    }

    #[test]
    fn a_typo_in_a_profile_name_is_a_load_time_error_not_a_runtime_surprise() {
        let mut settings = Settings::default_inline();
        settings.detected_profile = "exploit-prob".to_string();
        let error = settings.validate().unwrap_err();
        assert!(
            error.contains("detected_profile") && error.contains("no such profile"),
            "unhelpful error: {error}"
        );
    }

    #[test]
    fn a_zero_drip_cap_is_rejected_because_it_would_refuse_everything() {
        let mut settings = Settings::default_inline();
        settings.max_concurrent_drips = 0;
        assert!(settings
            .validate()
            .unwrap_err()
            .contains("max_concurrent_drips"));
    }

    #[test]
    fn a_profile_bigger_than_the_byte_budget_is_refused_at_load() {
        let mut settings = Settings::default_inline();
        settings.per_connection_max_bytes = 8; // every built-in body is larger than this
        let error = settings.validate().unwrap_err();
        assert!(error.contains("over per_connection_max_bytes"), "{error}");
    }

    #[test]
    fn delays_are_clamped_so_a_profile_cannot_stall_a_connection_forever() {
        let mut settings = Settings::default_inline();
        settings.max_drip_ms = 1_000;
        let profile = lookup("generic").unwrap(); // asks for 5000 ms
        assert_eq!(settings.delay_for(profile).as_millis(), 1_000);
        assert!(
            settings.drip_total(profile).as_millis() <= 1_000,
            "the planned drip must fit inside the clamped budget, got {} ms",
            settings.drip_total(profile).as_millis()
        );
        let header = settings.deception_header(profile);
        assert!(
            header.starts_with("generic;drip_ms="),
            "the header must name the shape it actually used: {header}"
        );
        assert!(header.contains(";chunks="), "{header}");
    }

    /// The bug this change exists to fix: with a single frame, the inline path was a latency tarpit
    /// while the responder dripped, so one request told a scanner which responder answered.
    #[tokio::test]
    async fn the_inline_answer_arrives_in_more_than_one_piece() {
        let mut settings = Settings::default_inline();
        settings.chunk_size = 16;
        settings.chunk_delay_ms = 1;
        let budget = Arc::new(Budget::new(&settings));
        let profile = lookup("generic").unwrap();
        let (expected_chunks, _) = settings.drip_plan(profile);
        assert!(expected_chunks > 1, "the fixture must span several chunks");

        let response = budget.try_acquire().expect("capacity").response(profile);
        let mut body = response.into_body();
        let mut pieces = 0_usize;
        let mut assembled = Vec::new();
        while let Some(frame) = body.frame().await {
            let frame = frame.expect("an inline body cannot fail");
            if let Some(data) = frame.data_ref() {
                pieces += 1;
                assembled.extend_from_slice(data);
            }
        }
        assert_eq!(pieces, expected_chunks, "one frame per chunk");
        assert_eq!(assembled, profile.body.as_bytes(), "the body is unchanged");
    }

    /// The permit has to outlive the response object, or a burst of long drips exceeds the cap it is
    /// supposed to enforce.
    #[tokio::test]
    async fn a_streaming_answer_holds_its_budget_slot_until_the_last_byte() {
        let mut settings = Settings::default_inline();
        settings.chunk_size = 16;
        settings.chunk_delay_ms = 1;
        let budget = Arc::new(Budget::new(&settings));
        let response = budget
            .try_acquire()
            .expect("capacity")
            .response(lookup("generic").unwrap());
        assert_eq!(budget.in_use(), 1, "the slot is held while streaming");
        let mut body = response.into_body();
        let _ = body.frame().await.expect("at least one frame").expect("ok");
        assert_eq!(budget.in_use(), 1, "still held mid-stream");
        drop(body);
        assert_eq!(budget.in_use(), 0, "dropping the body refunds the slot");
    }

    /// A zero budget must still answer immediately, and still in pieces - the diagnostic path must
    /// not turn back into a single write.
    #[tokio::test]
    async fn a_zero_ceiling_answers_immediately_in_several_pieces() {
        let settings = Settings {
            max_drip_ms: 0,
            chunk_size: 16,
            chunk_delay_ms: 0,
            ..Settings::default_inline()
        };
        settings.validate().expect("valid");
        let profile = lookup("generic").unwrap();
        let (chunks, gap) = settings.drip_plan(profile);
        assert!(chunks > 1);
        assert!(gap.is_zero());
        let budget = Arc::new(Budget::new(&settings));
        let mut body = budget
            .try_acquire()
            .expect("capacity")
            .response(profile)
            .into_body();
        let mut seen = 0;
        while body.frame().await.is_some() {
            seen += 1;
        }
        assert_eq!(seen, chunks);
    }

    #[test]
    fn selection_answers_a_detected_request_and_a_quarantined_request_differently() {
        let settings = Settings::default_inline();
        let detected = select(
            &settings.detected_profile,
            &settings.quarantined_profile,
            true,
            "/index.html",
        );
        let quarantined = select(
            &settings.detected_profile,
            &settings.quarantined_profile,
            false,
            "/index.html",
        );
        assert_eq!(detected.name, "exploit-probe");
        assert_eq!(quarantined.name, "generic");
        assert_ne!(
            detected.status, quarantined.status,
            "T3: same answer to both classes is the failure mode"
        );
    }

    #[test]
    fn an_api_path_gets_an_api_shaped_answer_when_detected() {
        let settings = Settings::default_inline();
        let profile = select(
            &settings.detected_profile,
            &settings.quarantined_profile,
            true,
            "/api/v1/session.json",
        );
        assert_eq!(profile.name, "api-probe");
        assert_eq!(profile.content_type, "application/json");
        // ...but the same path without a detection is answered as any other quarantined client.
        assert_eq!(
            select(
                &settings.detected_profile,
                &settings.quarantined_profile,
                false,
                "/api/v1/session.json"
            )
            .name,
            "generic"
        );
    }

    #[test]
    fn the_budget_refuses_the_surplus_and_gives_the_slot_back() {
        let settings = Settings {
            max_concurrent_drips: 2,
            ..Settings::default_inline()
        };
        let budget = Arc::new(Budget::new(&settings));
        assert_eq!(budget.in_use(), 0);
        let first = budget.try_acquire().expect("first slot");
        let second = budget.try_acquire().expect("second slot");
        assert_eq!(budget.in_use(), 2);
        assert!(
            budget.try_acquire().is_none(),
            "a third drip must be refused, not queued"
        );
        let response = first.response(lookup("generic").unwrap());
        assert_eq!(response.status().as_u16(), 403);
        // The permit lives inside the body now, so dropping the permit alone is not possible:
        // dropping the *body* is what releases the slot.
        drop(response.into_body());
        assert_eq!(
            budget.in_use(),
            1,
            "dropping a response body must release the slot"
        );
        assert!(
            budget.try_acquire().is_some(),
            "capacity returns, so a transient burst cannot permanently disable deception"
        );
        drop(second);
        assert_eq!(budget.in_use(), 0);
    }

    #[test]
    fn an_unbounded_sleep_is_the_bug_the_budget_exists_to_bound() {
        // Two settings that would be invisible in a naive implementation: a cap of 1 and a 0 ms
        // ceiling must still produce a correct, immediate answer.
        let settings = Settings {
            max_concurrent_drips: 1,
            max_drip_ms: 0,
            ..Settings::default_inline()
        };
        settings.validate().expect("valid");
        let budget = Arc::new(Budget::new(&settings));
        let permit = budget.try_acquire().expect("one slot available");
        assert_eq!(
            settings.delay_for(lookup("generic").unwrap()).as_millis(),
            0
        );
        assert_eq!(
            permit
                .response(lookup("generic").unwrap())
                .status()
                .as_u16(),
            403
        );
    }
}
