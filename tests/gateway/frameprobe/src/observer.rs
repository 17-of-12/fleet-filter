//! observer.rs - raw HTTP/2 frame observation in front of hyper's parser (Bundle Q).
//!
//! What this file is for
//! ---------------------
//! Bundle Q asks whether a *passive frame observer* can see - and act on - HTTP/2 frames before
//! `hyper`/`h2` parses them, without forking the codec. The only place that is true by
//! construction is the byte stream itself: everything above `h2::server` is already post-parse.
//! So this module implements the byte-stream side directly:
//!
//! * [`Observer`] validates complete frames out of a raw byte stream (RFC 9113 framing rules plus
//!   the policy in [`Policy`]) and reports what it saw ([`Stats`]).
//! * [`ObservedIo`] is the `AsyncRead`/`AsyncWrite` adapter that puts an [`Observer`] between a
//!   TLS stream and `hyper::server::conn::http2::Builder`. It releases bytes to hyper **only
//!   after** the observer has validated the frame they belong to, which is what turns observation
//!   into enforcement (Q3): a rejected frame is never handed to the parser, so no request object
//!   is ever produced for it.
//!
//! Deliberate limits, stated here rather than discovered later
//! ----------------------------------------------------------
//! * Only the client-to-server direction is parsed. Response frames the server writes are counted
//!   but not parsed, because parsing them would require buffering the response too (Q6).
//! * A frame is released whole. The observer can withhold a HEADERS frame until it is complete
//!   (which is also when HPACK can be decoded), but it cannot un-deliver bytes already handed to
//!   hyper. Cost is one buffered frame per connection, reported as `Stats::max_buffered_bytes`.
//! * Header *names* are unknowable from raw bytes; they need HPACK. That decoding sits behind the
//!   `hpack` cargo feature - without it, the experiment still answers Q4 by demonstrating the gap.

use std::collections::BTreeMap;
use std::io;
use std::pin::Pin;
use std::sync::{Arc, Mutex, MutexGuard};
use std::task::{Context, Poll};

use bytes::BytesMut;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

/// The client-to-server connection preface (RFC 9113 3.4). It is not a frame, but it is the first
/// thing on the decrypted stream, so an observer has to recognise it before framing can start.
pub const PREFACE: &[u8; 24] = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";

/// Flag bit meanings that differ per frame type; everything else is treated as an unknown bit.
const F_END_STREAM: u8 = 0x01;
const F_ACK: u8 = 0x01;
const F_END_HEADERS: u8 = 0x04;
const F_PADDED: u8 = 0x08;
const F_PRIORITY: u8 = 0x20;

/// A parsed frame header (RFC 9113 4.1).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FrameHeader {
    pub length: u32,
    pub ftype: u8,
    pub flags: u8,
    pub stream_id: u32,
}

impl FrameHeader {
    /// Parse a 9-byte frame header, masking the reserved stream-id bit.
    ///
    /// Returns `None` when the slice is short, so callers can accumulate before parsing.
    pub fn parse(b: &[u8]) -> Option<FrameHeader> {
        if b.len() < 9 {
            return None;
        }
        Some(FrameHeader {
            length: ((b[0] as u32) << 16) | ((b[1] as u32) << 8) | b[2] as u32,
            ftype: b[3],
            flags: b[4],
            stream_id: u32::from_be_bytes([b[5], b[6], b[7], b[8]]) & 0x7fff_ffff,
        })
    }

    /// Serialise back to the exact 9 bytes, so a validated frame can be handed to hyper unchanged.
    pub fn to_bytes(&self) -> [u8; 9] {
        let id = self.stream_id.to_be_bytes();
        [
            (self.length >> 16) as u8,
            (self.length >> 8) as u8,
            self.length as u8,
            self.ftype,
            self.flags,
            id[0],
            id[1],
            id[2],
            id[3],
        ]
    }

    /// Frame type name, including an `UNKNOWN(n)` bucket so unknown types are still reportable.
    pub fn type_name(&self) -> String {
        match self.ftype {
            0 => "DATA",
            1 => "HEADERS",
            2 => "PRIORITY",
            3 => "RST_STREAM",
            4 => "SETTINGS",
            5 => "PUSH_PROMISE",
            6 => "PING",
            7 => "GOAWAY",
            8 => "WINDOW_UPDATE",
            9 => "CONTINUATION",
            _ => return format!("UNKNOWN({})", self.ftype),
        }
        .to_string()
    }

    /// True for frames that belong to a stream (as opposed to the connection itself).
    ///
    /// WINDOW_UPDATE is deliberately excluded: RFC 9113 lets it name stream 0 (a connection-wide
    /// window) as well as a stream, so answering "yes" here would flag a legal frame. That is
    /// exactly the false positive the first selftest run caught.
    pub fn is_stream_level(&self) -> bool {
        matches!(self.ftype, 0 | 1 | 2 | 3 | 5 | 9)
    }

    /// True for frame types that may only ever be connection-level (must name stream 0).
    pub fn is_connection_only(&self) -> bool {
        matches!(self.ftype, 4 | 6 | 7)
    }

    /// One-line rendering of the header, used in the frame log.
    pub fn label(&self) -> String {
        format!(
            "{}(len={},flags={},id={})",
            self.type_name(),
            self.length,
            self.flags_desc(),
            self.stream_id
        )
    }

    /// True when this frame type defines the PADDED flag at all.
    pub fn padded_flag_defined(&self) -> bool {
        matches!(self.ftype, 0 | 1 | 2 | 5)
    }

    /// True when this frame type carries a header block (so HPACK applies).
    pub fn carries_header_block(&self) -> bool {
        matches!(self.ftype, 1 | 5 | 9)
    }

    /// Human-readable flag names, plus the raw value whenever a bit outside the set this code
    /// understands is set - an unrecognised flag bit is exactly what a raw observer can see and a
    /// parsed view would hide.
    pub fn flags_desc(&self) -> String {
        let mut names: Vec<&str> = Vec::new();
        let mut known: u8 = 0;
        let has = |bit: u8| self.flags & bit != 0;
        match self.ftype {
            0 => {
                known |= F_END_STREAM | F_PADDED;
                if has(F_END_STREAM) {
                    names.push("END_STREAM");
                }
                if has(F_PADDED) {
                    names.push("PADDED");
                }
            }
            1 => {
                known |= F_END_STREAM | F_END_HEADERS | F_PADDED | F_PRIORITY;
                if has(F_END_STREAM) {
                    names.push("END_STREAM");
                }
                if has(F_END_HEADERS) {
                    names.push("END_HEADERS");
                }
                if has(F_PADDED) {
                    names.push("PADDED");
                }
                if has(F_PRIORITY) {
                    names.push("PRIORITY");
                }
            }
            2 => {
                known |= F_PADDED;
                if has(F_PADDED) {
                    names.push("PADDED");
                }
            }
            4 | 6 => {
                known |= F_ACK;
                if has(F_ACK) {
                    names.push("ACK");
                }
            }
            5 => {
                known |= F_END_HEADERS | F_PADDED;
                if has(F_END_HEADERS) {
                    names.push("END_HEADERS");
                }
                if has(F_PADDED) {
                    names.push("PADDED");
                }
            }
            9 => {
                known |= F_END_HEADERS;
                if has(F_END_HEADERS) {
                    names.push("END_HEADERS");
                }
            }
            _ => {}
        }
        let unknown = self.flags & !known;
        if names.is_empty() {
            format!("0x{:02x}", self.flags)
        } else if unknown == 0 {
            names.join("|")
        } else {
            format!("{}|0x{:02x}", names.join("|"), unknown)
        }
    }
}

/// A validated frame: header plus payload.
#[derive(Clone, Debug)]
pub struct Frame {
    pub hdr: FrameHeader,
    pub payload: Vec<u8>,
}

impl Frame {
    /// Exact wire bytes for this frame.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut v = Vec::with_capacity(9 + self.payload.len());
        v.extend_from_slice(&self.hdr.to_bytes());
        v.extend_from_slice(&self.payload);
        v
    }

    /// Build a frame's bytes directly, for the selftest's crafted cases.
    pub fn bytes(ftype: u8, flags: u8, stream_id: u32, payload: &[u8]) -> Vec<u8> {
        Frame {
            hdr: FrameHeader {
                length: payload.len() as u32,
                ftype,
                flags,
                stream_id,
            },
            payload: payload.to_vec(),
        }
        .to_bytes()
    }
}

/// One observable item taken out of the byte stream.
#[derive(Clone, Debug)]
pub enum Item {
    Preface,
    Frame(Frame),
}

impl Item {
    /// The exact bytes this item consumes off the stream.
    pub fn to_bytes(&self) -> Vec<u8> {
        match self {
            Item::Preface => PREFACE.to_vec(),
            Item::Frame(f) => f.to_bytes(),
        }
    }

    /// Short label used in the frame log.
    pub fn label(&self) -> String {
        match self {
            Item::Preface => "PREFACE".to_string(),
            Item::Frame(f) => f.hdr.label(),
        }
    }
}

/// Observe-only versus enforce.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Mode {
    /// Record violations but keep the connection alive: telemetry.
    Observe,
    /// Refuse the frame and let the caller abort the connection: enforcement.
    Enforce,
}

/// Frame-level policy. Every field corresponds to a check that raw framing alone can answer,
/// except `path_contains`, which needs HPACK.
#[derive(Clone, Debug)]
pub struct Policy {
    pub mode: Mode,
    /// When set, frame types outside this list are refused (`frame-type-not-allowed`).
    pub allowed_types: Option<Vec<u8>>,
    /// RFC 9113 default is 16384; a peer must not send more than the endpoint advertised.
    pub max_frame: u32,
    /// Refuse any padded frame (`{TYPE}-padded`) - padding is a common scanner tell.
    pub reject_padded: bool,
    /// RFC says ignore unknown frame types; a security gateway may prefer to refuse them.
    pub reject_unknown_types: bool,
    /// Client-initiated stream ids must be odd; an even id from a client is a protocol error.
    pub require_odd_stream_id: bool,
    /// Requires header decoding (HPACK): the only way to act on `:path` before the parser.
    pub path_contains: Option<String>,
}

impl Default for Policy {
    fn default() -> Self {
        Policy {
            mode: Mode::Observe,
            allowed_types: None,
            max_frame: 16384,
            reject_padded: false,
            reject_unknown_types: true,
            require_odd_stream_id: true,
            path_contains: None,
        }
    }
}

/// Everything the observer can prove about a connection.
#[derive(Default, Clone, Debug)]
pub struct Stats {
    pub frames_total: u64,
    pub by_type: BTreeMap<String, u64>,
    pub bytes_observed: u64,
    pub max_frame_len: u32,
    pub max_buffered_bytes: usize,
    pub preface_ok: u64,
    pub violations: BTreeMap<String, u64>,
    pub hpack_ok: u64,
    pub hpack_err: u64,
    /// Last decoded header block, to show what needed HPACK to know.
    pub last_headers: Vec<(String, String)>,
    /// Decoded SETTINGS parameters, e.g. `MAX_FRAME_SIZE=16384`.
    pub settings: Vec<String>,
    pub last_window_update: Option<i64>,
    pub last_rst_code: Option<u32>,
}

impl Stats {
    /// Record one frame's contribution to the counters shared by every code path.
    pub fn count_frame(&mut self, hdr: FrameHeader, payload: &[u8]) {
        self.frames_total += 1;
        *self.by_type.entry(hdr.type_name()).or_insert(0) += 1;
        self.bytes_observed += 9 + payload.len() as u64;
        if hdr.length > self.max_frame_len {
            self.max_frame_len = hdr.length;
        }
    }

    /// Record a rule hit.
    pub fn violation(&mut self, rule: &str) {
        *self.violations.entry(rule.to_string()).or_insert(0) += 1;
    }

    /// Compact one-line rendering for the tool's report.
    pub fn summary(&self) -> String {
        let by_type: Vec<String> = self
            .by_type
            .iter()
            .map(|(k, v)| format!("{k}={v}"))
            .collect();
        let violations: Vec<String> = self
            .violations
            .iter()
            .map(|(k, v)| format!("{k}={v}"))
            .collect();
        format!(
            "frames={} bytes={} max_frame_len={} buffered={} preface={} by_type[{}] violations[{}] hpack_ok={} hpack_err={} settings[{}] window_update={:?} rst_code={:?}",
            self.frames_total,
            self.bytes_observed,
            self.max_frame_len,
            self.max_buffered_bytes,
            self.preface_ok,
            by_type.join(","),
            violations.join(","),
            self.hpack_ok,
            self.hpack_err,
            self.settings.join(","),
            self.last_window_update,
            self.last_rst_code,
        )
    }
}

/// The observer: validates frames as they complete and accumulates what it learned.
pub struct Observer {
    pub policy: Policy,
    pub stats: Stats,
    /// Labels for the frames observed, capped so a chatty connection cannot grow without bound.
    /// The report prints this list; it is the artefact reviewers ask for ("show me the frames").
    pub frame_log: Vec<String>,
    /// Bytes received but not yet releasable, because the frame they belong to is incomplete.
    pending: Vec<u8>,
    /// A header block opened by HEADERS without END_HEADERS, awaiting CONTINUATION.
    open_block: Option<(u32, Vec<u8>)>,
    /// Highest stream id seen from a client-initiated frame (HEADERS / PUSH_PROMISE).
    last_new_stream: Option<u32>,
    preface_done: bool,
}

impl Observer {
    /// New observer with the given policy and empty stats.
    pub fn new(policy: Policy) -> Observer {
        Observer {
            policy,
            stats: Stats::default(),
            frame_log: Vec::new(),
            pending: Vec::new(),
            open_block: None,
            last_new_stream: None,
            preface_done: false,
        }
    }

    /// Consume raw decrypted bytes and return every item that became complete.
    ///
    /// `Err` means the policy refused a frame (in `Enforce`) or the stream is unparseable (bad
    /// preface). On `Err` the caller must not release the bytes it fed in: that withholding is
    /// what makes this enforcement rather than logging.
    pub fn push(&mut self, bytes: &[u8]) -> Result<Vec<Item>, String> {
        self.pending.extend_from_slice(bytes);
        let mut items: Vec<Item> = Vec::new();

        loop {
            if !self.preface_done {
                if self.pending.len() < PREFACE.len() {
                    break;
                }
                if &self.pending[..PREFACE.len()] != PREFACE {
                    // Without a valid preface there is no framing to recover, so this is fatal in
                    // Observe mode too.
                    self.stats.violation("bad-preface");
                    return Err("bad-preface: stream does not start with the HTTP/2 preface".to_string());
                }
                self.preface_done = true;
                self.stats.preface_ok += 1;
                if self.frame_log.len() < 256 {
                    self.frame_log.push(Item::Preface.label());
                }
                items.push(Item::Preface);
                self.pending.drain(..PREFACE.len());
                continue;
            }

            if self.pending.len() < 9 {
                break;
            }
            let hdr = match FrameHeader::parse(&self.pending[..9]) {
                Some(h) => h,
                None => break,
            };
            let total = 9usize + hdr.length as usize;
            if self.pending.len() < total {
                // Incomplete frame: withhold it. This is the buffering cost the report quantifies.
                break;
            }
            let payload: Vec<u8> = self.pending[9..total].to_vec();
            self.check_frame(hdr, &payload)?;
            let frame = Frame { hdr, payload };
            if self.frame_log.len() < 256 {
                self.frame_log.push(hdr.label());
            }
            items.push(Item::Frame(frame));
            self.pending.drain(..total);
        }

        if self.pending.len() > self.stats.max_buffered_bytes {
            self.stats.max_buffered_bytes = self.pending.len();
        }
        Ok(items)
    }

    /// Validate one complete frame and record it. Returns `Err` in `Enforce` mode when a rule
    /// matches; in `Observe` mode the violation is recorded and the frame is accepted.
    pub fn check_frame(&mut self, hdr: FrameHeader, payload: &[u8]) -> Result<(), String> {
        // 1. Is the frame type defined at all? (RFC says ignore; a gateway may refuse.)
        if hdr.ftype > 9 && self.policy.reject_unknown_types {
            return self.reject(hdr, payload, "unknown-frame-type", "frame type is not defined by RFC 9113");
        }
        // 2. Type allowlist - a policy choice, not a spec rule.
        if let Some(allowed) = &self.policy.allowed_types {
            if !allowed.contains(&hdr.ftype) {
                return self.reject(
                    hdr,
                    payload,
                    "frame-type-not-allowed",
                    &format!("{} is not in the configured allowlist", hdr.type_name()),
                );
            }
        }
        // 3. Length versus the advertised maximum frame size.
        if hdr.length > self.policy.max_frame {
            return self.reject(
                hdr,
                payload,
                "frame-too-large",
                &format!(
                    "length {} exceeds max_frame {}",
                    hdr.length, self.policy.max_frame
                ),
            );
        }
        // 4. Stream-id rules. Connection-only frames must name stream 0; frames that name a
        //    stream must not name 0; any named client stream must be odd.
        if hdr.is_connection_only() && hdr.stream_id != 0 {
            return self.reject(
                hdr,
                payload,
                &format!("{}-bad-stream-id", hdr.type_name()),
                &format!(
                    "{} is connection-level but names stream {}",
                    hdr.type_name(),
                    hdr.stream_id
                ),
            );
        }
        if hdr.is_stream_level() && hdr.stream_id == 0 {
            return self.reject(
                hdr,
                payload,
                &format!("{}-bad-stream-id", hdr.type_name()),
                format!("{} names stream 0, which is reserved", hdr.type_name()),
            );
        }
        // 5. Client-initiated stream ids are odd (applies to any frame naming a stream, including
        //    a connection-level WINDOW_UPDATE's sibling form and PUSH_PROMISE).
        if self.policy.require_odd_stream_id && hdr.stream_id != 0 && hdr.stream_id % 2 == 0 {
            return self.reject(
                hdr,
                payload,
                "even-client-stream-id",
                format!("{} names even stream {}", hdr.type_name(), hdr.stream_id),
            );
        }
        // 6. Per-type length rules - all answerable from the 9-byte header alone.
        let bad_len: Option<&str> = match hdr.ftype {
            2 if hdr.length != 5 => Some("PRIORITY-bad-length"),
            3 if hdr.length != 4 => Some("RST_STREAM-bad-length"),
            6 if hdr.length != 8 => Some("PING-bad-length"),
            7 if hdr.length < 8 => Some("GOAWAY-bad-length"),
            5 if hdr.length < 4 => Some("PUSH_PROMISE-bad-length"),
            8 if hdr.length != 4 => Some("WINDOW_UPDATE-bad-length"),
            4 if (hdr.flags & F_ACK != 0 && hdr.length != 0) => Some("SETTINGS-ACK-with-payload"),
            4 if (hdr.flags & F_ACK == 0 && hdr.length % 6 != 0) => Some("SETTINGS-bad-length"),
            1 if (hdr.length == 0 && hdr.flags & F_PADDED == 0) => Some("HEADERS-empty"),
            _ => None,
        };
        if let Some(rule) = bad_len {
            return self.reject(
                hdr,
                payload,
                rule,
                &format!("{} length {} violates RFC 9113", hdr.type_name(), hdr.length),
            );
        }
        // 7. Header-block state: CONTINUATION needs an open block; HEADERS cannot open a second one.
        if hdr.ftype == 9 && self.open_block.is_none() {
            return self.reject(
                hdr,
                payload,
                "CONTINUATION-without-block",
                "CONTINUATION arrived with no open header block".to_string(),
            );
        }
        if hdr.ftype == 1 && self.open_block.is_some() {
            return self.reject(
                hdr,
                payload,
                "HEADERS-while-block-open",
                format!(
                    "HEADERS on stream {} arrived while the block for stream {} is still open",
                    hdr.stream_id,
                    self.open_block.as_ref().map(|(s, _)| *s).unwrap_or(0)
                ),
            );
        }
        // 8. Client-initiated stream ids must increase.
        if matches!(hdr.ftype, 1 | 5) {
            if let Some(last) = self.last_new_stream {
                if hdr.stream_id <= last {
                    return self.reject(
                        hdr,
                        payload,
                        "stream-id-not-increasing",
                        format!(
                            "stream {} is not greater than previously seen {}",
                            hdr.stream_id, last
                        ),
                    );
                }
            }
            self.last_new_stream = Some(hdr.stream_id);
        }
        // 9. Padding must fit in the payload, and may be policy-rejected.
        if hdr.padded_flag_defined() && hdr.flags & F_PADDED != 0 {
            if payload.is_empty() {
                return self.reject(
                    hdr,
                    payload,
                    &format!("{}-bad-padding", hdr.type_name()),
                    "PADDED set but the payload is empty".to_string(),
                );
            }
            let pad_len = payload[0] as usize;
            let prefix = if hdr.ftype == 1 && hdr.flags & F_PRIORITY != 0 {
                6 // 1 padding byte + 5 priority bytes
            } else if hdr.ftype == 5 {
                5 // 1 padding byte + 4 promised-stream-id bytes
            } else {
                1
            };
            if pad_len + prefix > payload.len() {
                return self.reject(
                    hdr,
                    payload,
                    &format!("{}-bad-padding", hdr.type_name()),
                    format!(
                        "padding length {pad_len} exceeds the {} payload",
                        hdr.type_name()
                    ),
                );
            }
            if self.policy.reject_padded {
                return self.reject(
                    hdr,
                    payload,
                    &format!("{}-padded", hdr.type_name()),
                    "policy rejects padded frames".to_string(),
                );
            }
        }

        // Accepted: count it once, then extract the payload-level facts.
        self.stats.count_frame(hdr, payload);
        match hdr.ftype {
            4 if hdr.flags & F_ACK == 0 => {
                self.stats.settings = decode_settings(payload);
            }
            8 if hdr.length == 4 => {
                let raw = u32::from_be_bytes([payload[0], payload[1], payload[2], payload[3]]);
                self.stats.last_window_update = Some((raw & 0x7fff_ffff) as i32 as i64);
            }
            3 if hdr.length == 4 => {
                self.stats.last_rst_code =
                    Some(u32::from_be_bytes([payload[0], payload[1], payload[2], payload[3]]));
            }
            _ => {}
        }
        // 10. Header blocks: HPACK is the only way to learn the names.
        if hdr.carries_header_block() {
            if hdr.ftype == 9 {
                let (id, mut acc) = self.open_block.take().unwrap_or((hdr.stream_id, Vec::new()));
                acc.extend_from_slice(payload);
                if hdr.flags & F_END_HEADERS != 0 {
                    self.decode_block(&acc)?;
                } else {
                    self.open_block = Some((id, acc));
                }
            } else {
                let block = header_block(&hdr, payload);
                if hdr.flags & F_END_HEADERS != 0 {
                    self.decode_block(block)?;
                } else {
                    self.open_block = Some((hdr.stream_id, block.to_vec()));
                }
            }
        }
        Ok(())
    }

    /// Common path for a rule hit: count the frame, record the rule, and in Enforce mode return the
    /// error the caller must act on. In Observe mode the frame is accepted so the connection lives.
    fn reject(&mut self, hdr: FrameHeader, payload: &[u8], rule: &str, detail: impl Into<String>) -> Result<(), String> {
        let detail = detail.into();
        self.stats.count_frame(hdr, payload);
        self.stats.violation(rule);
        match self.policy.mode {
            Mode::Enforce => Err(format!("{rule}: {detail}")),
            Mode::Observe => Ok(()),
        }
    }

    /// Decode a complete HPACK header block and apply the `path_contains` rule.
    fn decode_block(&mut self, block: &[u8]) -> Result<(), String> {
        match decode_headers(block) {
            Ok(headers) => {
                self.stats.hpack_ok += 1;
                self.stats.last_headers = headers.clone();
                if let Some(needle) = self.policy.path_contains.clone() {
                    let path = headers
                        .iter()
                        .find(|(n, _)| n == ":path")
                        .map(|(_, v)| v.clone())
                        .unwrap_or_default();
                    if !needle.is_empty() && path.contains(needle.as_str()) {
                        return self.reject_headers(
                            "path-contains",
                            format!(":path {path} matches the configured pattern {needle}"),
                        );
                    }
                }
                Ok(())
            }
            Err(e) => self.reject_headers("hpack-error", e),
        }
    }

    /// Variant of `reject` for failures found after the frame was already counted (header block).
    fn reject_headers(&mut self, rule: &str, detail: String) -> Result<(), String> {
        self.stats.violation(rule);
        match self.policy.mode {
            Mode::Enforce => Err(format!("{rule}: {detail}")),
            Mode::Observe => Ok(()),
        }
    }
}

/// Extract the HPACK header block from a HEADERS/PUSH_PROMISE payload, stripping padding and the
/// optional priority prefix.
fn header_block<'a>(hdr: &FrameHeader, payload: &'a [u8]) -> &'a [u8] {
    let mut start = 0usize;
    if hdr.ftype == 1 && hdr.flags & F_PRIORITY != 0 {
        start = 5; // Stream Priority (5 bytes) precedes the block
    } else if hdr.ftype == 5 {
        start = 4; // Promised Stream ID (4 bytes) precedes the block
    }
    let mut end = payload.len();
    if hdr.padded_flag_defined() && hdr.flags & F_PADDED != 0 && !payload.is_empty() {
        let pad = payload[0] as usize;
        end = end.saturating_sub(pad).max(start);
    }
    let start = start.min(end);
    &payload[start..end]
}

/// Decode SETTINGS payload into `NAME=value` strings for the report.
fn decode_settings(payload: &[u8]) -> Vec<String> {
    let mut out = Vec::new();
    for chunk in payload.chunks(6) {
        if chunk.len() < 6 {
            break;
        }
        let id = u16::from_be_bytes([chunk[0], chunk[1]]);
        let value = u32::from_be_bytes([chunk[2], chunk[3], chunk[4], chunk[5]]);
        let name = match id {
            0x1 => "HEADER_TABLE_SIZE",
            0x2 => "ENABLE_PUSH",
            0x3 => "MAX_CONCURRENT_STREAMS",
            0x4 => "INITIAL_WINDOW_SIZE",
            0x5 => "MAX_FRAME_SIZE",
            0x6 => "MAX_HEADER_LIST_SIZE",
            _ => "UNKNOWN_SETTING",
        };
        out.push(format!("{name}={value}"));
    }
    out
}

/// HPACK decode a header block. Behind the `hpack` feature; without it the caller learns that the
/// names are not recoverable from raw bytes, which is the Q4 answer.
#[cfg(feature = "hpack")]
pub fn decode_headers(block: &[u8]) -> Result<Vec<(String, String)>, String> {
    let mut decoder = hpack::Decoder::new();
    match decoder.decode(block) {
        Ok(pairs) => Ok(pairs
            .into_iter()
            .map(|(n, v)| {
                (
                    String::from_utf8_lossy(&n).to_string(),
                    String::from_utf8_lossy(&v).to_string(),
                )
            })
            .collect()),
        Err(e) => Err(format!("hpack: {e:?}")),
    }
}

#[cfg(not(feature = "hpack"))]
pub fn decode_headers(_block: &[u8]) -> Result<Vec<(String, String)>, String> {
    Err("hpack feature disabled: header names are not recoverable from raw bytes".to_string())
}

/// `AsyncRead`/`AsyncWrite` adapter that puts an [`Observer`] in front of hyper.
///
/// Reads are frame-aligned: bytes reach hyper only once the frame they belong to has been
/// validated, so a refused frame is never parsed. Writes are delegated and counted, which is how
/// the "we only see the request direction" limit is measured rather than hand-waved.
pub struct ObservedIo<T: AsyncRead + AsyncWrite> {
    /// Boxed and pinned so the adapter works for any stream, including ones that are not `Unpin`
    /// (`tokio_rustls::TlsStream` is `Unpin` today, but depending on that would be a gratuitous
    /// coupling to a dependency's internal layout).
    inner: Pin<Box<T>>,
    rx: BytesMut,
    obs: Arc<Mutex<Observer>>,
    pub bytes_written: u64,
}

impl<T: AsyncRead + AsyncWrite> ObservedIo<T> {
    /// Wrap a stream (typically `tokio_rustls::server::TlsStream`) with a shared observer.
    pub fn new(inner: T, obs: Arc<Mutex<Observer>>) -> ObservedIo<T> {
        ObservedIo {
            inner: Box::pin(inner),
            rx: BytesMut::new(),
            obs,
            bytes_written: 0,
        }
    }
}

impl<T: AsyncRead + AsyncWrite> ObservedIo<T> {
    /// Lock the observer, recovering from poisoning so a panic elsewhere cannot wedge a connection.
    fn observer(&mut self) -> MutexGuard<'_, Observer> {
        self.obs.lock().unwrap_or_else(|e| e.into_inner())
    }
}

impl<T: AsyncRead + AsyncWrite> AsyncRead for ObservedIo<T> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let me = self.as_mut().get_mut();
        if !me.rx.is_empty() {
            let n = buf.remaining().min(me.rx.len());
            let chunk: Vec<u8> = me.rx.split_to(n).to_vec();
            buf.put_slice(&chunk);
            return Poll::Ready(Ok(()));
        }
        let mut tmp = [0u8; 16384];
        let mut rb = ReadBuf::new(&mut tmp[..]);
        match me.inner.as_mut().poll_read(cx, &mut rb) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(Err(e)) => Poll::Ready(Err(e)),
            Poll::Ready(Ok(())) => {
                let got = rb.filled().len();
                if got == 0 {
                    // EOF: hand hyper an empty ReadBuf, which is how tokio signals end of stream.
                    return Poll::Ready(Ok(()));
                }
                let fed = tmp[..got].to_vec();
                let items = match me.observer().push(&fed) {
                    Ok(items) => items,
                    Err(reason) => {
                        // The frame is refused: nothing from this read reaches hyper.
                        return Poll::Ready(Err(io::Error::new(io::ErrorKind::InvalidData, reason)));
                    }
                };
                let bytes: Vec<u8> = items.iter().flat_map(|i| i.to_bytes()).collect();
                let take = buf.remaining().min(bytes.len());
                buf.put_slice(&bytes[..take]);
                me.rx.extend_from_slice(&bytes[take..]);
                Poll::Ready(Ok(()))
            }
        }
    }
}

impl<T: AsyncRead + AsyncWrite> AsyncWrite for ObservedIo<T> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let me = self.as_mut().get_mut();
        match me.inner.as_mut().poll_write(cx, buf) {
            Poll::Ready(Ok(n)) => {
                me.bytes_written += n as u64;
                Poll::Ready(Ok(n))
            }
            other => other,
        }
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.as_mut().get_mut().inner.as_mut().poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.as_mut().get_mut().inner.as_mut().poll_shutdown(cx)
    }
}
