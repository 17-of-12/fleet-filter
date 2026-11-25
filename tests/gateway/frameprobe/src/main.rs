//! frameprobe - Bundle Q experiment harness: observe raw HTTP/2 frames before hyper's parser.
//!
//! What this binary proves
//! ----------------------
//! Bundle Q asks whether a passive frame observer can be added to the Stage 2 gateway *without*
//! forking the `h2` codec, and whether such an observer can enforce (not just log). The gateway
//! already shows `hyper` can serve HTTP/2 from any `AsyncRead + AsyncWrite` stream, so the
//! experiment is to put `observer::ObservedIo` - a validating frame reader - in that exact slot and
//! measure what happens.
//!
//! Modes
//! -----
//! * `--selftest` : offline. Reconstructs a synthetic client stream, checks that the observer's
//!   framing round-trips byte-for-byte, runs the violation matrix (every RFC 9113 framing rule the
//!   observer claims to check, plus the policy rules), and measures cost (time and allocations per
//!   byte, whole-buffer versus one-byte-at-a-time). This is the Q2/Q5 evidence.
//! * server mode  : terminates TLS, runs `hyper`'s HTTP/2 server on top of the observer, and
//!   reports per connection: frames seen, bytes, requests served, and - in `--rule enforce` -
//!   whether the connection was aborted and with what reason. `requests_served=0` alongside a
//!   refusal is the Q3 evidence: the request never reached hyper's handler.
//!
//! Why a separate crate from the gateway: the shipped artifact pins one Cargo.lock, and an
//! experiment (which adds the `hpack` crate) must not be able to change the artifact's hash.

mod observer;

use std::error::Error;
use std::fs::File;
use std::io::BufReader;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::{Duration, Instant};

use bytes::Bytes;
use http_body_util::Full;
use hyper::body::Incoming;
use hyper::server::conn::http2::Builder as Http2Builder;
use hyper::service::service_fn;
use hyper::{Request, Response};
use hyper_util::rt::{TokioExecutor, TokioIo};
use tokio::net::TcpListener;
use tokio_rustls::TlsAcceptor;

use observer::{
    decode_headers, Frame, FrameHeader, Item, Mode, ObservedIo, Observer, Policy, PREFACE,
};

/// Pass-through allocator that counts allocations, so Q5 can report allocations per operation
/// instead of estimating them. Every allocation still comes from the system allocator; only the
/// bookkeeping is ours.
struct Counting;
static ALLOCS: AtomicU64 = AtomicU64::new(0);
static ALLOC_BYTES: AtomicU64 = AtomicU64::new(0);

unsafe impl std::alloc::GlobalAlloc for Counting {
    unsafe fn alloc(&self, layout: std::alloc::Layout) -> *mut u8 {
        let p = unsafe { std::alloc::System.alloc(layout) };
        if !p.is_null() {
            ALLOCS.fetch_add(1, Ordering::Relaxed);
            ALLOC_BYTES.fetch_add(layout.size() as u64, Ordering::Relaxed);
        }
        p
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: std::alloc::Layout) {
        unsafe { std::alloc::System.dealloc(ptr, layout) }
    }
}

#[global_allocator]
static GLOBAL: Counting = Counting;

/// Command line.
#[derive(Clone, Debug)]
struct Args {
    listen: String,
    cert: Option<String>,
    key: Option<String>,
    rules: Vec<String>,
    selftest: bool,
    iters: u64,
    connections: u64,
    max_seconds: u64,
    dump_frames: bool,
}

impl Default for Args {
    fn default() -> Self {
        Args {
            listen: "127.0.0.1:18443".to_string(),
            cert: None,
            key: None,
            rules: Vec::new(),
            selftest: false,
            iters: 20_000,
            connections: 1,
            max_seconds: 30,
            dump_frames: false,
        }
    }
}

fn usage() {
    eprintln!(
        "usage: frameprobe [options]\n\
         \n\
         \x20 --selftest            run the offline framing/violation/cost suite and exit\n\
         \x20 --iters N             iterations for the cost measurement (default 20000)\n\
         \x20 --listen ADDR:PORT    TLS listener (default 127.0.0.1:18443)\n\
         \x20 --tls-cert FILE       certificate (PEM)\n\
         \x20 --tls-key FILE        private key (PEM)\n\
         \x20 --rule SPEC           repeatable; see policy_from_rules() for the vocabulary\n\
         \x20 --connections N       accept N connections then exit (default 1)\n\
         \x20 --max-seconds N       stop after N seconds even if fewer connections arrived\n\
         \x20 --dump-frames         print the observed frame log for each connection\n\
         \n\
         rules: enforce | observe | allow=TYPE[,TYPE] | max-frame=N | padded=reject|allow\n\
                | unknown-types=reject|ignore | stream-id=odd|any | path-contains=STRING"
    );
}

impl Args {
    /// Parse argv. Hand-rolled so the experiment adds no argument-parsing crate to the lockfile.
    fn parse(argv: &[String]) -> Result<Args, String> {
        let mut a = Args::default();
        let mut i = 0;
        while i < argv.len() {
            let flag = argv[i].as_str();
            let next = |i: &mut usize| -> Result<String, String> {
                *i += 1;
                argv.get(*i).cloned().ok_or_else(|| format!("{flag} needs a value"))
            };
            match flag {
                "--selftest" => a.selftest = true,
                "--dump-frames" => a.dump_frames = true,
                "--iters" => a.iters = next(&mut i)?.parse().map_err(|e| format!("--iters: {e}"))?,
                "--listen" => a.listen = next(&mut i)?,
                "--tls-cert" => a.cert = Some(next(&mut i)?),
                "--tls-key" => a.key = Some(next(&mut i)?),
                "--rule" => a.rules.push(next(&mut i)?),
                "--connections" => {
                    a.connections = next(&mut i)?.parse().map_err(|e| format!("--connections: {e}"))?
                }
                "--max-seconds" => {
                    a.max_seconds = next(&mut i)?.parse().map_err(|e| format!("--max-seconds: {e}"))?
                }
                "-h" | "--help" => {
                    usage();
                    std::process::exit(0);
                }
                other => return Err(format!("unknown argument: {other}")),
            }
            i += 1;
        }
        Ok(a)
    }
}

/// Translate `--rule` strings into a [`Policy`].
///
/// The vocabulary mirrors what raw framing can answer (see the observer docs): mode, frame-type
/// allowlist, max frame size, padding, unknown types, stream-id parity, and one header-derived rule
/// (`path-contains`) that requires HPACK.
fn policy_from_rules(rules: &[String]) -> Result<Policy, String> {
    let mut p = Policy::default();
    for raw in rules {
        let (k, v) = match raw.find('=') {
            Some(i) => (raw[..i].to_string(), Some(raw[i + 1..].to_string())),
            None => (raw.clone(), None),
        };
        let need = || -> Result<String, String> {
            v.clone().ok_or_else(|| format!("{k} needs a value"))
        };
        match k.as_str() {
            "enforce" => p.mode = Mode::Enforce,
            "observe" => p.mode = Mode::Observe,
            "allow" => {
                let mut types = Vec::new();
                for t in need()?.split(',') {
                    let t = t.trim();
                    if t.is_empty() {
                        continue;
                    }
                    let id = match t.parse::<u8>() {
                        Ok(n) => n,
                        Err(_) => FrameHeader {
                            length: 0,
                            ftype: match t {
                                "DATA" => 0,
                                "HEADERS" => 1,
                                "PRIORITY" => 2,
                                "RST_STREAM" => 3,
                                "SETTINGS" => 4,
                                "PUSH_PROMISE" => 5,
                                "PING" => 6,
                                "GOAWAY" => 7,
                                "WINDOW_UPDATE" => 8,
                                "CONTINUATION" => 9,
                                _ => return Err(format!("allow: unknown frame type {t}")),
                            },
                            flags: 0,
                            stream_id: 0,
                        }
                        .ftype,
                    };
                    types.push(id);
                }
                p.allowed_types = Some(types);
            }
            "max-frame" => p.max_frame = need()?.parse().map_err(|e| format!("max-frame: {e}"))?,
            "padded" => {
                p.reject_padded = match need()?.as_str() {
                    "reject" => true,
                    "allow" => false,
                    other => return Err(format!("padded: unknown value {other}")),
                }
            }
            "unknown-types" => {
                p.reject_unknown_types = match need()?.as_str() {
                    "reject" => true,
                    "ignore" => false,
                    other => return Err(format!("unknown-types: unknown value {other}")),
                }
            }
            "stream-id" => {
                p.require_odd_stream_id = match need()?.as_str() {
                    "odd" => true,
                    "any" => false,
                    other => return Err(format!("stream-id: unknown value {other}")),
                }
            }
            "path-contains" => p.path_contains = Some(need()?),
            other => return Err(format!("unknown rule: {other}")),
        }
    }
    Ok(p)
}

fn main() -> Result<(), Box<dyn Error>> {
    let argv: Vec<String> = std::env::args().skip(1).collect();
    let args = Args::parse(&argv).map_err(|e| {
        usage();
        e
    })?;

    if args.selftest {
        run_selftest(&args)?;
        return Ok(());
    }

    let rt = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()?;
    rt.block_on(run_server(&args))
}

/// A synthetic client-to-server stream: preface, SETTINGS, one HEADERS block, one DATA frame.
///
/// The HEADERS payload uses HPACK *indexed* representations only (0x82 `:method: GET`, 0x84
/// `:path: /`, 0x86 `:scheme: http`), which is the cheapest way to build a valid block without
/// depending on an encoder for the fixture.
fn synthetic_stream() -> Vec<u8> {
    let mut v = Vec::new();
    v.extend_from_slice(PREFACE);
    // SETTINGS: one parameter, MAX_FRAME_SIZE (0x5) = 16384.
    v.extend_from_slice(&Frame::bytes(4, 0x00, 0, &[0x00, 0x05, 0x00, 0x00, 0x40, 0x00]));
    // HEADERS, END_HEADERS, stream 1.
    v.extend_from_slice(&Frame::bytes(1, 0x04, 1, &[0x82, 0x84, 0x86]));
    // DATA, END_STREAM, stream 1.
    v.extend_from_slice(&Frame::bytes(0, 0x01, 1, b"hello"));
    v
}

/// A HEADERS block with a literal `:path` value (no Huffman), for the path-rule cases.
fn headers_block_path(path: &str) -> Vec<u8> {
    let mut v = Vec::new();
    // 0b0100_xxxx: literal header field without indexing, 4-bit name index = 4 (`:path`).
    v.push(0x44);
    // Literal value: no Huffman flag, 7-bit length. Only correct for paths shorter than 128 bytes,
    // which every fixture here is.
    assert!(path.len() < 128, "fixture paths must be shorter than 128 bytes");
    v.push(path.len() as u8);
    v.extend_from_slice(path.as_bytes());
    v
}

/// One entry in the violation matrix: a policy, a crafted frame, and the rule it must produce.
struct Case {
    name: &'static str,
    bytes: Vec<u8>,
    expect: &'static str,
    policy: Policy,
}

/// The default policy used by most cases: enforce, no type allowlist, RFC defaults.
fn enforcing() -> Policy {
    Policy {
        mode: Mode::Enforce,
        ..Policy::default()
    }
}

/// The matrix: every framing rule the observer claims to enforce, exercised with a frame that
/// violates it, plus controls that must be accepted.
fn violation_matrix() -> Vec<Case> {
    let expect_path_rule = if cfg!(feature = "hpack") {
        "path-contains"
    } else {
        // Without the decoder the observer can still see the bytes but cannot name the header, so
        // the honest outcome is an hpack error rather than a silent pass.
        "hpack-error"
    };

    vec![
        Case {
            name: "DATA-stream0",
            bytes: Frame::bytes(0, 0x01, 0, b"x"),
            expect: "DATA-bad-stream-id",
            policy: enforcing(),
        },
        Case {
            name: "PING-length7",
            bytes: Frame::bytes(6, 0x00, 0, b"1234567"),
            expect: "PING-bad-length",
            policy: enforcing(),
        },
        Case {
            name: "PING-stream1",
            bytes: Frame::bytes(6, 0x00, 1, b"12345678"),
            expect: "PING-bad-stream-id",
            policy: enforcing(),
        },
        Case {
            name: "SETTINGS-stream1",
            bytes: Frame::bytes(4, 0x00, 1, &[]),
            expect: "SETTINGS-bad-stream-id",
            policy: enforcing(),
        },
        Case {
            name: "SETTINGS-length7",
            bytes: Frame::bytes(4, 0x00, 0, &[0u8; 7]),
            expect: "SETTINGS-bad-length",
            policy: enforcing(),
        },
        Case {
            name: "SETTINGS-ACK-with-payload",
            bytes: Frame::bytes(4, 0x01, 0, &[0u8; 6]),
            expect: "SETTINGS-ACK-with-payload",
            policy: enforcing(),
        },
        Case {
            name: "HEADERS-empty",
            bytes: Frame::bytes(1, 0x04, 1, &[]),
            expect: "HEADERS-empty",
            policy: enforcing(),
        },
        Case {
            name: "PRIORITY-length4",
            bytes: Frame::bytes(2, 0x00, 1, &[0u8; 4]),
            expect: "PRIORITY-bad-length",
            policy: enforcing(),
        },
        Case {
            name: "RST_STREAM-length3",
            bytes: Frame::bytes(3, 0x00, 1, &[0u8; 3]),
            expect: "RST_STREAM-bad-length",
            policy: enforcing(),
        },
        Case {
            name: "GOAWAY-length7",
            bytes: Frame::bytes(7, 0x00, 0, &[0u8; 7]),
            expect: "GOAWAY-bad-length",
            policy: enforcing(),
        },
        Case {
            name: "PUSH_PROMISE-stream0",
            bytes: Frame::bytes(5, 0x04, 0, &[0u8; 4]),
            expect: "PUSH_PROMISE-bad-stream-id",
            policy: enforcing(),
        },
        // Control: a connection-level WINDOW_UPDATE (stream 0) is legal and must not be flagged.
        Case {
            name: "WINDOW_UPDATE-connection-control",
            bytes: Frame::bytes(8, 0x00, 0, &[0u8; 4]),
            expect: "",
            policy: enforcing(),
        },
        Case {
            name: "WINDOW_UPDATE-length3",
            bytes: Frame::bytes(8, 0x00, 1, &[0u8; 3]),
            expect: "WINDOW_UPDATE-bad-length",
            policy: enforcing(),
        },
        Case {
            name: "WINDOW_UPDATE-even-stream",
            bytes: Frame::bytes(8, 0x00, 4, &[0u8; 4]),
            expect: "even-client-stream-id",
            policy: enforcing(),
        },
        Case {
            name: "unknown-frame-type",
            bytes: Frame::bytes(99, 0x00, 1, b"x"),
            expect: "unknown-frame-type",
            policy: enforcing(),
        },
        Case {
            name: "unknown-frame-type-ignored",
            bytes: Frame::bytes(99, 0x00, 1, b"x"),
            expect: "",
            policy: Policy {
                mode: Mode::Enforce,
                reject_unknown_types: false,
                ..Policy::default()
            },
        },
        Case {
            name: "frame-type-not-allowed",
            bytes: Frame::bytes(6, 0x00, 0, b"12345678"),
            expect: "frame-type-not-allowed",
            policy: Policy {
                mode: Mode::Enforce,
                allowed_types: Some(vec![4, 1, 0]),
                ..Policy::default()
            },
        },
        Case {
            name: "frame-too-large",
            bytes: Frame::bytes(1, 0x04, 1, &vec![0x82u8; 16385]),
            expect: "frame-too-large",
            policy: enforcing(),
        },
        Case {
            name: "even-client-stream-id",
            bytes: Frame::bytes(1, 0x04, 2, &[0x82, 0x84, 0x86]),
            expect: "even-client-stream-id",
            policy: enforcing(),
        },
        Case {
            name: "stream-id-not-increasing",
            bytes: [
                Frame::bytes(1, 0x04, 1, &[0x82, 0x84, 0x86]),
                Frame::bytes(1, 0x04, 1, &[0x82, 0x84, 0x86]),
            ]
            .concat(),
            expect: "stream-id-not-increasing",
            policy: enforcing(),
        },
        Case {
            name: "CONTINUATION-without-block",
            bytes: Frame::bytes(9, 0x04, 1, &[0x82]),
            expect: "CONTINUATION-without-block",
            policy: enforcing(),
        },
        Case {
            name: "HEADERS-while-block-open",
            bytes: [
                Frame::bytes(1, 0x00, 1, &[0x82, 0x84, 0x86]), // opens a block (no END_HEADERS)
                Frame::bytes(1, 0x04, 3, &[0x82, 0x84, 0x86]), // second HEADERS before CONTINUATION
            ]
            .concat(),
            expect: "HEADERS-while-block-open",
            policy: enforcing(),
        },
        Case {
            name: "DATA-bad-padding",
            bytes: Frame::bytes(0, 0x08, 1, &[0x05, b'A']),
            expect: "DATA-bad-padding",
            policy: enforcing(),
        },
        Case {
            name: "HEADERS-padded-rejected",
            // PADDED HEADERS: pad-length byte (2), the header block, then 2 padding bytes. Using
            // the bare block here would be a malformed frame (the pad length would read 0x44=68),
            // which the observer correctly reports as bad padding before it ever reaches the policy.
            bytes: Frame::bytes(1, 0x0C, 1, &[0x02, 0x82, 0x84, 0x86, 0x00, 0x00]),
            expect: "HEADERS-padded",
            policy: Policy {
                mode: Mode::Enforce,
                reject_padded: true,
                ..Policy::default()
            },
        },
        Case {
            name: "control-valid-headers",
            bytes: Frame::bytes(1, 0x04, 1, &[0x82, 0x84, 0x86]),
            expect: "",
            policy: enforcing(),
        },
        Case {
            name: "path-contains-match",
            bytes: Frame::bytes(1, 0x04, 1, &headers_block_path("/h2probe-12345")),
            expect: expect_path_rule,
            policy: Policy {
                mode: Mode::Enforce,
                path_contains: Some("/h2probe-".to_string()),
                ..Policy::default()
            },
        },
        Case {
            name: "path-contains-miss",
            bytes: Frame::bytes(1, 0x04, 1, &headers_block_path("/index.html")),
            expect: "",
            policy: Policy {
                mode: Mode::Enforce,
                path_contains: Some("/h2probe-".to_string()),
                ..Policy::default()
            },
        },
    ]
}


/// Run one matrix case through a fresh observer and return the rule it reported ("" if accepted).
fn run_case(policy: Policy, bytes: &[u8]) -> Result<Vec<Item>, String> {
    let mut obs = Observer::new(policy);
    obs.push(PREFACE).and_then(|_| obs.push(bytes))
}

/// Offline suite: framing correctness, HPACK evidence, the violation matrix, and cost.
fn run_selftest(args: &Args) -> Result<(), Box<dyn Error>> {
    println!(
        "frameprobe selftest (Bundle Q) hpack_feature={}",
        cfg!(feature = "hpack")
    );

    // 1. Framing round-trip: the bytes the observer releases must be the bytes it was fed.
    let stream = synthetic_stream();
    let mut obs = Observer::new(Policy::default());
    let items = obs
        .push(&stream)
        .map_err(|e| format!("synthetic stream rejected in Observe mode: {e}"))?;
    let released: Vec<u8> = items.iter().flat_map(|i| i.to_bytes()).collect();
    println!(
        "[framing] {} bytes fed -> {} items: {}",
        stream.len(),
        items.len(),
        items
            .iter()
            .map(|i| i.label())
            .collect::<Vec<String>>()
            .join(" ")
    );
    println!(
        "[framing] round-trip {} bytes -> {}",
        released.len(),
        if released == stream {
            "OK (byte-identical to the input)"
        } else {
            "MISMATCH (observer would corrupt the stream)"
        }
    );

    // 2. HPACK evidence: the same bytes, decoded, are the only way to learn the header names.
    let block = [0x82u8, 0x84, 0x86];
    match decode_headers(&block) {
        Ok(headers) => println!(
            "[hpack]   HEADERS payload {:02x?} decodes to {}",
            block,
            headers
                .iter()
                .map(|(n, v)| format!("{n}={v}"))
                .collect::<Vec<String>>()
                .join(" ")
        ),
        Err(e) => println!("[hpack]   HEADERS payload {:02x?} -> {e}", block),
    }

    // 3. Violation matrix, in Enforce mode (the mode that actually refuses frames).
    let mut passed = 0usize;
    let mut failed: Vec<String> = Vec::new();
    for case in violation_matrix() {
        let result = run_case(case.policy.clone(), &case.bytes);
        let reported = match result {
            Ok(_) => String::new(),
            Err(e) => e.split(':').next().unwrap_or("").to_string(),
        };
        if reported == case.expect {
            passed += 1;
        } else {
            failed.push(format!(
                "{}: expected {:?} got {:?}",
                case.name, case.expect, reported
            ));
        }
    }
    println!(
        "[matrix]  {} cases, {} correct, {} wrong{}",
        violation_matrix().len(),
        passed,
        failed.len(),
        if failed.is_empty() {
            String::new()
        } else {
            format!(" -> {}", failed.join("; "))
        }
    );

    // 4. Cost (Q5). Three measurements, same fixture: whole-buffer feed, one-byte-at-a-time feed,
    //    and the empty-observer baseline so construction cost is not silently charged to parsing.
    let iters = args.iters;
    let policy = Policy::default();

    let a0 = ALLOCS.load(Ordering::Relaxed);
    let b0 = ALLOC_BYTES.load(Ordering::Relaxed);
    let t0 = Instant::now();
    for _ in 0..iters {
        let mut o = Observer::new(policy.clone());
        let _ = o.push(&[]);
    }
    let base = t0.elapsed().as_nanos() as u64 / iters.max(1);
    let base_allocs = (ALLOCS.load(Ordering::Relaxed) - a0) / iters.max(1);
    let base_bytes = (ALLOC_BYTES.load(Ordering::Relaxed) - b0) / iters.max(1);

    let a1 = ALLOCS.load(Ordering::Relaxed);
    let b1 = ALLOC_BYTES.load(Ordering::Relaxed);
    let t1 = Instant::now();
    for _ in 0..iters {
        let mut o = Observer::new(policy.clone());
        o.push(&stream).expect("whole-buffer push");
    }
    let whole = t1.elapsed().as_nanos() as u64 / iters.max(1);
    let whole_allocs = (ALLOCS.load(Ordering::Relaxed) - a1) / iters.max(1);
    let whole_bytes = (ALLOC_BYTES.load(Ordering::Relaxed) - b1) / iters.max(1);

    let a2 = ALLOCS.load(Ordering::Relaxed);
    let b2 = ALLOC_BYTES.load(Ordering::Relaxed);
    let t2 = Instant::now();
    for _ in 0..iters {
        let mut o = Observer::new(policy.clone());
        for byte in stream.chunks(1) {
            o.push(byte).expect("fragmented push");
        }
    }
    let frag = t2.elapsed().as_nanos() as u64 / iters.max(1);
    let frag_allocs = (ALLOCS.load(Ordering::Relaxed) - a2) / iters.max(1);
    let frag_bytes = (ALLOC_BYTES.load(Ordering::Relaxed) - b2) / iters.max(1);

    // How many bytes the observer has to hold when it is fed one byte at a time: the preface is
    // released at 24 bytes, then each frame is held until its last payload byte arrives.
    let mut probe = Observer::new(policy.clone());
    for byte in stream.chunks(1) {
        let _ = probe.push(byte);
    }
    let frag_buffered = probe.stats.max_buffered_bytes;

    println!(
        "[cost]    iters={iters} fixture={} bytes\n\
         \x20 baseline (construct + empty push): {base} ns/op, {base_allocs} allocs/op, {base_bytes} bytes/op\n\
         \x20 whole-buffer push:                 {whole} ns/op, {whole_allocs} allocs/op, {whole_bytes} bytes/op\n\
         \x20 one-byte-at-a-time push:           {frag} ns/op, {frag_allocs} allocs/op, {frag_bytes} bytes/op\n\
         \x20 fragmentation factor: {}x slower than whole-buffer (observer holds {} bytes while a frame is incomplete)",
        stream.len(),
        if whole == 0 {
            "n/a".to_string()
        } else {
            let x10 = frag * 10 / whole;
            format!("{}\u{2e}{}", x10 / 10, x10 % 10)
        },
        frag_buffered
    );
    Ok(())
}

/// rustls server config for the experiment listener.
///
/// ALPN advertises **only** `h2`: this listener exists to serve HTTP/2, and advertising
/// `http/1.1` as well would let a client negotiate a protocol this binary then refuses to parse.
fn build_server_config(cert: &str, key: &str) -> Result<rustls::ServerConfig, String> {
    let provider = rustls::crypto::ring::default_provider();
    let mut cert_reader =
        BufReader::new(File::open(cert).map_err(|e| format!("{cert}: {e}"))?);
    let certs: Vec<rustls::pki_types::CertificateDer<'static>> = rustls_pemfile::certs(&mut cert_reader)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| format!("{cert}: {e}"))?;
    if certs.is_empty() {
        return Err(format!("{cert}: no certificates found"));
    }
    let mut key_reader = BufReader::new(File::open(key).map_err(|e| format!("{key}: {e}"))?);
    let key = rustls_pemfile::private_key(&mut key_reader)
        .map_err(|e| format!("{key}: {e}"))?
        .ok_or_else(|| format!("{key}: no private key found"))?;
    let mut config = rustls::ServerConfig::builder_with_provider(provider.into())
        .with_safe_default_protocol_versions()
        .map_err(|e| format!("builder: {e}"))?
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .map_err(|e| format!("with_single_cert: {e}"))?;
    config.alpn_protocols = vec![b"h2".to_vec()];
    Ok(config)
}

/// Lock a shared observer without panicking if another thread panicked while holding it.
fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|e| e.into_inner())
}

/// Server mode: terminate TLS, run hyper's HTTP/2 server on top of the observer, report.
async fn run_server(args: &Args) -> Result<(), Box<dyn Error>> {
    let policy = policy_from_rules(&args.rules)?;
    let cert = args
        .cert
        .clone()
        .ok_or("--tls-cert is required unless --selftest is used")?;
    let key = args
        .key
        .clone()
        .ok_or("--tls-key is required unless --selftest is used")?;
    let acceptor = TlsAcceptor::from(Arc::new(build_server_config(&cert, &key)?));
    let listener = TcpListener::bind(&args.listen)
        .await
        .map_err(|e| format!("bind {}: {e}", args.listen))?;

    println!(
        "frameprobe listening on {} mode={} rules={:?} hpack_feature={}",
        args.listen,
        if policy.mode == Mode::Enforce { "enforce" } else { "observe" },
        args.rules,
        cfg!(feature = "hpack")
    );

    let deadline = Instant::now() + Duration::from_secs(args.max_seconds);
    let mut n = 0u64;
    while n < args.connections {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            eprintln!("frameprobe: --max-seconds reached after {n} connections");
            break;
        }
        let (sock, peer) = match tokio::time::timeout(remaining, listener.accept()).await {
            Ok(r) => r.map_err(|e| format!("accept: {e}"))?,
            Err(_) => {
                eprintln!("frameprobe: timed out waiting for a connection after {n} connections");
                break;
            }
        };
        let tls = match acceptor.accept(sock).await {
            Ok(t) => t,
            Err(e) => {
                eprintln!("connection={n} tls_handshake=error error={e}");
                n += 1;
                continue;
            }
        };
        // `TlsStream::get_ref()` gives (&io, &CommonState); the negotiated ALPN comes from
        // CommonState, and printing it is how the report proves the client really negotiated h2.
        let negotiated = tls
            .get_ref()
            .1
            .alpn_protocol()
            .map(|p| String::from_utf8_lossy(p).to_string());
        let served = Arc::new(AtomicU64::new(0));
        let obs = Arc::new(Mutex::new(Observer::new(policy.clone())));
        let io = ObservedIo::new(tls, obs.clone());

        let counter = served.clone();
        let service = service_fn(move |_req: Request<Incoming>| {
            let counter = counter.clone();
            async move {
                counter.fetch_add(1, Ordering::Relaxed);
                Ok::<_, hyper::Error>(
                    Response::builder()
                        .status(200)
                        .header("x-frameprobe", "1")
                        .body(Full::new(Bytes::from("frameprobe-ok")))
                        .unwrap(),
                )
            }
        });

        let result = Http2Builder::new(TokioExecutor::new())
            .serve_connection(TokioIo::new(io), service)
            .await;
        let stats = lock(&obs).stats.clone();
        let frame_log = lock(&obs).frame_log.clone();
        println!(
            "connection={n} peer={peer} alpn={} served={} http2={} {}",
            negotiated.unwrap_or_else(|| "-".to_string()),
            served.load(Ordering::Relaxed),
            if result.is_ok() { "ok" } else { "error" },
            stats.summary()
        );
        if let Err(e) = result {
            println!("connection={n} abort_reason={e}");
        }
        if args.dump_frames {
            println!("connection={n} frames={}", frame_log.join(" "));
        }
        n += 1;
    }
    Ok(())
}
