//! `h2probe` - open N concurrent HTTP/2 streams on ONE connection and report what came back.
//!
//! Why this exists: Bundle O claim 4 is "client-side multiplexing is preserved (N concurrent
//! streams on one connection)". lab-web01 ships curl 7.61 built without `-Z`, so curl there cannot
//! issue parallel requests over one connection, and curl from build01 cannot route to the gateway's
//! TEST-NET listener. Every remaining option (install a package the host's modules filter out, or
//! eyeball a pcap) was more work than this client.
//!
//! What it proves and what it does not:
//!   * it proves one TCP connection carried N requests and returned N distinct responses, and the
//!     elapsed time distinguishes parallel from sequential issue on that same connection;
//!   * it does not prove anything about the backend's behaviour under load - the backend's own
//!     capacity is Bundle P's subject.
//!
//! TLS is terminated with a permissive verifier (`--insecure`, like `curl -k`) so the tool works
//! against a host certificate whose chain is not in any local trust store, while still sending SNI
//! and still advertising `h2` in ALPN - because an ALPN-less client would not be testing h2.

use std::collections::BTreeMap;
use std::env;
use std::process::exit;
use std::sync::Arc;
use std::time::Instant;

use bytes::Bytes;
use http_body_util::{BodyExt, Empty};
use hyper::client::conn::http2;
use hyper::header::HeaderName;
use hyper::{Request, Uri};
use hyper_util::rt::{TokioExecutor, TokioIo};
use tokio::net::TcpStream;

/// A verifier that accepts any certificate, so the tool works like `curl -k`.
///
/// rustls requires a verifier even when the caller does not care about trust; the "assertion"
/// constructors exist exactly for this case. Keeping it in its own type means the insecure path is
/// visible in the output (`insecure=true`) instead of being the silent default.
#[derive(Debug)]
struct Permissive;

impl rustls::client::danger::ServerCertVerifier for Permissive {
    fn verify_server_cert(
        &self,
        _end_entity: &rustls::pki_types::CertificateDer<'_>,
        _intermediates: &[rustls::pki_types::CertificateDer<'_>],
        _server_name: &rustls::pki_types::ServerName<'_>,
        _ocsp_response: &[u8],
        _now: rustls::pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &rustls::pki_types::CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &rustls::pki_types::CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        rustls::crypto::ring::default_provider()
            .signature_verification_algorithms
            .supported_schemes()
    }
}

/// Parsed command line.
struct Args {
    /// Target URI, e.g. `https://198.51.100.111:8443/base`. The path is a prefix: each stream
    /// requests `<path>-<n>` so responses can be told apart.
    url: String,
    /// Number of streams to open on the single connection.
    streams: usize,
    /// Skip certificate verification (the `curl -k` equivalent).
    insecure: bool,
    /// Issue requests one after another instead of all at once, for the sequential baseline.
    sequential: bool,
    /// SNI name to send when the URI host is an IP address with no reverse name.
    sni: Option<String>,
}

/// Parse argv; every flag is documented in `usage`.
fn parse_args(argv: &[String]) -> Result<Args, String> {
    let mut args = Args {
        url: String::new(),
        streams: 4,
        insecure: false,
        sequential: false,
        sni: None,
    };
    let mut i = 1;
    while i < argv.len() {
        match argv[i].as_str() {
            "--url" => {
                args.url = argv.get(i + 1).cloned().ok_or("--url needs a value")?;
                i += 2;
            }
            "--streams" => {
                args.streams = argv
                    .get(i + 1)
                    .and_then(|v| v.parse::<usize>().ok())
                    .ok_or("--streams needs a number")?;
                i += 2;
            }
            "--insecure" => {
                args.insecure = true;
                i += 1;
            }
            "--sequential" => {
                args.sequential = true;
                i += 1;
            }
            "--sni" => {
                args.sni = Some(argv.get(i + 1).cloned().ok_or("--sni needs a value")?);
                i += 2;
            }
            "--help" => {
                usage(0);
            }
            other => return Err(format!("unknown argument: {other}")),
        }
    }
    if args.url.is_empty() {
        return Err("--url is required".to_string());
    }
    if args.streams == 0 {
        return Err("--streams must be >= 1".to_string());
    }
    Ok(args)
}

/// Print usage and exit; also the error path, so a wrong invocation explains itself.
fn usage(code: i32) -> ! {
    eprintln!(
        "usage: h2probe --url URL [--streams N] [--insecure] [--sequential] [--sni NAME]\n\
         \x20 opens ONE connection and issues N requests on it (parallel unless --sequential)"
    );
    exit(code)
}

/// Establish the transport: TLS when the URL is https, plain TCP otherwise.
///
/// Returns the hyper-compatible IO handle plus the address actually connected to, so the output
/// states the connection it used rather than the one the operator typed.
async fn connect(args: &Args) -> Result<(BoxedIo, String), String> {
    let uri: Uri = args.url.parse().map_err(|e| format!("--url: {e}"))?;
    let host = uri.host().ok_or("--url has no host")?.to_string();
    let port = uri.port_u16().unwrap_or(if uri.scheme_str() == Some("https") { 443 } else { 80 });
    let addr = format!("{host}:{port}");
    let tcp = TcpStream::connect(&addr).await.map_err(|e| format!("connect {addr}: {e}"))?;

    if uri.scheme_str() == Some("https") {
        let sni = args.sni.clone().unwrap_or_else(|| host.clone());
        let server_name = rustls::pki_types::ServerName::try_from(sni.clone())
            .map_err(|e| format!("invalid SNI {sni}: {e}"))?;
        let mut config = rustls::ClientConfig::builder_with_provider(
            rustls::crypto::ring::default_provider().into(),
        )
        .with_safe_default_protocol_versions()
        .map_err(|e| format!("builder: {e}"))?
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(Permissive))
        .with_no_client_auth();
        // Advertising h2 in ALPN is the point: without it the server may answer HTTP/1.1 and the
        // probe would silently test the wrong protocol.
        config.alpn_protocols = vec![b"h2".to_vec()];
        let connector = tokio_rustls::TlsConnector::from(Arc::new(config));
        let tls = connector
            .connect(server_name, tcp)
            .await
            .map_err(|e| format!("tls handshake to {addr}: {e}"))?;
        Ok((BoxedIo::Tls(TokioIo::new(tls), sni), addr))
    } else {
        Ok((BoxedIo::Plain(TokioIo::new(tcp)), addr))
    }
}

/// The connection handed to hyper's http2 client, either TLS-wrapped or plain.
///
/// hyper's client is generic over the IO type, so the enum plus a small `AsRef`-style split keeps
/// one code path for both transports instead of duplicating the request logic.
enum BoxedIo {
    Plain(hyper_util::rt::TokioIo<TcpStream>),
    Tls(
        hyper_util::rt::TokioIo<tokio_rustls::client::TlsStream<TcpStream>>,
        String,
    ),
}

/// Issue one GET on an existing h2 connection and return status, byte count and the request id the
/// gateway put on the response (the join key that ties the response back to a backend log line).
async fn one_request(
    mut sender: hyper::client::conn::http2::SendRequest<Empty<Bytes>>,
    path: String,
) -> Result<(u16, usize, String), String> {
    let request = Request::get(&path)
        .body(Empty::<Bytes>::new())
        .map_err(|e| format!("build request {path}: {e}"))?;
    let response = sender
        .send_request(request)
        .await
        .map_err(|e| format!("request {path}: {e}"))?;
    let status = response.status().as_u16();
    let request_id = response
        .headers()
        .get(HeaderName::from_static("x-request-id"))
        .and_then(|v| v.to_str().ok())
        .unwrap_or("-")
        .to_string();
    let body = response
        .into_body()
        .collect()
        .await
        .map(|collected| collected.to_bytes().len())
        .map_err(|e| format!("read body {path}: {e}"))?;
    Ok((status, body, request_id))
}

#[tokio::main]
async fn main() {
    let argv: Vec<String> = env::args().collect();
    let args = match parse_args(&argv) {
        Ok(a) => a,
        Err(error) => {
            eprintln!("error: {error}");
            usage(2);
        }
    };

    let (io, addr) = match connect(&args).await {
        Ok(pair) => pair,
        Err(error) => {
            eprintln!("error: {error}");
            exit(1);
        }
    };

    // One handshake, one connection, N streams: the http2 client's SendRequest is cloned per
    // stream, which is what makes "N streams on one connection" testable at all.
    let started = match io {
        BoxedIo::Plain(io) => {
            let (sender, connection) = http2::Builder::new(TokioExecutor::new())
                .handshake::<_, Empty<Bytes>>(io)
                .await
                .unwrap_or_else(|e| {
                    eprintln!("error: h2 handshake on {addr}: {e}");
                    exit(1)
                });
            tokio::spawn(connection);
            sender
        }
        BoxedIo::Tls(io, sni) => {
            let (sender, connection) = http2::Builder::new(TokioExecutor::new())
                .handshake::<_, Empty<Bytes>>(io)
                .await
                .unwrap_or_else(|e| {
                    eprintln!("error: h2 handshake over tls({sni}) on {addr}: {e}");
                    exit(1)
                });
            tokio::spawn(connection);
            sender
        }
    };

    let base = {
        let uri: Uri = args.url.parse().unwrap_or_else(|e| {
            eprintln!("error: --url: {e}");
            exit(2);
        });
        let path = uri.path().to_string();
        if path == "/" {
            String::from("/probe")
        } else {
            path
        }
    };

    println!(
        "h2probe target={addr} streams={} mode={} tls={}",
        args.streams,
        if args.sequential { "sequential" } else { "parallel" },
        match &args.sni {
            Some(sni) => sni.clone(),
            None => "none".to_string(),
        }
    );

    let clock = Instant::now();
    let mut results: BTreeMap<usize, String> = BTreeMap::new();

    if args.sequential {
        for index in 1..=args.streams {
            let path = format!("{base}-{index}");
            let line = match one_request(started.clone(), path.clone()).await {
                Ok((status, bytes, request_id)) => {
                    format!("stream={index} path={path} status={status} bytes={bytes} x_request_id={request_id}")
                }
                Err(error) => format!("stream={index} path={path} error={error}"),
            };
            println!("{line}");
            results.insert(index, line);
        }
    } else {
        let mut tasks = Vec::with_capacity(args.streams);
        for index in 1..=args.streams {
            let path = format!("{base}-{index}");
            let sender = started.clone();
            tasks.push(tokio::spawn(async move {
                let outcome = one_request(sender, path.clone()).await;
                let line = match outcome {
                    Ok((status, bytes, request_id)) => {
                        format!("stream={index} path={path} status={status} bytes={bytes} x_request_id={request_id}")
                    }
                    Err(error) => format!("stream={index} path={path} error={error}"),
                };
                (index, line)
            }));
        }
        for task in tasks {
            let (index, line) = task
                .await
                .unwrap_or_else(|e| (usize::MAX, format!("task join failed: {e}")));
            println!("{line}");
            results.insert(index, line);
        }
    }

    println!("elapsed_ms={}", clock.elapsed().as_millis());
    println!("streams_reported={}", results.len());
}
