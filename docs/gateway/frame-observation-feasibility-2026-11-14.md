# Bundle Q - HTTP/2 frame observation feasibility (2026-11-14)

Answers Q1-Q7 from the Stage 2 handoff for the **frame observation spike**. The spike is an
experiment, not a product: its standing constraint is that the observer must not become an
unproven dependency of the proxy, and a fork of `h2`/`hyper` needs a proven capability gap.

Evidence sources (all on `build01.lab`, the host that runs the vulnerable
`mod_http2-2.0.26` stack, so it is the host the gateway would protect):

| Artifact | Location |
| --- | --- |
| Observer library | `tests/gateway/frameprobe/src/observer.rs` |
| Experiment driver (selftest + TLS server) | `tests/gateway/frameprobe/src/main.rs` |
| EL8 build recipe | `tests/gateway/frameprobe/Containerfile` |
| Binary under test | `/home/agent/frameprobe`, sha256 `78fed82f397018f925f2a02e1402985017a0da7408ffc669b65409c5d1d6b5f1`, 3,143,648 bytes, rustc 1.92.0 / glibc 2.28 |
| Live scenario harness | `tests/gateway/q_live_matrix.sh` |
| Raw live output | `/tmp/q_live_results3.txt` (reproduced inline in Q3) |
| HTTP/2 client used | `tests/gateway/h2probe` (`/tmp/h2probe`), one TLS connection, 4 or 8 streams |

Reproduce:

```sh
# offline: framing round-trip, violation matrix, cost model
/home/agent/frameprobe --selftest --iters 20000

# live: five policy scenarios against a real h2 client
bash tests/gateway/q_live_matrix.sh /home/agent/frameprobe /tmp/h2probe /tmp/gw-test.crt /tmp/gw-test.key
```

Current selftest status: `27 cases, 27 correct, 0 wrong`, round-trip byte-identical, HPACK decode
verified, cost model emitted.

---

## Q1 - Where decrypted HTTP/2 input can be observed before hyper consumes it

There are exactly two insertion points, and only one of them is before the parser:

1. **The byte stream** (implemented). `hyper::server::conn::http2::Builder::serve_connection`
   accepts any `AsyncRead + AsyncWrite`, so `ObservedIo<T>` wraps the decrypted TLS stream and
   hands hyper bytes only after the frame they belong to has been validated. The gateway already
   passes a `TlsStream` through `TokioIo`, so this needs no change to hyper's API surface.
2. **The parsed event stream** (`h2::server::Server::handshake` -> `read_reply`). By the time an
   event exists, the h2 codec - the component `CVE-2026-119618` lives in - has already run. This
   is post-parse telemetry and cannot prevent a parser crash.

Proof the wrapper is faithful rather than lossy: the selftest feeds a 65-byte connection
(preamble + SETTINGS + HEADERS + DATA) and asserts the bytes released to the consumer are
byte-identical to the input (`round-trip 65 bytes -> OK`). Live scenario A below serves four
requests through the wrapper with `http2=ok`, i.e. hyper accepted the connection normally with the
observer in the path.

Answer: the byte stream is the only pre-parser location, and reaching it does **not** require a
fork.

## Q2 - Which raw frame properties are accessible

| Property | Source | How verified |
| --- | --- | --- |
| Length, type, flags, stream id | 9-byte frame header | selftest round-trip; live frame log (`HEADERS(len=14,flags=END_STREAM\|END_HEADERS,id=1)`) |
| Flag names, including unassigned bits | flags byte | live log renders `ACK`, `END_HEADERS`, and raw `0x..` when bits are unassigned |
| Connection preface presence/validity | first 24 bytes | live `preface=1` in every scenario |
| Frame type validity (defined vs unknown) | type byte | matrix case `unknown-frame-type`, plus the `reject_unknown_types` policy switch (matrix case `unknown-frame-type-ignored`) |
| Per-type length rules (PRIORITY=5, RST_STREAM=4, PING=8, GOAWAY>=8, PUSH_PROMISE>=4, WINDOW_UPDATE=4, SETTINGS%6, HEADERS!=0) | header only | 9 matrix cases, one per rule |
| Padding presence, pad length, padding fits the payload | first payload byte (types 0, 1, 2, 5) | matrix cases `DATA-bad-padding`, `HEADERS-padded-rejected` |
| Header block boundaries (END_HEADERS / CONTINUATION pairing) | flags + observer state | matrix cases `CONTINUATION-without-block`, `HEADERS-while-block-open` |
| Stream id ordering and client parity | header + observer state | matrix cases `even-client-stream-id`, `stream-id-not-increasing` |
| SETTINGS values (all six defined ids plus unknown ids) | payload parse | live `settings[ENABLE_PUSH=0,INITIAL_WINDOW_SIZE=2097152,MAX_FRAME_SIZE=16384,MAX_HEADER_LIST_SIZE=16384]` |
| WINDOW_UPDATE increment (signed 31-bit) | payload parse | live `window_update=Some(5177345)` |
| RST_STREAM error code | payload parse | summary field `rst_code` |
| Max bytes buffered (framing cost) | observer state | live `buffered=0`; selftest reports 23 bytes held mid-frame |

## Q3 - Can an observation synchronously reject or halt processing, or is it read-only?

It can halt, at frame granularity. `poll_read` returns an `io::Error` (or simply withholds the
bytes) the moment a frame is refused; hyper aborts the connection and never produces a request
object for the refused frame. The measurable signature is `served=0` on the listener side while the
frame is visible in the frame log.

Live matrix (single connection per scenario, `--dump-frames`, client = h2probe):

| Scenario | Policy | Listener | Client |
| --- | --- | --- | --- |
| A-observe | `observe` | `served=4 http2=ok frames=7 by_type[HEADERS=4,SETTINGS=2,WINDOW_UPDATE=1] violations[] hpack_ok=4` | 4x `status=200` |
| B-enforce-permissive | `enforce`, allowlist = every frame type | `served=4 http2=ok frames=7 violations[]` | 4x `status=200` |
| C-enforce-no-headers | `enforce`, allowlist = everything **except** HEADERS | `served=0 http2=error frames=4 violations[frame-type-not-allowed=1] abort_reason=connection error` | 4x `error=request ...: connection error` |
| D-enforce-path-hit | `enforce`, `path-contains=/h2probe-` | `served=0 http2=error frames=4 violations[path-contains=1] hpack_ok=1 abort_reason=connection error` | 4x `error=request ...: connection error` |
| E-enforce-path-miss | same policy as D, path `/index.html` | `served=4 http2=ok frames=7 violations[] hpack_ok=4` | 4x `status=200` |

Reading of the table:

- **B is the important control.** Enforcement with a policy that matches everything the peer
  legitimately sends is transparent (`served=4`, no violations). The first version of this scenario
  allowed only `SETTINGS,HEADERS,DATA` and therefore refused a perfectly legal `WINDOW_UPDATE`; a
  policy that does not name every type the peer sends breaks real clients, and only the live run
  exposed it. Two more bugs of the same class were fixed the same way (see "Findings" below).
- **C and D are the enforcement proof.** A frame that exists on the wire produced no request and no
  response (`served=0`, client sees `connection error`). D additionally proves the decision was
  made on a header *value*: `hpack_ok=1` means the header block was decoded, `:path` matched the
  CVE-2026-119618 PoC pattern, and the frame was refused before hyper built a request.
- **E is the false-positive control**: same policy, non-matching path, four normal responses.
- `http2=error` in C and D is the expected signature of a refusal, not a crash; A, B and E report
  `http2=ok`.

Limits of that halt, stated precisely:

- The unit of refusal is the **connection**, not the stream. Refusing one HEADERS frame killed all
  four multiplexed streams. A gateway that wants to tarpit one request and keep the connection
  alive has to act at the HTTP layer, where it can answer a single stream.
- A frame is released whole, so a HEADERS block split across CONTINUATION frames can only be judged
  once END_HEADERS arrives. That is still before hyper parses it, but after the bytes have arrived.
- Bytes already handed to hyper cannot be un-delivered; the wrapper can only withhold what it has
  not yet released.
- The observer validates framing rules, not h2's implementation-specific acceptance (see Q6).

## Q4 - What requires HPACK versus raw framing versus stream state

| Needs | Examples | Evidence |
| --- | --- | --- |
| Raw framing only | type, flags, length, stream id, padding structure, per-type length rules, frame-type validity | Q2 table |
| HPACK | every header name and value: `:method`, `:path`, `:scheme`, `:authority`, and any custom header such as `X-Tarpit-Signature` | the 3-byte payload `[82,84,86]` decodes to `:method=GET :path=/ :scheme=http`; without a decoder those bytes carry no name at all |
| Stream state | open / half-closed tracking, stream id monotonicity, CONTINUATION block membership | matrix cases `stream-id-not-increasing`, `HEADERS-while-block-open` |
| The peer's own SETTINGS (to validate frame size correctly) | `MAX_FRAME_SIZE` from the *server* SETTINGS | not visible from the read side at all - the observer only sees the client's SETTINGS (see Q6) |

Cost note: `hpack` 0.3.0 works (feature-gated `hpack` in `tests/gateway/frameprobe/Cargo.toml`),
but it is a 2017-era crate and `h2`'s own decoder is private. Pre-parse header inspection therefore
means carrying a second HPACK implementation, or forking `h2` purely to expose its decoder. That is
the real price of "own the framing", not the framing code itself.

## Q5 - Cost of the observer

Selftest, 20,000 iterations over a 65-byte fixture (preamble + SETTINGS + HEADERS + DATA):

| Mode | ns/op | allocs/op | bytes/op |
| --- | --- | --- | --- |
| Baseline (construct observer + empty push) | 61-101 | 0 | 0 |
| Whole-buffer push | 2,135-2,748 | 46 | 1,626 |
| One byte at a time | 3,051-3,272 | 51 | 2,097 |

- Fragmentation factor 1.1-1.2x (one-byte feed vs whole-buffer feed), with 23 bytes held while a
  frame is incomplete. Cost scales with **frames**, not bytes: ~33-42 ns per input byte on the
  fixture, dominated by 46 allocations per 65-byte feed (the per-frame `Vec` plus re-serialising the
  header into the read buffer). That is the thing worth optimising before any production use.
- Process footprint: frameprobe RSS 4,028 kB vs gateway RSS 3,532 kB on the same host. The 496 kB
  delta includes the observer *and* the different feature set, so it is not a clean isolation of
  observer RSS; treat it as an upper bound for "observer plus its own hyper/rustls binary".
- Caveats: one small fixture, one connection, no TLS cost included (the measurement loop excludes
  the handshake), and no response-side work.

## Q6 - Limits statement: what this can and cannot prove

Can prove: the exact bytes the client sent, in order; whether each frame was legal per RFC 9113
structure; and that a refused frame produced no request (`served=0`).

Cannot prove:

1. **Anything about the server-to-client direction** - responses, the server's SETTINGS, push. The
   observer counts written bytes only. Parsing writes would mean buffering responses, which breaks
   streaming responses.
2. **Whether the request was semantically valid.** HTTP semantics live above framing: method and
   path validation, duplicate headers, pseudo-header ordering, "malformed request" rules. hyper
   enforces those; a framing observer cannot see them without reimplementing them.
3. **Whether the h2 parser itself would have accepted the bytes.** The observer checks RFC framing
   rules; h2 has implementation-specific acceptance. "Observer accepted it" is not "h2 will not
   crash", which matters because the whole point of Stage 2 is surviving parser flaws.
4. **Pre-parser protection for bodies.** h2 can deliver a partial DATA payload to a body stream
   before the frame completes, so only the header block is strictly pre-parser.
5. **Correct frame-size validation** without the server's own SETTINGS (item 1).
6. **Per-stream rejection.** A frame-level refusal is a connection-level action (Q3).

## Q7 - Decision: fork, vendor, or keep the current pattern

**Recommendation: no fork, and do not make the observer a dependency of the basic proxy yet. Keep
frame-level telemetry as an opt-in capability and keep enforcement in the request path, which the
gateway already has.**

Reasoning:

- The bundle's own test is "does it prove a specific capability gap that justifies maintaining a
  fork". It does not: hyper accepts any `AsyncRead`, so pre-parse observation is available without
  touching the crate. Forking the codec would buy nothing that the wrapper did not already provide.
- The two gaps that *do* exist are cheaper to fix elsewhere. HPACK reuse is a visibility problem in
  `h2` (its decoder is private) that costs either a second HPACK implementation or a fork purely for
  visibility. Per-stream action - answering one stream while keeping the connection - is not a
  framing problem at all; it is the HTTP layer, where the gateway already has the parsed request and
  can serve a tarpit response.
- Therefore the shape to adopt is: **frame-level observation = telemetry and policy input** (frame
  log, violation counters, SETTINGS/window capture), **request-path handling = enforcement**. That
  keeps the proven gateway behaviour and keeps the unproven part optional.
- Explicitly deferred, and it should be its own bundle with its own evidence: making the observer
  *answer* the offending stream (a tarpit response generated from the frame layer). That requires
  generating frames in the write direction, i.e. becoming an h2 endpoint rather than a wrapper, and
  that is the only design that would genuinely justify owning the framing.
- Also deferred: the observer's allocation profile (Q5) should be fixed before it is put in front of
  a real listener, and the `Policy` surface needs a documented allowlist of frame types a real
  client sends (the Q3 finding) rather than a hand-written list.

## Findings fixed during the run (kept for the record)

All three were found by running the harness, not by reading the code - which is the argument for
measuring rather than reasoning about framing:

1. **Legal connection-level WINDOW_UPDATE was reported as a violation.** The stream-id predicate
   classified type 8 as stream-only, but RFC 9113 allows it to name stream 0. Fixed by splitting
   frame classification into `is_connection_only` / `is_stream_level` on `FrameHeader` (previously an
   inline match in `check_frame`) and excluding WINDOW_UPDATE from the stream-level set, plus a
   dedicated control case so the regression cannot come back silently.
2. **`frames=0` in observe mode.** `frames_total` was incremented only on the reject paths, so a
   clean connection reported zero frames while `by_type` was populated. Fixed by moving the
   increment into `Stats::count_frame`.
3. **`--rule=allow=...` was rejected.** The argument parser only accepted the two-token form
   `--rule VALUE`, so the matrix script's `--rule=...` form printed usage and exited 2. Fixed in the
   script; the parser's single-token form remains unsupported deliberately (one parser, one syntax).
