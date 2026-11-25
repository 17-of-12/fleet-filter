//! Bundle S3 - posture profiles and the request-level verdict they produce.
//!
//! A profile is the part of the policy that changes during a disclosure window: which methods the
//! site really serves, which header names clients legitimately send, which content types bodies
//! carry, how long a path may be, and what TLS floor is acceptable. S3's requirement is that
//! changing the posture is a *switch* rather than a code change, so the profile is data
//! ([`Profile`]) and the decision it produces for a request is a pure function ([`Profile::evaluate`])
//! with no I/O - which also makes it the one part of the gateway that can be tested exhaustively
//! without a socket.
//!
//! Two rules keep the profile honest:
//!   * an empty allowlist means **no restriction**, not "nothing is allowed". The distinction
//!     matters because a profile that accidentally ships an empty method list would 405 every
//!     request, and the operator would learn that from a support ticket rather than from the
//!     validator;
//!   * a rejection names the rule that fired (`method_not_allowed`, `path_charset`, ...). "400
//!     Bad Request" without a reason is not actionable during an incident.

use hyper::header::{HeaderMap, HeaderName};
use hyper::{Method, Uri};

use super::{toml::Document, TlsFloor};

/// The active posture profile, as declared in a policy bundle's `[posture]` table.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Profile {
    /// The profile's name (`open`, `standard`, `hardened`, `lockdown`, or a site-specific one).
    pub name: String,
    /// Allowed HTTP methods, uppercased. Empty means every method is allowed.
    pub methods: Vec<String>,
    /// Allowed request header names, lowercased. Empty means every header name is allowed.
    pub header_names: Vec<String>,
    /// Allowed media types for a request body, lowercased and without parameters. Empty means any
    /// content type is allowed.
    pub content_types: Vec<String>,
    /// Maximum path length in bytes.
    pub max_path_bytes: usize,
    /// Maximum query-string length in bytes.
    pub max_query_bytes: usize,
    /// Maximum number of `/`-separated path segments.
    pub max_path_segments: usize,
    /// Lowest TLS version the gateway will accept from a client.
    pub min_tls_version: TlsFloor,
    /// Maximum in-flight requests for one authority (per-vhost admission cap); 0 means unlimited.
    pub admission_cap_per_authority: usize,
}

/// A request that the profile refuses, with the status and rule name to report.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Rejection {
    /// Status the gateway answers with.
    pub status: hyper::StatusCode,
    /// Machine-readable rule name, also emitted as the `X-Fleet-Filter-Posture` value.
    pub rule: &'static str,
}

impl Rejection {
    /// The short body the gateway returns for a posture rejection.
    pub fn body(&self, policy_version: &str) -> String {
        format!(
            "fleet-filter-gateway\npolicy={policy_version}\nrule={}\nstatus={}\n",
            self.rule,
            self.status.as_u16()
        )
    }
}

impl Profile {
    /// Build a profile from a bundle document's `[posture]` table.
    pub fn from_document(doc: &Document) -> Result<Profile, String> {
        let name = doc.require_str("posture", "active")?;
        validate_token(&name, "posture `active`")?;
        let methods = doc.require_strs("posture", "methods")?;
        for method in &methods {
            if method.is_empty() || !method.bytes().all(|b| b.is_ascii_uppercase()) {
                return Err(format!(
                    "[posture] `methods` entry `{method}` must be an uppercase method token"
                ));
            }
        }
        let header_names: Vec<String> = doc
            .require_strs("posture", "header_names")?
            .into_iter()
            .map(|name| name.to_ascii_lowercase())
            .collect();
        for header in &header_names {
            validate_token(header, "posture `header_names`")?;
        }
        let content_types: Vec<String> = doc
            .require_strs("posture", "content_types")?
            .into_iter()
            .map(|ct| ct.to_ascii_lowercase())
            .collect();
        for content_type in &content_types {
            // `type/subtype` only; parameters (`; charset=`) are stripped at match time, not here.
            let ok = content_type.contains('/')
                && content_type
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'-' | b'+' | b'/'));
            if !ok {
                return Err(format!(
                    "[posture] `content_types` entry `{content_type}` must look like `type/subtype`"
                ));
            }
        }
        let int = |key: &str| -> Result<usize, String> {
            let raw = doc.require_int("posture", key)?;
            if raw <= 0 {
                return Err(format!(
                    "[posture] `{key}` must be greater than 0 (got {raw})"
                ));
            }
            usize::try_from(raw).map_err(|e| format!("[posture] `{key}`: {e}"))
        };
        let min_tls_version = TlsFloor::parse(&doc.require_str("posture", "min_tls_version")?)
            .ok_or_else(|| {
                "[posture] `min_tls_version` must be 1.0, 1.1, 1.2 or 1.3".to_string()
            })?;
        let cap_raw = doc.require_int("posture", "admission_cap_per_authority")?;
        if cap_raw < 0 {
            return Err(format!(
                "[posture] `admission_cap_per_authority` must be 0 or greater (got {cap_raw})"
            ));
        }

        Ok(Profile {
            name,
            methods,
            header_names,
            content_types,
            max_path_bytes: int("max_path_bytes")?,
            max_query_bytes: int("max_query_bytes")?,
            max_path_segments: int("max_path_segments")?,
            min_tls_version,
            admission_cap_per_authority: cap_raw as usize,
        })
    }

    /// Decide whether a request is acceptable under this profile.
    ///
    /// `negotiated` is the TLS version the connection negotiated; `None` means the connection is
    /// cleartext, in which case the TLS floor cannot be applied and is not faked.
    pub fn evaluate(
        &self,
        method: &Method,
        uri: &Uri,
        headers: &HeaderMap,
        negotiated: Option<TlsFloor>,
    ) -> Option<Rejection> {
        // 1. TLS floor. A client below the floor is refused before anything else is inspected:
        //    the transport itself is the disqualifying property.
        if let (Some(actual), _) = (negotiated, ()) {
            if rank(actual) < rank(self.min_tls_version) {
                return Some(Rejection {
                    status: hyper::StatusCode::FORBIDDEN,
                    rule: "tls_below_floor",
                });
            }
        }

        // 2. Method allowlist (empty = unrestricted).
        if !self.methods.is_empty() {
            let name = method.as_str().to_ascii_uppercase();
            if !self.methods.contains(&name) {
                return Some(Rejection {
                    status: hyper::StatusCode::METHOD_NOT_ALLOWED,
                    rule: "method_not_allowed",
                });
            }
        }

        // 3. Path shape. Length and segment limits catch the "one request with a 6 kB path" class
        //    of scanner traffic without needing a signature per payload.
        let path = uri.path();
        if path.len() > self.max_path_bytes {
            return Some(Rejection {
                status: hyper::StatusCode::URI_TOO_LONG,
                rule: "path_too_long",
            });
        }
        if let Some(query) = uri.query() {
            if query.len() > self.max_query_bytes {
                return Some(Rejection {
                    status: hyper::StatusCode::URI_TOO_LONG,
                    rule: "query_too_long",
                });
            }
        }
        if path.len() > 1 && path.bytes().any(|b| !(0x21..=0x7e).contains(&b)) {
            // Anything outside printable ASCII in a path is either a scanner probe or a client
            // that needs percent-encoding; either way it is not worth proxying to the backend.
            // A bare "/" is exempt because it is the one path that is always well-formed.
            return Some(Rejection {
                status: hyper::StatusCode::BAD_REQUEST,
                rule: "path_charset",
            });
        }
        let segments = path.split('/').filter(|s| !s.is_empty()).count();
        if segments > self.max_path_segments {
            return Some(Rejection {
                status: hyper::StatusCode::BAD_REQUEST,
                rule: "path_segments",
            });
        }

        // 4. Header-name allowlist (empty = unrestricted). Checked against the parsed header set,
        //    which is the gateway's advantage over raw-string matching in mod_rewrite.
        if !self.header_names.is_empty() {
            for name in headers.keys() {
                if !self
                    .header_names
                    .iter()
                    .any(|allowed| allowed == name.as_str())
                {
                    return Some(Rejection {
                        status: hyper::StatusCode::BAD_REQUEST,
                        rule: "header_not_allowed",
                    });
                }
            }
        }

        // 5. Content type (only when the request declares one; a bodiless GET has no content type
        //    to validate even if it carries a Content-Type header, which is itself a signature).
        if !self.content_types.is_empty() {
            if let Some(value) = headers.get(hyper::header::CONTENT_TYPE) {
                let declared = value.to_str().unwrap_or_default().to_ascii_lowercase();
                let media_type = declared.split(';').next().unwrap_or("").trim();
                if !media_type.is_empty() && !self.content_types.iter().any(|ct| ct == media_type) {
                    return Some(Rejection {
                        status: hyper::StatusCode::UNSUPPORTED_MEDIA_TYPE,
                        rule: "content_type_not_allowed",
                    });
                }
            }
        }

        None
    }
}

/// Numeric rank for TLS versions (1.0 < 1.1 < 1.2 < 1.3).
fn rank(version: TlsFloor) -> u8 {
    match version {
        TlsFloor::Tls10 => 0,
        TlsFloor::Tls11 => 1,
        TlsFloor::Tls12 => 2,
        TlsFloor::Tls13 => 3,
    }
}

/// Validate a name as an HTTP token (RFC 7230 tchar subset: alphanumerics plus `-` and `_`).
fn validate_token(value: &str, label: &str) -> Result<(), String> {
    if value.is_empty()
        || !value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_' || b == b'.')
    {
        return Err(format!("{label}: `{value}` is not a valid token"));
    }
    Ok(())
}

/// The header name type is only used for the signature's clarity; re-export keeps clippy quiet.
#[allow(dead_code)]
type _HeaderName = HeaderName;

#[cfg(test)]
mod tests {
    use super::*;
    use hyper::header::HeaderValue;

    /// A `[posture]` table with sensible defaults, overridable field by field.
    struct Fixture {
        methods: Vec<String>,
        header_names: Vec<String>,
        content_types: Vec<String>,
        max_path_bytes: i64,
        max_query_bytes: i64,
        max_path_segments: i64,
        min_tls_version: String,
        admission_cap_per_authority: i64,
    }

    impl Default for Fixture {
        fn default() -> Fixture {
            Fixture {
                methods: vec!["GET".into(), "HEAD".into(), "POST".into(), "OPTIONS".into()],
                header_names: Vec::new(),
                content_types: Vec::new(),
                max_path_bytes: 4096,
                max_query_bytes: 4096,
                max_path_segments: 128,
                min_tls_version: "1.2".into(),
                admission_cap_per_authority: 0,
            }
        }
    }

    impl Fixture {
        /// Render the fixture as a `[posture]` table inside a minimal document body.
        fn toml(&self) -> String {
            format!(
                "[posture]\n\
                 active = \"standard\"\n\
                 methods = [{}]\n\
                 header_names = [{}]\n\
                 content_types = [{}]\n\
                 max_path_bytes = {}\n\
                 max_query_bytes = {}\n\
                 max_path_segments = {}\n\
                 min_tls_version = \"{}\"\n\
                 admission_cap_per_authority = {}\n",
                quote_join(&self.methods),
                quote_join(&self.header_names),
                quote_join(&self.content_types),
                self.max_path_bytes,
                self.max_query_bytes,
                self.max_path_segments,
                self.min_tls_version,
                self.admission_cap_per_authority,
            )
        }

        /// Build the profile, panicking with the table contents when validation fails.
        fn build(&self) -> Profile {
            let text = self.toml();
            let doc = Document::parse(&text).expect("fixture table must parse");
            Profile::from_document(&doc).unwrap_or_else(|e| panic!("fixture rejected: {e}\n{text}"))
        }

        /// Evaluate a request under this fixture's profile.
        fn check(
            &self,
            method: Method,
            uri: &str,
            headers: &[(&str, &str)],
            tls: Option<TlsFloor>,
        ) -> Option<Rejection> {
            let profile = self.build();
            let parsed: Uri = uri.parse().expect("fixture URI must parse");
            let mut map = HeaderMap::new();
            for (name, value) in headers {
                map.insert(
                    HeaderName::try_from(name.to_string()).expect("fixture header name must parse"),
                    HeaderValue::from_str(value).expect("fixture header value must parse"),
                );
            }
            profile.evaluate(&method, &parsed, &map, tls)
        }
    }

    /// `["a", "b"]` for embedding in a TOML array.
    fn quote_join(values: &[String]) -> String {
        values
            .iter()
            .map(|v| format!("\"{v}\""))
            .collect::<Vec<String>>()
            .join(", ")
    }

    #[test]
    fn standard_profile_passes_ordinary_requests() {
        let fixture = Fixture::default();
        assert_eq!(
            fixture.check(
                Method::GET,
                "/",
                &[("user-agent", "curl/7.61.1")],
                Some(TlsFloor::Tls12)
            ),
            None
        );
        assert_eq!(
            fixture.check(
                Method::POST,
                "/api/v1/thing?id=7",
                &[
                    ("content-type", "application/json"),
                    ("content-length", "2")
                ],
                Some(TlsFloor::Tls13),
            ),
            None
        );
    }

    #[test]
    fn method_allowlist_rejects_with_405_and_names_the_rule() {
        let fixture = Fixture {
            methods: vec!["GET".into(), "HEAD".into()],
            ..Default::default()
        };
        let rejection = fixture
            .check(Method::POST, "/", &[], Some(TlsFloor::Tls12))
            .expect("POST must be refused");
        assert_eq!(rejection.status, hyper::StatusCode::METHOD_NOT_ALLOWED);
        assert_eq!(rejection.rule, "method_not_allowed");
        // The allowed set still passes, and an empty list means unrestricted.
        assert_eq!(
            fixture.check(Method::GET, "/", &[], Some(TlsFloor::Tls12)),
            None
        );
        let unrestricted = Fixture {
            methods: Vec::new(),
            ..Default::default()
        };
        assert_eq!(
            unrestricted.check(Method::DELETE, "/", &[], Some(TlsFloor::Tls12)),
            None
        );
    }

    #[test]
    fn tls_floor_is_compared_not_matched() {
        let fixture = Fixture {
            min_tls_version: "1.3".into(),
            ..Default::default()
        };
        let rejection = fixture
            .check(Method::GET, "/", &[], Some(TlsFloor::Tls12))
            .expect("1.2 must fail a 1.3 floor");
        assert_eq!(rejection.status, hyper::StatusCode::FORBIDDEN);
        assert_eq!(rejection.rule, "tls_below_floor");
        assert_eq!(
            fixture.check(Method::GET, "/", &[], Some(TlsFloor::Tls13)),
            None
        );
        // Cleartext has no negotiated version, so the floor is not applied and not faked.
        assert_eq!(fixture.check(Method::GET, "/", &[], None), None);
    }

    #[test]
    fn path_shape_rules() {
        let long_path = "/".to_string() + &"a".repeat(500);
        let fixture = Fixture {
            max_path_bytes: 64,
            ..Default::default()
        };
        assert_eq!(
            fixture
                .check(Method::GET, &long_path, &[], Some(TlsFloor::Tls12))
                .unwrap()
                .rule,
            "path_too_long"
        );

        let fixture = Fixture {
            max_query_bytes: 8,
            ..Default::default()
        };
        assert_eq!(
            fixture
                .check(Method::GET, "/x?abcdefghij=1", &[], Some(TlsFloor::Tls12))
                .unwrap()
                .rule,
            "query_too_long"
        );

        let fixture = Fixture {
            max_path_segments: 2,
            ..Default::default()
        };
        assert_eq!(
            fixture
                .check(Method::GET, "/a/b/c", &[], Some(TlsFloor::Tls12))
                .unwrap()
                .rule,
            "path_segments"
        );
        // "/" and "/a" are within any sane segment budget.
        assert_eq!(
            fixture.check(Method::GET, "/", &[], Some(TlsFloor::Tls12)),
            None
        );
        assert_eq!(
            fixture.check(Method::GET, "/a", &[], Some(TlsFloor::Tls12)),
            None
        );
    }

    #[test]
    fn header_allowlist_names_the_offending_header() {
        let fixture = Fixture {
            header_names: vec!["host".into(), "user-agent".into(), "accept".into()],
            ..Default::default()
        };
        let profile = fixture.build();
        let mut headers = HeaderMap::new();
        headers.insert(hyper::header::HOST, HeaderValue::from_static("x"));
        headers.insert(hyper::header::USER_AGENT, HeaderValue::from_static("curl"));
        headers.insert(
            HeaderName::try_from("x-evil".to_string()).unwrap(),
            HeaderValue::from_static("1"),
        );
        let rejection = profile
            .evaluate(
                &Method::GET,
                &Uri::from_static("/"),
                &headers,
                Some(TlsFloor::Tls12),
            )
            .expect("x-evil must be refused");
        assert_eq!(rejection.rule, "header_not_allowed");
        assert_eq!(rejection.status, hyper::StatusCode::BAD_REQUEST);

        // Without the extra header the same request passes.
        let mut clean = HeaderMap::new();
        clean.insert(hyper::header::HOST, HeaderValue::from_static("x"));
        clean.insert(hyper::header::USER_AGENT, HeaderValue::from_static("curl"));
        assert_eq!(
            profile.evaluate(
                &Method::GET,
                &Uri::from_static("/"),
                &clean,
                Some(TlsFloor::Tls12)
            ),
            None
        );
    }

    #[test]
    fn content_type_rules_strip_parameters_and_use_415() {
        let fixture = Fixture {
            content_types: vec!["application/json".into()],
            ..Default::default()
        };
        // With parameters, still matches.
        assert_eq!(
            fixture.check(
                Method::POST,
                "/",
                &[("content-type", "application/json; charset=utf-8")],
                Some(TlsFloor::Tls12),
            ),
            None
        );
        let rejection = fixture
            .check(
                Method::POST,
                "/",
                &[("content-type", "multipart/form-data; boundary=x")],
                Some(TlsFloor::Tls12),
            )
            .expect("form-data must be refused");
        assert_eq!(rejection.status, hyper::StatusCode::UNSUPPORTED_MEDIA_TYPE);
        assert_eq!(rejection.rule, "content_type_not_allowed");
        // No Content-Type at all: nothing to validate, so the request is not refused here.
        assert_eq!(
            fixture.check(Method::GET, "/", &[], Some(TlsFloor::Tls12)),
            None
        );
    }

    #[test]
    fn validation_refuses_malformed_profile_fields() {
        let cases: Vec<(String, &str)> = vec![
            (
                "[posture]\nactive = \"\"\n".to_string(),
                "not a valid token",
            ),
            (
                Fixture {
                    methods: vec!["get".into()],
                    ..Default::default()
                }
                .toml(),
                "uppercase method token",
            ),
            (
                Fixture {
                    min_tls_version: "1.99".into(),
                    ..Default::default()
                }
                .toml(),
                "`min_tls_version` must be",
            ),
            (
                Fixture {
                    content_types: vec!["application".into()],
                    ..Default::default()
                }
                .toml(),
                "must look like `type/subtype`",
            ),
            (
                Fixture {
                    max_path_bytes: 0,
                    ..Default::default()
                }
                .toml(),
                "`max_path_bytes` must be greater than 0",
            ),
            (
                Fixture {
                    admission_cap_per_authority: -1,
                    ..Default::default()
                }
                .toml(),
                "`admission_cap_per_authority` must be 0 or greater",
            ),
        ];
        for (text, expected) in cases {
            let doc = Document::parse(&text).unwrap_or_else(|e| panic!("fixture must parse: {e}"));
            let error = Profile::from_document(&doc).expect_err("profile must be rejected");
            assert!(
                error.contains(expected),
                "expected {expected:?}, got {error:?} for\n{text}"
            );
        }
    }

    #[test]
    fn rejection_body_names_the_policy_and_the_rule() {
        let rejection = Rejection {
            status: hyper::StatusCode::METHOD_NOT_ALLOWED,
            rule: "method_not_allowed",
        };
        let body = rejection.body("lab-web01-s1");
        assert!(body.contains("policy=lab-web01-s1"));
        assert!(body.contains("rule=method_not_allowed"));
        assert!(body.contains("status=405"));
    }

    #[test]
    fn rank_orders_tls_versions() {
        assert!(rank(TlsFloor::Tls13) > rank(TlsFloor::Tls12));
        assert!(rank(TlsFloor::Tls12) > rank(TlsFloor::Tls11));
        assert!(rank(TlsFloor::Tls11) > rank(TlsFloor::Tls10));
    }
}
