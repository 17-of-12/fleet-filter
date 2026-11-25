//! The subset of TOML the gateway accepts for a policy bundle (Bundle S1).
//!
//! Why a hand-written parser instead of the `toml` crate: ADR-0001 M6 pins the dependency set to
//! an exact list, and the audit trail for an artifact includes the lockfile hash. A parser crate
//! would add `serde`, `serde_derive`, `syn`, `winnow` and friends to a binary whose only
//! structured input is a file this project also writes itself. The trade is real - a hand-written
//! parser is code we own - so the accepted grammar is deliberately tiny and *everything else is an
//! error* rather than a silent pass. A policy file that this parser cannot read is a policy file
//! that must not be deployed, which is exactly the behaviour S2 requires.
//!
//! Accepted grammar (and nothing else):
//!   * blank lines and `#` comments (a `#` inside a quoted value is literal);
//!   * table headers `[a]`, `[a.b]`, `[a.b.c]` - dot-separated names of `[A-Za-z0-9_-]+`;
//!   * `key = value` inside a table, keys using the same character set;
//!   * values: `"basic strings"` (with `\"`, `\\`, `\n`, `\t` escapes), integers, `true`/`false`,
//!     and arrays of strings written inline (`["a", "b"]`) or across lines (`key = [` ... `]`).
//!
//! Rejected: duplicate tables, duplicate keys, bare/unquoted strings, floats, nested inline
//! tables, arrays mixing types, unterminated strings or arrays, and any line that is not one of
//! the forms above. Every rejection names the line number.

use std::collections::BTreeMap;

/// A parsed TOML value, restricted to the types a policy bundle needs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Value {
    /// A quoted string.
    Str(String),
    /// A signed integer (all sizes in the schema fit in i64).
    Int(i64),
    /// A boolean.
    Bool(bool),
    /// An array of strings - the only array type, so a mixed array cannot be silently coerced.
    Strs(Vec<String>),
}

impl Value {
    /// The value as a string, or a typed error naming what was found.
    pub fn as_str(&self) -> Result<&str, String> {
        match self {
            Value::Str(v) => Ok(v),
            other => Err(format!("expected a string, found {}", describe(other))),
        }
    }

    /// The value as an integer, or a typed error naming what was found.
    pub fn as_int(&self) -> Result<i64, String> {
        match self {
            Value::Int(v) => Ok(*v),
            other => Err(format!("expected an integer, found {}", describe(other))),
        }
    }

    /// The value as a boolean, or a typed error naming what was found.
    pub fn as_bool(&self) -> Result<bool, String> {
        match self {
            Value::Bool(v) => Ok(*v),
            other => Err(format!("expected a boolean, found {}", describe(other))),
        }
    }

    /// The value as a string array, or a typed error naming what was found.
    pub fn as_strs(&self) -> Result<&[String], String> {
        match self {
            Value::Strs(v) => Ok(v),
            other => Err(format!(
                "expected a string array, found {}",
                describe(other)
            )),
        }
    }
}

/// Short type label used in error messages, without echoing arbitrary user text back.
fn describe(value: &Value) -> &'static str {
    match value {
        Value::Str(_) => "a string",
        Value::Int(_) => "an integer",
        Value::Bool(_) => "a boolean",
        Value::Strs(_) => "a string array",
    }
}

/// A parsed document: table name -> (key -> value).
#[derive(Debug, Default, Clone)]
pub struct Document {
    tables: BTreeMap<String, BTreeMap<String, Value>>,
}

impl Document {
    /// Parse the accepted grammar, returning `Err(line N: reason)` for anything outside it.
    pub fn parse(text: &str) -> Result<Document, String> {
        let mut tables: BTreeMap<String, BTreeMap<String, Value>> = BTreeMap::new();
        let mut current: Option<String> = None;
        let source: Vec<&str> = text.lines().collect();
        let mut index = 0usize;

        while index < source.len() {
            let raw = source[index];
            let line_number = index + 1;
            index += 1;
            let line = strip_comment(raw).trim().to_string();
            if line.is_empty() {
                continue;
            }

            // A multi-line array: `key = [` followed by quoted strings and a closing `]`.
            if line.ends_with('[') && !line.starts_with('[') {
                let (key, head) = split_assignment(&line)
                    .ok_or_else(|| format!("line {line_number}: expected `key = value`"))?;
                let mut items = Vec::new();
                let mut closed = false;
                // The opening line may already carry items (`signatures = ["a",` style).
                let rest = head.trim().trim_start_matches('[').to_string();
                if let Some((items_now, done)) = parse_inline_array_body(&rest) {
                    items = items_now;
                    closed = done;
                }
                while !closed {
                    if index >= source.len() {
                        return Err(format!("line {line_number}: unterminated array"));
                    }
                    let next_raw = source[index];
                    let next_number = index + 1;
                    index += 1;
                    let next = strip_comment(next_raw).trim().to_string();
                    if next.is_empty() {
                        continue;
                    }
                    let (items_now, done) = parse_inline_array_body(&next).ok_or_else(|| {
                        format!("line {next_number}: expected a quoted string or `]`")
                    })?;
                    items.extend(items_now);
                    closed = done;
                }
                let value = Value::Strs(items);
                insert(&mut tables, table_of(&current, line_number)?, key, value)?;
                continue;
            }

            if line.starts_with('[') {
                let name = line
                    .strip_prefix('[')
                    .and_then(|rest| rest.strip_suffix(']'))
                    .ok_or_else(|| format!("line {line_number}: malformed table header"))?
                    .trim();
                validate_name(name)
                    .ok_or_else(|| format!("line {line_number}: invalid table name `{name}`"))?;
                if tables.insert(name.to_string(), BTreeMap::new()).is_some() {
                    return Err(format!("line {line_number}: duplicate table `[{name}]`"));
                }
                current = Some(name.to_string());
                continue;
            }

            let (key, head) = split_assignment(&line).ok_or_else(|| {
                format!("line {line_number}: expected `key = value` or a table header")
            })?;
            validate_name(key).ok_or_else(|| format!("line {line_number}: invalid key `{key}`"))?;

            let value = if head.starts_with('[') {
                // Inline array on one line: `key = ["a", "b"]`. The two failure words are chosen
                // deliberately: an array with no closing bracket continues onto the next line
                // (`unterminated`), while one that has a closing bracket but bad contents is
                // malformed. Collapsing them would make a typo look like a formatting problem.
                match parse_inline_array_body(head) {
                    Some((items, true)) => Value::Strs(items),
                    Some((_, false)) => {
                        return Err(format!("line {line_number}: unterminated array"))
                    }
                    None if !head.ends_with(']') => {
                        return Err(format!("line {line_number}: unterminated array"))
                    }
                    None => return Err(format!("line {line_number}: malformed array")),
                }
            } else if head.starts_with('"') {
                let (text, rest) = parse_string(head)
                    .ok_or_else(|| format!("line {line_number}: malformed string"))?;
                if !rest.trim().is_empty() {
                    return Err(format!("line {line_number}: trailing content after string"));
                }
                Value::Str(text)
            } else if head == "true" || head == "false" {
                Value::Bool(head == "true")
            } else if is_integer(head) {
                Value::Int(
                    head.parse::<i64>()
                        .map_err(|e| format!("line {line_number}: {e}"))?,
                )
            } else {
                return Err(format!(
                    "line {line_number}: unsupported value `{}` (only quoted strings, integers, booleans and string arrays are accepted)",
                    head
                ));
            };

            insert(&mut tables, table_of(&current, line_number)?, key, value)?;
        }

        Ok(Document { tables })
    }

    /// The key map for a table, if the table exists.
    pub fn table(&self, name: &str) -> Option<&BTreeMap<String, Value>> {
        self.tables.get(name)
    }

    /// Every table name present, in sorted order (used by the schema check for unknown tables).
    pub fn table_names(&self) -> Vec<String> {
        self.tables.keys().cloned().collect()
    }

    /// One value from a table.
    pub fn get(&self, table: &str, key: &str) -> Option<&Value> {
        self.tables.get(table).and_then(|t| t.get(key))
    }

    /// A required string value, or an error naming the missing/invalid key.
    pub fn require_str(&self, table: &str, key: &str) -> Result<String, String> {
        self.get(table, key)
            .ok_or_else(|| format!("[{table}] missing required key `{key}`"))?
            .as_str()
            .map(str::to_string)
            .map_err(|e| format!("[{table}] `{key}`: {e}"))
    }

    /// An optional string value.
    pub fn opt_str(&self, table: &str, key: &str) -> Result<Option<String>, String> {
        match self.get(table, key) {
            None => Ok(None),
            Some(value) => value
                .as_str()
                .map(|v| Some(v.to_string()))
                .map_err(|e| format!("[{table}] `{key}`: {e}")),
        }
    }

    /// A required integer value.
    pub fn require_int(&self, table: &str, key: &str) -> Result<i64, String> {
        self.get(table, key)
            .ok_or_else(|| format!("[{table}] missing required key `{key}`"))?
            .as_int()
            .map_err(|e| format!("[{table}] `{key}`: {e}"))
    }

    /// An optional integer value.
    pub fn opt_int(&self, table: &str, key: &str) -> Result<Option<i64>, String> {
        match self.get(table, key) {
            None => Ok(None),
            Some(value) => value
                .as_int()
                .map(Some)
                .map_err(|e| format!("[{table}] `{key}`: {e}")),
        }
    }

    /// A required boolean value.
    pub fn require_bool(&self, table: &str, key: &str) -> Result<bool, String> {
        self.get(table, key)
            .ok_or_else(|| format!("[{table}] missing required key `{key}`"))?
            .as_bool()
            .map_err(|e| format!("[{table}] `{key}`: {e}"))
    }

    /// An optional boolean: `Ok(None)` when the key is absent.
    pub fn opt_bool(&self, table: &str, key: &str) -> Result<Option<bool>, String> {
        match self.get(table, key) {
            Some(value) => Ok(Some(
                value
                    .as_bool()
                    .map_err(|e| format!("[{table}] `{key}`: {e}"))?,
            )),
            None => Ok(None),
        }
    }

    /// A required string array (an empty array is valid and means "no restriction").
    pub fn require_strs(&self, table: &str, key: &str) -> Result<Vec<String>, String> {
        self.get(table, key)
            .ok_or_else(|| format!("[{table}] missing required key `{key}`"))?
            .as_strs()
            .map(|v| v.to_vec())
            .map_err(|e| format!("[{table}] `{key}`: {e}"))
    }

    /// An optional string array.
    pub fn opt_strs(&self, table: &str, key: &str) -> Result<Option<Vec<String>>, String> {
        match self.get(table, key) {
            None => Ok(None),
            Some(value) => value
                .as_strs()
                .map(|v| Some(v.to_vec()))
                .map_err(|e| format!("[{table}] `{key}`: {e}")),
        }
    }
}

/// The table a `key = value` line belongs to, or an error if no table header has been seen.
fn table_of(current: &Option<String>, line_number: usize) -> Result<String, String> {
    current
        .clone()
        .ok_or_else(|| format!("line {line_number}: key outside of a table"))
}

/// Insert a key into a table, rejecting duplicates.
fn insert(
    tables: &mut BTreeMap<String, BTreeMap<String, Value>>,
    table: String,
    key: &str,
    value: Value,
) -> Result<(), String> {
    let keys = tables
        .get_mut(&table)
        .ok_or_else(|| format!("table `[{table}]` disappeared while parsing"))?;
    if keys.contains_key(key) {
        return Err(format!("duplicate key `{key}` in table `[{table}]`"));
    }
    keys.insert(key.to_string(), value);
    Ok(())
}

/// Split `key = rest` into its two halves, or None when the line is not an assignment.
fn split_assignment(line: &str) -> Option<(&str, &str)> {
    let (key, rest) = line.split_once('=')?;
    let key = key.trim();
    if key.is_empty() {
        return None;
    }
    Some((key, rest.trim()))
}

/// True when the token is a base-10 integer that fits the schema's use of i64.
fn is_integer(token: &str) -> bool {
    let body = token.strip_prefix('-').unwrap_or(token);
    !body.is_empty() && body.bytes().all(|b| b.is_ascii_digit()) && token.parse::<i64>().is_ok()
}

/// True when `name` is a legal table or key name: `[A-Za-z0-9_-]+` segments joined by dots.
fn validate_name(name: &str) -> Option<&str> {
    if name.is_empty() {
        return None;
    }
    for segment in name.split('.') {
        if segment.is_empty()
            || !segment
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
        {
            return None;
        }
    }
    Some(name)
}

/// Remove a trailing `# comment`, respecting quoted strings so `key = "a#b"` survives intact.
fn strip_comment(line: &str) -> String {
    let mut out = String::with_capacity(line.len());
    let mut in_string = false;
    let mut escaped = false;
    for ch in line.chars() {
        if in_string {
            out.push(ch);
            if escaped {
                escaped = false;
            } else if ch == '\\' {
                escaped = true;
            } else if ch == '"' {
                in_string = false;
            }
            continue;
        }
        match ch {
            '"' => {
                in_string = true;
                out.push(ch);
            }
            '#' => break,
            _ => out.push(ch),
        }
    }
    out
}

/// Parse a quoted string at the start of `text`, returning (contents, remainder).
fn parse_string(text: &str) -> Option<(String, &str)> {
    let mut out = String::with_capacity(text.len());
    let mut chars = text.chars();
    if chars.next()? != '"' {
        return None;
    }
    let mut escaped = false;
    loop {
        let ch = chars.next()?;
        if escaped {
            out.push(match ch {
                'n' => '\n',
                't' => '\t',
                'r' => '\r',
                other => other,
            });
            escaped = false;
            continue;
        }
        match ch {
            '\\' => escaped = true,
            '"' => return Some((out, chars.as_str())),
            _ => out.push(ch),
        }
    }
}

/// Parse an array, returning (items, closed_by_bracket).
///
/// Accepts both the whole array (`["a", "b"]`) and a body without its opening bracket (`"a", "b"]`),
/// because the two call sites differ: the single-line form hands over the value after `=`, while
/// the multi-line form strips the opening `[` on the first line and feeds the remaining lines.
fn parse_inline_array_body(text: &str) -> Option<(Vec<String>, bool)> {
    let mut items = Vec::new();
    let mut rest = text.trim();
    if let Some(stripped) = rest.strip_prefix('[') {
        rest = stripped.trim();
    }
    if rest.is_empty() {
        return Some((items, false));
    }
    if rest == "]" {
        return Some((items, true));
    }
    while !rest.is_empty() {
        if let Some(closed) = rest.strip_prefix(']') {
            let trailing = closed.trim();
            if !trailing.is_empty() {
                return None; // content after the closing bracket is not accepted
            }
            return Some((items, true));
        }
        if rest.starts_with('"') {
            let (item, remainder) = parse_string(rest)?;
            items.push(item);
            rest = remainder.trim();
            if rest.starts_with(',') {
                rest = rest[1..].trim();
            } else if !rest.starts_with(']') {
                return None;
            }
            continue;
        }
        return None; // anything but a quoted string inside an array
    }
    Some((items, false))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Assert that a document parses and expose it for the assertions that follow.
    fn ok(text: &str) -> Document {
        Document::parse(text).unwrap_or_else(|e| panic!("expected parse to succeed: {e}"))
    }

    /// Assert that a document is rejected and return the message, so tests can name the reason.
    fn err(text: &str) -> String {
        match Document::parse(text) {
            Ok(_) => panic!("expected parse to fail for: {text}"),
            Err(e) => e,
        }
    }

    #[test]
    fn parses_the_accepted_grammar() {
        let doc = ok("# comment\n\
             \n\
             [policy]\n\
             schema_version = 1 # inline comment\n\
             version = \"lab-web01-s1\"\n\
             enabled = true\n\
             [detection]\n\
             prefixes = [\"/h2probe-\", \"/.env\"]\n\
             signatures = [\n\
             \x20 \"CVE-2026-119618:probe_path\",\n\
             \x20 \"CVE-2026-119618:bodyless_ct\",\n\
             ]\n");
        assert_eq!(doc.require_int("policy", "schema_version").unwrap(), 1);
        assert_eq!(
            doc.require_str("policy", "version").unwrap(),
            "lab-web01-s1"
        );
        assert!(doc.require_bool("policy", "enabled").unwrap());
        assert_eq!(
            doc.require_strs("detection", "prefixes").unwrap(),
            vec!["/h2probe-".to_string(), "/.env".to_string()]
        );
        assert_eq!(
            doc.require_strs("detection", "signatures").unwrap(),
            vec![
                "CVE-2026-119618:probe_path".to_string(),
                "CVE-2026-119618:bodyless_ct".to_string()
            ]
        );
    }

    #[test]
    fn hash_inside_a_string_survives_comment_stripping() {
        let doc = ok("[policy]\nversion = \"a#b\"\n");
        assert_eq!(doc.require_str("policy", "version").unwrap(), "a#b");
    }

    #[test]
    fn rejects_forms_that_would_silently_change_meaning() {
        assert!(err("[a]\nb = 1\nb = 2\n").contains("duplicate key"));
        assert!(err("[a]\nb = 1\n[a]\nc = 2\n").contains("duplicate table"));
        assert!(err("b = 1\n").contains("key outside of a table"));
        assert!(err("[a]\nb = bare\n").contains("unsupported value"));
        assert!(err("[a]\nb = 1.5\n").contains("unsupported value"));
        assert!(err("[a]\nb = \"unterminated\n").contains("malformed string"));
        assert!(err("[a\n").contains("malformed table header"));
        assert!(err("[a b]\nc = 1\n").contains("invalid table name"));
        assert!(err("[a]\nb = \"x\" trailing\n").contains("trailing content"));
        assert!(err("[a]\nb = [\"x\"\n").contains("unterminated array"));
        assert!(err("[a]\nb = [\"x\", 1]\n").contains("malformed array"));
        assert!(err("[a]\nb = \"x\", \"y\"\n").contains("trailing content"));
    }

    #[test]
    fn typed_accessors_refuse_the_wrong_type() {
        let doc = ok("[t]\ns = \"x\"\ni = 7\nb = true\na = [\"z\"]\n");
        assert!(doc.require_str("t", "i").is_err());
        assert!(doc.require_int("t", "s").is_err());
        assert!(doc.require_bool("t", "i").is_err());
        assert!(doc.require_strs("t", "s").is_err());
        assert!(doc.require_str("t", "absent").is_err());
        assert_eq!(doc.opt_str("t", "absent").unwrap(), None);
        assert_eq!(doc.opt_int("t", "i").unwrap(), Some(7));
        assert_eq!(
            doc.opt_strs("t", "a").unwrap().unwrap(),
            vec!["z".to_string()]
        );
    }

    #[test]
    fn empty_array_is_valid_and_means_no_restriction() {
        let doc = ok("[posture]\nmethods = []\n");
        let empty: Vec<String> = Vec::new();
        assert_eq!(doc.require_strs("posture", "methods").unwrap(), empty);
    }
}
