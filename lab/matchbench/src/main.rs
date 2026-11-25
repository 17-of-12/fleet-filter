// Micro-benchmark for the Stage 2 gateway matcher choice (Bundle S: regex vs multi-literal).
//
// Question being answered: what does it cost, per proxied request, to test a request URI against
// a large signature set, and does the answer change depending on whether the rules are plain
// literals or real regular expressions?
//
//   A1 regex::RegexSet built from plain literals only            (no regex syntax at all)
//   A2 regex::RegexSet built from the same literals + 3 real regexes (one with a leading .*)
//   B  aho_corasick::AhoCorasick over the same literals          (multi-literal engine)
//   C  N separate regex::Regex::is_match calls                   (naive "one regex per signature")
use aho_corasick::AhoCorasick;
use regex::RegexSet;
use std::hint::black_box;
use std::time::Instant;

fn corpus() -> (Vec<String>, Vec<String>) {
    let a = ["wp-", "wp-content/", "wp-admin/", "api/", "assets/", "modules/", "sites/", "upload/"];
    let b = ["elementor", "woocommerce", "admin", "ajax", "async", "core", "export", "import",
             "json", "legacy", "mobile", "old", "plugin", "public", "rest", "static", "temp",
             "upload", "v1", "xmlrpc"];
    let c = [".php", ".html", ".json", ".js", ".css", ".cgi", ".pl", ".asp", ".aspx", ".jsp"];
    let mut literals = Vec::new();
    let mut i = 0usize;
    for w in a.iter() {
        for x in b.iter() {
            for e in c.iter() {
                literals.push(format!("/{}{}{}", w, x, e));
                i += 1;
                if i % 7 == 0 { literals.push(format!("/{}{}-{}.php", w, x, 1000 + i)); }
            }
        }
    }
    let mut with_regex = literals.clone();
    with_regex.push(r"^/h2probe-[0-9]{1,8}$".to_string());
    with_regex.push(r"^/index\.php/[A-Za-z0-9_]{4,12}$".to_string());
    with_regex.push(r"^/(?:admin|administrator)/setup[-_]?config\.php$".to_string());
    with_regex.push(r".*(?:bash|c99|r57|webshell|cmd\.php)\?.*(?:cmd|exec|system)=".to_string());
    (literals, with_regex)
}

fn time_set(set: &RegexSet, uris: &[String], reps: usize) -> (u128, usize) {
    let t = Instant::now();
    let mut hits = 0usize;
    for _ in 0..reps {
        for u in uris { if set.is_match(black_box(u)) { hits += 1; } }
    }
    (t.elapsed().as_nanos() / (uris.len() * reps) as u128, hits)
}

fn main() {
    let (literals, with_regex) = corpus();
    let mut uris: Vec<String> = literals.iter().step_by(3).cloned().collect();
    for n in 0..2000 { uris.push(format!("/some/real/path{}-page.html", n % 997)); }
    println!("literals={}  patterns_with_regex={}  uris={}",
             literals.len(), with_regex.len(), uris.len());

    let t = Instant::now();
    let set_lit = RegexSet::new(&literals).unwrap();
    let b1 = t.elapsed();
    let (ns_a1, h1) = time_set(&set_lit, &uris, 10);

    let t = Instant::now();
    let set_mix = RegexSet::new(&with_regex).unwrap();
    let b2 = t.elapsed();
    let (ns_a2, h2) = time_set(&set_mix, &uris, 10);

    let t = Instant::now();
    let ac = AhoCorasick::new(&literals).unwrap();
    let bb = t.elapsed();
    let t = Instant::now();
    let mut hb = 0usize;
    for _ in 0..10 { for u in &uris { if ac.is_match(black_box(u)) { hb += 1; } } }
    let ns_b = t.elapsed().as_nanos() / (uris.len() * 10) as u128;

    let t = Instant::now();
    let many: Vec<regex::Regex> = with_regex.iter().map(|p| regex::Regex::new(p).unwrap()).collect();
    let bc = t.elapsed();
    let sample: Vec<&String> = uris.iter().step_by(20).collect();
    let t = Instant::now();
    let mut hc = 0usize;
    for u in &sample { for r in &many { if r.is_match(black_box(u)) { hc += 1; break; } } }
    let ns_c = t.elapsed().as_nanos() / sample.len() as u128;

    println!("A1 RegexSet literals-only     build {:>10?}  {:>9} ns/uri  hits={}", b1, ns_a1, h1);
    println!("A2 RegexSet literals+3 regex  build {:>10?}  {:>9} ns/uri  hits={}", b2, ns_a2, h2);
    println!("B  AhoCorasick literals       build {:>10?}  {:>9} ns/uri  hits={}", bb, ns_b, hb);
    println!("C  {} separate Regex (all)    build {:>10?}  {:>9} ns/uri  hits={}", many.len(), bc, ns_c, hc);
}
