/*
  Fleet Filter project-owned yara ruleset (Bundle Z, tier 2 - known-bad matching).

  Why this file exists in the repo instead of being downloaded from a rules feed: the shape metrics
  in bin/webtree-audit.py answer "is this file weird?", which is a judgement. A signature answers
  "have we seen this before?", which is a fact, and the two need different handling - a signature hit
  quarantines outright, a shape score only asks for review. Keeping the rules in the repo means a
  change to detection content is reviewed like any other change, and the image build records which
  ruleset a host is running.

  The EICAR rule is not a joke about yara: it is the only way to prove, from a fixture, that the
  signature path actually ran. "0 findings" and "the ruleset never matched anything" look identical
  without it. The remaining rules encode the sink patterns the controller already treats as exploit
  indicators (see controller/signatures/signatures.yaml) plus the brand markers of the shells that
  show up in web-server incident reports, so tier 1 and tier 2 are not guessing independently.

  Validated by: bin/build-scanner.sh compiles this file inside the built image and fails the build
  if yara rejects it, and tests/fixtures/webtree/ holds one file per rule class.

  Dialect notes, all learned the hard way on 2026-11-16 with yara 4.6.0:
    - the Perl-style non-capturing group `(?:abc)` is rejected; use a plain group `(abc)`.
    - there is no `\b` word boundary.
    - a literal parenthesis must be escaped (`\(`, `\)`); an unescaped one opens a group and the
      group has to close, so `/foo(bar/` fails to compile while `/foo\(bar/` and `/foo(bar)/` do not.
    - `yara -c` does not exist in 4.x; rulesets are validated with `yarac <rules> <out>`, which is why
      the image ships both binaries.
*/

rule EICAR_TestFile
{
    meta:
        origin = "EICAR standard anti-malware test file"
        purpose = "pipeline proof: a scan that cannot match this is a broken scan, not a clean tree"
    strings:
        $eicar = "X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"
    condition:
        $eicar
}

rule PHP_Sink_On_Superglobal
{
    meta:
        origin = "Fleet Filter detection content; mirrors the sink set in bin/webtree-audit.py"
        family = "generic php webshell"
    strings:
        $sink = /(eval|assert|system|exec|passthru|shell_exec|popen|proc_open|create_function|call_user_func|call_user_func_array|preg_replace)\(\$_(GET|POST|REQUEST|COOKIE|FILES|SERVER)/
    condition:
        $sink
}

rule PHP_Base64_Decode_Eval
{
    meta:
        origin = "the single most common packed-shell idiom"
        family = "packed php"
    strings:
        $a = /eval\(base64_decode\(/i
        $b = /assert\(base64_decode\(/i
        $c = /eval\(str_rot13\(/i
    condition:
        any of them
}

rule PHP_Compressed_Payload
{
    meta:
        family = "packed php"
    strings:
        $a = /gz(inflate|uncompress|decode)\(base64_decode\(/
        $b = /gzinflate\s*\(\s*\$/
    condition:
        any of them
}

rule PHP_Hex_Packed_String
{
    meta:
        family = "obfuscated php"
    strings:
        $hex = /(\\x[0-9a-fA-F]{2}){12,}/
    condition:
        $hex
}

rule PHP_Variable_Function_Call
{
    meta:
        family = "obfuscated php"
        note = "${\"sys\".\"tem\"}($x) hides a function name from a plain string search"
    strings:
        $direct = /\$[A-Za-z_][A-Za-z0-9_]*\((\$[A-Za-z0-9_]*)\)/
        $braced = /\$\{[^{}\n]{1,64}\}\s*\(/
    condition:
        any of them
}

rule PHP_Uploader_Move
{
    meta:
        family = "dropper"
    strings:
        $a = /move_uploaded_file\(\$_FILES\[/
    condition:
        $a
}

rule PHP_Mail_Spam_Sink
{
    meta:
        family = "mail spammer"
    strings:
        $a = /mail\(\$_(POST|GET|REQUEST)/
    condition:
        $a
}

rule PHP_Shell_Brand_Markers
{
    meta:
        family = "named shells"
        note = "brand strings survive most hand edits, even when the code around them is rewritten"
    strings:
        $a = "c999shell" nocase
        $b = "r57shell" nocase
        $c = "b374k" nocase
        $d = "indoxploit" nocase
        $e = "w40k" nocase
        $f = "webshell" nocase
        $g = "Jed Shell" nocase
        $h = "WSO 2.5" nocase
    condition:
        any of them
}

rule JSP_Runtime_Exec
{
    meta:
        family = "jsp shell"
    strings:
        $a = /Runtime\.getRuntime\(\)\.exec\(/
    condition:
        $a
}

rule ASP_WScript_Shell
{
    meta:
        family = "asp/.net shell"
    strings:
        $a = /CreateObject\("(WScript\.Shell|Shell\.Application|MSXML2\.XMLHTTP|Scripting\.FileSystemObject)"/
    condition:
        $a
}

rule PHP_Preg_Replace_E_Modifier
{
    meta:
        family = "legacy php backdoor"
        note = "the /e modifier executes the replacement; removed in PHP 7, still shipped in old drops"
    strings:
        $a = /preg_replace\(["'][^"']*\/e["']\)/
    condition:
        $a
}
