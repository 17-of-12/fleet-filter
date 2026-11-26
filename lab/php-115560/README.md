# CVE-2026-115560 lab victim

A victim that runs the application shape the advisory names, so the CVE can be reproduced on a PHP
this fleet actually runs.

| | |
|---|---|
| CVE | CVE-2026-115560 - session upload-progress written with the `php_serialize` handler, read back with the `php` handler. NVD (2026-11-19, `security@php.net`): affected <8.2.36, 8.3.x <8.3.37, **8.4.x <8.4.28**, 8.5.x <8.5.13 |
| Base image | `docker.io/library/php:8.4.26-apache` - the version `lab/manifest.json` declares for `ff-php`, and inside the affected range (8.4.26 < 8.4.28) |
| Reference lab | https://github.com/googlesky/CVE-2026-115560 (MIT, Copyright (c) 2026 Lê Hiếu) at commit `03cf7eee9b870166cd3230a9f22b7d9e7ac86b6e` - `lab/conf/*`, `lab/src/*`, `poc.py` are copied from here; `src/index.php` carries an attribution header for the same reason |
| PoC | `poc.py` in this directory, the reference exploit, copied from the same commit |
| Detection reference | https://github.com/al4n4n/achilles-heel/tree/main/CVE-2026-115560 (the repo the store entry cites) - `detection/cve-2026-115560.rules` pins the same body literal the signature now carries |
| Deployed as | `ff-php-115560` on `ff-apache02` (10.20.0.226):8095 (vulnerable) and `ff-php-115560-mit`:8097 (mitigated twin, `upload_progress.enabled=0`) |

## Why this victim had to be built

`ff-php`, the PHP victim this fleet already runs, has `session.serialize_handler = php` globally
(measured over SSH, 2026-11-25). The advisory's first precondition is that the **server** config
selects `php_binary` or `php_serialize` and that an application then switches to `php` at runtime;
with the global handler already `php` there is no serializer mismatch, so `ff-php` as configured
cannot reproduce this CVE however the payload is shaped. The rule that invalidated an out-of-range
WordPress victim (6.8.2 for CVE-2026-63030) applies here: fix the victim, do not push harder on the
wrong one.

Two containers come from one image, so the pair differs by one ini line and nothing else:

- `:8095` - `conf/99-vuln.ini`: `session.serialize_handler = php_serialize`, upload progress enabled,
  `use_strict_mode=0` (an attacker-chosen session id is adopted). `src/index.php` does
  `ini_set('session.serialize_handler', 'php')` before `session_start()` - precondition #2 - and
  ships a `LabGadget` class whose `__destruct` runs a command, standing in for any class in scope at
  unserialize time.
- `:8097` - `conf/99-mitigated.ini`: the same application with `session.upload_progress.enabled = 0`,
  the vendor's published mitigation. Running the exploit at this twin is the causality control: the
  effect has to disappear when the vulnerable setting is turned off, or the RCE came from something
  else.
- `src/noswitch.php` on the vulnerable container is a second control - identical code without the
  runtime handler switch, so the poisoned session is decoded with the handler that wrote it and the
  gadget never fires.

## Changes made to the reference lab, and why

| change | reason |
|---|---|
| `FROM php:8.4.26-apache` instead of upstream's `php:8.4.27-apache` | 8.4.26 is the PHP this fleet declares and runs (`ff-php`), and it is inside the affected range; testing the fleet's own version is the point of the lab. |
| `ARG LAB_INI` in the Containerfile instead of a Compose volume mount | two image tags from one build, so the vulnerable/mitigated pair differs by exactly the ini file - a fact about the build rather than a claim about the runtime. |
| `ARG PHP_VERSION` so the base version is recorded in the build command | the same Containerfile builds the fleet's 8.4.26 and upstream's 8.4.27 without editing the file. |

`conf/99-vuln.ini` is kept byte-for-byte, including `session.upload_progress.cleanup = 1`. That is
deliberate: with the default `cleanup=1` the progress record is deleted when the upload ends, so a
short body leaves nothing to decode and the exploit is a race - which is why the reference `poc.py`
streams a throttled multi-MiB upload while a second connection reads the session. Running their
documented invocation is the test; making the setting cheaper would be changing the experiment.

## Running it

```sh
cd lab/php-115560
podman build --build-arg LAB_INI=conf/99-vuln.ini      -t localhost/ff-php-115560:8.4.26-vuln .
podman build --build-arg LAB_INI=conf/99-mitigated.ini -t localhost/ff-php-115560:8.4.26-mit .
podman run -d --name ff-php-115560        -p 8095:80 localhost/ff-php-115560:8.4.26-vuln
podman run -d --name ff-php-115560-mit    -p 8097:80 localhost/ff-php-115560:8.4.26-mit
python3 poc.py check --target http://10.20.0.226:8095     # preconditions, from the victim's own phpinfo
python3 poc.py exploit --target http://10.20.0.226:8095 --cmd id
```
