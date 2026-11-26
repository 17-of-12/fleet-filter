<?php
// CVE-2026-129474 lab - phpinfo() page, same role as lab/php-115560/src/info.php: the PoC's
// `check` mode reads the victim's own view of its version and ini here (a fingerprint from the
// machine, not from a string the lab wrote).
phpinfo();
