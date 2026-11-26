<?php
// CVE-2026-129496 lab - phpinfo() page for the PoC's `check` mode.
//
// The reference PoCs read the victim's configuration over HTTP through exactly this page:
// abraxas/lab/poc.py's check and lab/php-129474/poc.py's check parse the phpinfo() table for
// PHP Version / memory_limit / error_log / date.timezone and refuse victims whose
// configuration is not the vulnerable one ("version in range but the ini pair is not the
// vulnerable one"). Kept as a separate real file so the front controller stays the plain
// two-line page the abraxas lab ships.

phpinfo();
