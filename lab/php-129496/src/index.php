<?php
// CVE-2026-129496 lab - the application the victim serves (front controller).
//
// The app itself is what abraxas/lab/www/index.php is: one file that proves PHP executed
// (`echo "CVE-2026-129496-ALIVE " . PHP_SAPI`). Two lab additions, each documented:
//
//  * the worker pid is echoed, because the reference PoCs need `docker exec` + a /proc scan
//    to answer "did the worker that took this request die" (evenomn poc/exploit.py
//    Target.alive()). Over HTTP the app can answer the same question itself: ask again, and
//    a different pid means the old worker is gone. The lab A/B and the direct run read this
//    line; nothing about the exploit depends on it.
//  * FallbackResource (conf/apache-lab.conf) makes every non-file path - /check included -
//    run this file, so the request shapes the reference PoCs send are real requests here.
//    The route is echoed so a proxied response proves WHICH path the app served.

header('X-Lab-App: cve-2026-129496');
echo 'CVE-2026-129496-ALIVE ' . PHP_SAPI
    . ' pid=' . getmypid()
    . ' route=' . (isset($_SERVER['REQUEST_URI']) ? $_SERVER['REQUEST_URI'] : '-')
    . PHP_EOL;
