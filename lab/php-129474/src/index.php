<?php
// CVE-2026-129474 lab - the application the victim serves (front controller).
//
// The advisory's trigger is "a method call handled by __call() or __callStatic()" whose arguments
// are collected for a fatal-error backtrace. Whether a request reaches that shape is an application
// property - the NVD-cited reference (murrez/php2shell, poc.py:856-866) says the same: "Full RCE
// requires app __call/__callStatic + ini fatal_error_backtraces / ignore_args", and its probe
// walks the app's API routes (BACKTRACE_JSON_PROBE_PATHS, poc.py:96-105 of the pinned commit -
// the list below is that list, as real routes).
//
// Apache serves this file for every path that is not a real file (conf/apache-lab.conf adds
// FallbackResource /index.php), which is how /api/import can exist as a route instead of a file.
//
// Page layout rules learned the same way lab/php-115560/src/index.php learned them:
//  - the front page echoes nothing the reference parser looks for (no `__call(`, no
//    `Stack trace:`, no ini names), so an ordinary 200 can never be mistaken for artefacts;
//  - every route that exists does so through the class below, so the magic call is the only
//    way request data enters the app.

class Api
{
    // The app declares NO route methods (no import(), no imports(), no graphql()).
    // Every route dispatch therefore runs through __callStatic - the exact entry the CVE names.
    // The request body rides in as the argument array, which is what the backtrace will
    // then collect from (and, pre-8.5.13, read stale).
    public static function __callStatic(string $route, array $args): string
    {
        $raw = (string) ($args['body'] ?? ($args[0] ?? ''));

        // The endpoint's real work: normalise the received payload. Four working copies per
        // ingestion is ordinary format overhead, not a lab trick, and the app's documented
        // memory_limit (conf/99-vuln.ini: 2M) is sized so a ~640 KiB probe body overflows it
        // during this line. The fatal therefore fires INSIDE the magic-method call - the
        // "fatal error ... while an application enters such a call" the advisory requires.
        $normalised = str_repeat($raw, 4);

        // The answer names the route and the normalised size, so a small-body request still
        // proves the body entered through __call: `import:48` for a 12-byte body.
        return $route . ':' . strlen($normalised) . "\n";
    }

    // The object-side twin: `$api->import(...)` for any undeclared route runs THIS first, so both
    // spellings the advisory names (__call and __callStatic) are covered by the same work.
    public function __call(string $route, array $args): string
    {
        return self::__callStatic($route, $args);
    }

    // Declared routes (not magic): the site page and the ini self-report the PoC's check mode
    // reads. Deliberately far from the reference probe list so check answers never count as
    // exploit artefacts.
    public static function status(array $args = []): string
    {
        return "app=Api"
            . " memory_limit=" . ini_get('memory_limit')
            . " zend.exception_ignore_args=" . var_export(ini_get('zend.exception_ignore_args'), true)
            . " fatal_error_backtraces=" . var_export(ini_get('fatal_error_backtraces'), true)
            . "\n";
    }
}

$path = parse_url($_SERVER['REQUEST_URI'] ?? '/', PHP_URL_PATH) ?: '/';
$path = rtrim($path, '/') ?: '/';
if ($path === '') {
    $path = '/';
}

// The docroot's own page: an ordinary answer that allocates nothing and quotes nothing the
// reference parser matches on. This is the request the benign control uses through the gateway.
if ($path === '/' || $path === '/index.php') {
    header('Content-Type: text/plain');
    echo "fleet-filter lab victim\n";
    exit;
}

// Declared route (not the magic path): the ini self-report for lab/php-129474/poc.py check.
if ($path === '/api/status') {
    header('Content-Type: text/plain');
    echo Api::status();
    exit;
}

// Every other path - /api/import, /import, /api/imports, /api/v1/import,
// /rest/V1/guest-carts/estimate-shipping-methods, /graphql, /api/data (the reference lists) -
// dispatches through the magic call with the request body as the call's argument.
$route = substr(basename($path), 0, 64);
if ($route === '') {
    $route = 'index';
}
$body = file_get_contents('php://input');
header('Content-Type: text/plain');
$api = new Api();
echo $api->{$route}($body);
