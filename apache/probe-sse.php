<?php
/**
 * Fleet-Filter P5 parity probe - a server-sent-events endpoint on the gateway backend.
 *
 * Purpose: P5 asks about streaming responses / SSE. The backend previously offered nothing that
 * streams, so the row could only record an absence. This file makes the behaviour measurable: it
 * emits five events 200 ms apart, flushing after each, so a client can tell the difference between
 * a proxy that forwards bytes as they arrive and one that buffers the whole body before answering.
 *
 * Deployed to /var/www/html/sse-probe.php on lab-web01 (the gateway backend DocumentRoot). It is
 * additive: no existing file changes, and the :443 vhost simply gains one more static URL.
 */

// The stream body is emitted with the headers flushed first; without this Apache's own output
// buffering would hold the first event and the measurement would say "buffered" for the wrong reason.
if (ob_get_level() > 0) {
    @ob_end_clean();
}

header('Content-Type: text/event-stream');
header('Cache-Control: no-cache');
header('X-Fleet-Filter-SSE: 1');
header('X-Accel-Buffering: no'); // nginx-family hint, harmless for Apache, documents intent

$events = 5;
$gap_us = 200000; // 200 ms

for ($i = 1; $i <= $events; $i++) {
    echo "event: tick\n";
    echo "id: {$i}\n";
    echo 'data: {"i":' . $i . ',"server_ts":' . round(microtime(true), 6) . "}\n\n";
    if (ob_get_level() > 0) {
        @ob_flush();
    }
    flush();
    if ($i < $events) {
        usleep($gap_us);
    }
}

echo "event: done\ndata: end\n\n";
if (ob_get_level() > 0) {
    @ob_flush();
}
flush();
