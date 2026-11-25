// A6 execution harness: run the vendored upstream `web-tarpit` under Node 22 and capture what it
// actually returns, so the audit is based on executed output rather than on reading the source.
// Two things are exercised: the pure matcher/responder (`tarpit(request)`) and the Node HTTP adapter
// (`nodeTarpit()`), because the brief's A6 asks for a response object for a known trap path and the
// adapter is what turns that response onto a real socket.
import { tarpit, isBotPath } from '../../vendor/crumrine-web-tarpit/src/tarpit.js';
import { nodeTarpit } from '../../vendor/crumrine-web-tarpit/src/adapters.js';
import http from 'node:http';

const HOST = 'lab-web01.lab';
const cases = [
  ['GET', '/wp-login.php'],
  ['GET', '/.env'],
  ['GET', '/.git/config'],
  ['POST', '/xmlrpc.php'],
  ['GET', '/wp-admin/'],
  ['GET', '/backup.sql'],
  ['GET', '/ai.html'],          // a path this host really serves
  ['GET', '/ldap/'],            // a path this host really aliases
  ['GET', '/h2probe-12345678'], // a path our Tier 1 signature matches
];

const traps = [];
console.log('node', process.version, '| module: web-tarpit 1.1.1 (vendored)');
console.log('path'.padEnd(22), 'isBotPath', 'status', 'bytes', 'server', 'x-powered-by');
for (const [method, p] of cases) {
  const req = new Request(`https://${HOST}${p}`, {
    method,
    headers: method === 'POST' ? { 'content-type': 'text/xml', 'x-forwarded-for': '203.0.113.9' } : { 'x-forwarded-for': '203.0.113.9' },
    body: method === 'POST' ? '<?xml version="1.0"?><methodCall><methodName>weblogUpdates.ping</methodName></methodCall>' : undefined,
  });
  const res = tarpit(req, { slowDripMs: 0, onTrap: async (type, path, ip) => { traps.push([type, path, ip]); } });
  if (res === null) {
    console.log(p.padEnd(22), String(isBotPath(p)).padEnd(9), '-      -     -      -   (tarpit returned null: not trapped)');
    continue;
  }
  const body = await res.text();
  console.log(p.padEnd(22), String(isBotPath(p)).padEnd(9),
    String(res.status).padEnd(6), String(body.length).padEnd(5),
    (res.headers.get('server') || '-').padEnd(6), res.headers.get('x-powered-by') || '-');
}

console.log('\nclient identity seen by the module (from onTrap callbacks):');
const seen = [...new Set(traps.map(t => t[2]))];
console.log('  ips:', seen.join(', ') || '(none)', '| expected 203.0.113.9 from X-Forwarded-For');
console.log('  trap types:', [...new Set(traps.map(t => t[0]))].join(', '));

// --- the Node adapter on a real socket ---------------------------------------------------------
const handler = nodeTarpit({ slowDripMs: 0 });
const server = http.createServer((req, res) => {
  if (!handler(req, res)) { res.writeHead(404, { 'Server': 'Apache/2.4.37 (Oracle Linux Server)' }); res.end('real app'); }
});
await new Promise(r => server.listen(18099, '127.0.0.1', r));
for (const p of ['/wp-login.php', '/ai.html']) {
  const t0 = process.hrtime.bigint();
  const r = await fetch(`http://127.0.0.1:18099${p}`);
  const body = await r.text();
  const ms = Number(process.hrtime.bigint() - t0) / 1e6;
  console.log(`adapter GET ${p.padEnd(14)} -> ${r.status} ${body.length}b in ${ms.toFixed(0)}ms server=${r.headers.get('server') || '-'}`);
}
server.close();
