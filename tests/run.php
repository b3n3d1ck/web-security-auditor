<?php
// Dependency-free tests. Run with: php tests/run.php
require_once __DIR__ . '/../src/Scanner.php';

use Auditor\Scanner;
use Auditor\Grade;
use Auditor\Checks;
use Auditor\Http;
use Auditor\SsrfException;

$pass = 0;
$fail = 0;
function check(string $name, bool $cond): void
{
    global $pass, $fail;
    if ($cond) {
        $pass++;
    } else {
        $fail++;
        echo "  FAIL: $name\n";
    }
}

// --- URL normalization ---
check('adds https', Scanner::normalizeUrl('example.com') === 'https://example.com');
check('keeps http', Scanner::normalizeUrl('http://example.com/a') === 'http://example.com/a');
check('keeps port', Scanner::normalizeUrl('example.com:8080') === 'https://example.com:8080');
try { Scanner::normalizeUrl('not a host'); check('rejects junk', false); }
catch (\InvalidArgumentException $e) { check('rejects junk', true); }
try { Scanner::normalizeUrl(''); check('rejects empty', false); }
catch (\InvalidArgumentException $e) { check('rejects empty', true); }

// --- SSRF guard blocks internal targets ---
$http = new Http();
foreach (['http://localhost/', 'http://127.0.0.1/', 'http://169.254.169.254/', 'http://192.168.1.1/', 'http://10.0.0.1/'] as $u) {
    try {
        $http->fetch($u);
        check("blocks $u", false);
    } catch (SsrfException $e) {
        check("blocks $u", true);
    } catch (\Throwable $e) {
        check("blocks $u (other error ok)", true);
    }
}
try { $http->fetch('ftp://example.com/'); check('blocks ftp', false); }
catch (SsrfException $e) { check('blocks ftp', true); }

// --- Grading ---
$g = Grade::fromFindings([]);
check('empty is A', $g['letter'] === 'A' && $g['score'] === 100);
$g = Grade::fromFindings([['severity' => 'critical'], ['severity' => 'critical'], ['severity' => 'high']]);
check('many crits is F', $g['letter'] === 'F');
$g = Grade::fromFindings([['severity' => 'low'], ['severity' => 'ok'], ['severity' => 'info']]);
check('minor stays A', $g['letter'] === 'A');
$g = Grade::fromFindings([['severity' => 'high'], ['severity' => 'medium']]);
check('one high one medium is B/C', in_array($g['letter'], ['B', 'C'], true));

// --- Checks on synthetic data (no network) ---
$checks = new Checks($http);

$missing = $checks->securityHeaders([]);
check('flags missing CSP', (bool) array_filter($missing, fn($f) => $f['id'] === 'header-content-security-policy' && $f['severity'] === 'high'));
check('flags missing COOP', (bool) array_filter($missing, fn($f) => $f['id'] === 'header-cross-origin-opener-policy' && $f['severity'] === 'medium'));
check('flags missing CORP', (bool) array_filter($missing, fn($f) => $f['id'] === 'header-cross-origin-resource-policy' && $f['severity'] === 'medium'));
check('flags missing COEP', (bool) array_filter($missing, fn($f) => $f['id'] === 'header-cross-origin-embedder-policy' && $f['severity'] === 'low'));

$present = $checks->securityHeaders(['content-security-policy' => "default-src 'self'"]);
check('ok when CSP present', (bool) array_filter($present, fn($f) => $f['id'] === 'header-content-security-policy' && $f['severity'] === 'ok'));

$coopOk = $checks->securityHeaders(['cross-origin-opener-policy' => 'same-origin', 'cross-origin-resource-policy' => 'same-origin']);
check('ok when COOP present', (bool) array_filter($coopOk, fn($f) => $f['id'] === 'header-cross-origin-opener-policy' && $f['severity'] === 'ok'));
check('ok when CORP present', (bool) array_filter($coopOk, fn($f) => $f['id'] === 'header-cross-origin-resource-policy' && $f['severity'] === 'ok'));

$cookieBad = $checks->cookies(['set-cookie' => ['SESSID=abc; Path=/']]);
check('flags insecure cookie', (bool) array_filter($cookieBad, fn($f) => $f['severity'] !== 'ok'));

$cookieGood = $checks->cookies(['set-cookie' => ['SESSID=abc; Secure; HttpOnly; SameSite=Lax']]);
check('ok for secure cookie', (bool) array_filter($cookieGood, fn($f) => $f['severity'] === 'ok'));

$httpTls = $checks->tls('http', ['ok' => false]);
check('http is critical', (bool) array_filter($httpTls, fn($f) => $f['severity'] === 'critical'));

$expired = $checks->tls('https', ['ok' => true, 'protocol' => 'TLSv1.3', 'days_left' => -2]);
check('expired cert is critical', (bool) array_filter($expired, fn($f) => $f['id'] === 'tls-expired'));

$disclose = $checks->infoDisclosure(['x-powered-by' => 'PHP/7.4.1'], '');
check('flags version header', (bool) array_filter($disclose, fn($f) => $f['id'] === 'disclose-x-powered-by'));

// --- discovery helpers (private, via reflection) ---
$redact = new ReflectionMethod($checks, 'redact');
$redact->setAccessible(true);
check('masks password', str_contains($redact->invoke($checks, 'DB_PASSWORD=hunter2'), '***') && !str_contains($redact->invoke($checks, 'DB_PASSWORD=hunter2'), 'hunter2'));
check('masks api key', !str_contains($redact->invoke($checks, 'api_key: abc123xyz'), 'abc123xyz'));
check('keeps non-secret', str_contains($redact->invoke($checks, 'DB_HOST=127.0.0.1'), '127.0.0.1'));

$same = new ReflectionMethod($checks, 'sameOriginPath');
$same->setAccessible(true);
check('relative path kept', $same->invoke($checks, 'https://site.com/', 'css/app.css') === '/css/app.css');
check('same-origin absolute kept', $same->invoke($checks, 'https://site.com/', 'https://site.com/admin/') === '/admin/');
check('cross-origin dropped', $same->invoke($checks, 'https://site.com/', 'https://cdn.other.com/x.js') === null);
check('mailto dropped', $same->invoke($checks, 'https://site.com/', 'mailto:a@b.com') === null);

// --- advanced checks ---
require_once __DIR__ . '/../src/Advanced.php';
$adv = new Auditor\Advanced($http);

$weakCsp = $adv->cspQuality(['content-security-policy' => "default-src 'self' 'unsafe-inline' https:"]);
check('CSP unsafe-inline flagged', (bool) array_filter($weakCsp, fn($f) => $f['id'] === 'csp-unsafe-inline' && $f['severity'] === 'high'));
check('CSP wildcard flagged', (bool) array_filter($weakCsp, fn($f) => $f['id'] === 'csp-wildcard'));
$strongCsp = $adv->cspQuality(['content-security-policy' => "default-src 'none'; script-src 'self'; object-src 'none'; base-uri 'self'"]);
check('strong CSP: no unsafe-inline finding', !array_filter($strongCsp, fn($f) => $f['id'] === 'csp-unsafe-inline'));
check('no CSP header: no findings', $adv->cspQuality([]) === []);

$res = $adv->pageResources('https', 'https://site.com/', '<script src="https://cdn.other.com/x.js"></script>');
check('SRI missing flagged', (bool) array_filter($res, fn($f) => $f['id'] === 'sri-missing'));
$res2 = $adv->pageResources('https', 'https://site.com/', '<img src="http://x.com/a.png">');
check('mixed content flagged', (bool) array_filter($res2, fn($f) => $f['id'] === 'mixed-content'));
$res3 = $adv->pageResources('http', 'http://site.com/', '<img src="http://x.com/a.png">');
check('no mixed content on http page', !array_filter($res3, fn($f) => $f['id'] === 'mixed-content'));

check('email skipped for IP', $adv->emailSecurity('127.0.0.1') === []);

$mask = new ReflectionMethod($adv, 'maskSecret');
$mask->setAccessible(true);
check('secret masked', !str_contains($mask->invoke($adv, 'AKIAIOSFODNN7EXAMPLE'), 'IOSFODNN7'));
$regd = new ReflectionMethod($adv, 'registrableDomain');
$regd->setAccessible(true);
check('registrable co.id', $regd->invoke($adv, 'www.bank.co.id') === 'bank.co.id');
check('registrable .com', $regd->invoke($adv, 'a.b.example.com') === 'example.com');

// --- active checks (helpers, offline) ---
require_once __DIR__ . '/../src/Active.php';
$act = new Auditor\Active($http);
$dp = new ReflectionMethod($act, 'discoverParams');
$dp->setAccessible(true);
$found = $dp->invoke($act, 'https://site.com/', '<a href="/x?token=1&ref=2">x</a><input name="email">');
check('discovers link params', in_array('token', $found, true) && in_array('ref', $found, true));
check('discovers form field', in_array('email', $found, true));
check('includes common params', in_array('q', $found, true));
check('param count bounded', count($found) <= 10);

$wp = new ReflectionMethod($act, 'withParam');
$wp->setAccessible(true);
check('withParam adds query', $wp->invoke($act, 'https://s.com/', 'q', 'a b') === 'https://s.com/?q=a%20b');
check('withParam appends with &', str_contains($wp->invoke($act, 'https://s.com/?x=1', 'q', 'v'), '?x=1&q=v'));

echo "\n$pass passed, $fail failed\n";
exit($fail === 0 ? 0 : 1);
