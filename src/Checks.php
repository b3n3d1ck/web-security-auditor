<?php
// The passive checks. Each returns zero or more findings.
// A finding: [id, title, severity, detail, fix, evidence?].
// Severities: critical, high, medium, low, info, ok.

namespace Auditor;

class Checks
{
    public function __construct(private Http $http) {}

    /** Important response headers and what their absence means. */
    private const SECURITY_HEADERS = [
        'content-security-policy' => ['high', 'Content-Security-Policy',
            'Tanpa CSP, serangan XSS jauh lebih mudah dilakukan karena browser mau menjalankan skrip dari mana saja.',
            "Tambahkan header Content-Security-Policy. Awali dari yang ketat, mis. \"default-src 'self'\", lalu longgarkan seperlunya."],
        'strict-transport-security' => ['high', 'Strict-Transport-Security',
            'Tanpa HSTS, pengunjung bisa diarahkan ke versi HTTP yang bisa disadap pada kunjungan pertama.',
            'Tambahkan: Strict-Transport-Security: max-age=31536000; includeSubDomains'],
        'x-content-type-options' => ['medium', 'X-Content-Type-Options',
            'Tanpa header ini, browser bisa menebak tipe file dan mengeksekusi konten yang seharusnya tidak dijalankan (MIME sniffing).',
            'Tambahkan: X-Content-Type-Options: nosniff'],
        'x-frame-options' => ['medium', 'X-Frame-Options',
            'Tanpa proteksi framing, situs bisa dibungkus di iframe situs lain untuk serangan clickjacking.',
            'Tambahkan: X-Frame-Options: DENY (atau atur frame-ancestors di CSP).'],
        'referrer-policy' => ['low', 'Referrer-Policy',
            'Tanpa Referrer-Policy, URL lengkap halamanmu bisa bocor ke situs pihak ketiga.',
            'Tambahkan: Referrer-Policy: strict-origin-when-cross-origin'],
        'permissions-policy' => ['low', 'Permissions-Policy',
            'Tanpa Permissions-Policy, skrip pihak ketiga bebas memakai kamera, mikrofon, dan lokasi.',
            'Tambahkan Permissions-Policy yang mematikan fitur yang tidak dipakai, mis. geolocation=(), camera=(), microphone=()'],
        'cross-origin-opener-policy' => ['medium', 'Cross-Origin-Opener-Policy',
            'Tanpa COOP, window yang dibuka dari situsmu tetap punya referensi ke window asal, membuka pintu serangan tab-nabbing dan side-channel kelas Spectre.',
            'Tambahkan: Cross-Origin-Opener-Policy: same-origin'],
        'cross-origin-embedder-policy' => ['low', 'Cross-Origin-Embedder-Policy',
            'Tanpa COEP, halaman memuat resource lintas-origin tanpa persetujuan eksplisit, dan fitur yang butuh isolasi penuh (mis. SharedArrayBuffer) tidak bisa diaktifkan dengan aman.',
            'Tambahkan: Cross-Origin-Embedder-Policy: require-corp — biasanya dipasangkan dengan COOP untuk cross-origin isolation.'],
        'cross-origin-resource-policy' => ['medium', 'Cross-Origin-Resource-Policy',
            'Tanpa CORP, resource situsmu (gambar, font, data) bisa dibaca dari origin lain lewat elemen cross-origin, memperluas permukaan kebocoran data.',
            'Tambahkan: Cross-Origin-Resource-Policy: same-origin (atau same-site kalau ada subdomain sendiri).'],
    ];

    /** @return array<array> */
    public function securityHeaders(array $headers): array
    {
        $findings = [];
        foreach (self::SECURITY_HEADERS as $key => [$sev, $title, $detail, $fix]) {
            if (!isset($headers[$key])) {
                $findings[] = $this->finding("header-$key", "Header $title tidak ada", $sev, $detail, $fix);
            } else {
                $findings[] = $this->finding("header-$key", "Header $title terpasang", 'ok',
                    "Nilai: " . $this->str($headers[$key]), '');
            }
        }
        return $findings;
    }

    /** @return array<array> */
    public function tls(string $scheme, array $tls): array
    {
        $findings = [];
        if ($scheme !== 'https') {
            $findings[] = $this->finding('tls-http', 'Situs berjalan tanpa HTTPS', 'critical',
                'Lalu lintas dikirim tanpa enkripsi sehingga password dan data bisa disadap di jaringan.',
                'Pasang sertifikat (gratis lewat Let\'s Encrypt) dan paksa semua trafik ke HTTPS.');
            return $findings;
        }
        if (!($tls['ok'] ?? false)) {
            $findings[] = $this->finding('tls-error', 'Koneksi TLS gagal diperiksa', 'info',
                $this->str($tls['error'] ?? 'tidak diketahui'), '');
            return $findings;
        }

        $proto = $tls['protocol'] ?? '';
        if (preg_match('/1\.0|1\.1|SSLv/i', $proto)) {
            $findings[] = $this->finding('tls-old', "Protokol TLS lama: $proto", 'high',
                'Versi TLS lama punya kelemahan yang sudah diketahui dan ditolak browser modern.',
                'Nonaktifkan TLS 1.0/1.1 di server, aktifkan hanya TLS 1.2 dan 1.3.');
        } elseif ($proto) {
            $findings[] = $this->finding('tls-version', "Protokol: $proto", 'ok', 'Versi TLS sudah modern.', '');
        }

        $days = $tls['days_left'] ?? null;
        if ($days !== null) {
            if ($days < 0) {
                $findings[] = $this->finding('tls-expired', 'Sertifikat TLS sudah kedaluwarsa', 'critical',
                    'Browser akan menampilkan peringatan dan menolak membuka situs.',
                    'Perbarui sertifikat sekarang. Aktifkan auto-renew (mis. certbot) agar tidak terulang.');
            } elseif ($days < 15) {
                $findings[] = $this->finding('tls-expiring', "Sertifikat TLS kedaluwarsa dalam $days hari", 'high',
                    'Sebentar lagi situs akan ditolak browser kalau tidak diperbarui.',
                    'Perbarui sertifikat dan pastikan auto-renew aktif.');
            } else {
                $findings[] = $this->finding('tls-valid', "Sertifikat valid ($days hari lagi)", 'ok',
                    'Diterbitkan oleh: ' . $this->str($tls['issuer'] ?? '-'), '');
            }
        }
        if (!empty($tls['self_signed'])) {
            $findings[] = $this->finding('tls-selfsigned', 'Sertifikat self-signed', 'high',
                'Sertifikat tidak diterbitkan otoritas tepercaya, sehingga browser menandainya tidak aman.',
                'Pakai sertifikat dari CA tepercaya seperti Let\'s Encrypt.');
        }
        return $findings;
    }

    /** @return array<array> */
    public function cookies(array $headers): array
    {
        $cookies = $headers['set-cookie'] ?? [];
        if (!$cookies) {
            return [];
        }
        $findings = [];
        foreach ($cookies as $raw) {
            $name = trim(explode('=', $raw, 2)[0]);
            $flags = strtolower($raw);
            $missing = [];
            if (!str_contains($flags, 'secure')) {
                $missing[] = 'Secure';
            }
            if (!str_contains($flags, 'httponly')) {
                $missing[] = 'HttpOnly';
            }
            if (!str_contains($flags, 'samesite')) {
                $missing[] = 'SameSite';
            }
            if ($missing) {
                $findings[] = $this->finding("cookie-$name", "Cookie \"$name\" tanpa flag: " . implode(', ', $missing),
                    str_contains($flags, 'sess') || !str_contains($flags, 'httponly') ? 'medium' : 'low',
                    'Flag yang hilang membuat cookie bisa dicuri lewat skrip atau dikirim lewat koneksi tidak aman.',
                    'Set cookie dengan flag Secure; HttpOnly; SameSite=Lax (atau Strict untuk sesi).');
            } else {
                $findings[] = $this->finding("cookie-$name", "Cookie \"$name\" sudah lengkap flag-nya", 'ok',
                    'Secure, HttpOnly, dan SameSite terpasang.', '');
            }
        }
        return $findings;
    }

    /** @return array<array> */
    public function infoDisclosure(array $headers, string $body): array
    {
        $findings = [];
        foreach (['server' => 'Server', 'x-powered-by' => 'X-Powered-By'] as $key => $label) {
            if (isset($headers[$key]) && preg_match('/[0-9]/', $headers[$key])) {
                $findings[] = $this->finding("disclose-$key", "$label membocorkan versi: " . $this->str($headers[$key]), 'low',
                    'Nomor versi memudahkan penyerang mencari exploit yang cocok untuk versi itu.',
                    "Sembunyikan versi. Untuk $label, atur server_tokens off (nginx) atau expose_php = Off (PHP).");
            }
        }
        if (preg_match('/<meta[^>]+name=["\']generator["\'][^>]+content=["\']([^"\']+)/i', $body, $m)) {
            $findings[] = $this->finding('disclose-generator', 'Tag generator membocorkan software: ' . $this->str($m[1]), 'info',
                'Memberi tahu penyerang CMS dan versi yang dipakai.',
                'Hapus meta generator (di WordPress: remove_action("wp_head", "wp_generator")).');
        }
        if (preg_match('#/wp-content/#', $body) || isset($headers['x-powered-by']) && stripos($this->str($headers['x-powered-by']), 'wordpress') !== false) {
            $findings[] = $this->finding('disclose-wp', 'Terdeteksi WordPress', 'info',
                'Bukan kerentanan, tapi WordPress sering jadi sasaran. Pastikan core dan plugin selalu diperbarui.',
                'Rutin update, pasang plugin keamanan, dan batasi percobaan login.');
        }
        return $findings;
    }

    /**
     * Probe common sensitive paths. Uses a soft-404 baseline so we only flag real exposure.
     * @return array<array>
     */
    public function sensitiveFiles(string $baseUrl): array
    {
        $baseline = $this->softNotFoundBaseline($baseUrl);

        $targets = [
            ['/.env', '/APP_KEY|DB_(HOST|PASSWORD|DATABASE)|MAIL_/i', 'File .env berisi kredensial database dan API bisa diakses publik'],
            ['/.git/config', '/\[core\]|\[remote/i', 'Folder .git terekspos, seluruh kode sumber bisa diunduh'],
            ['/.git/HEAD', '/ref:\s*refs\//i', 'Folder .git terekspos, seluruh riwayat kode bisa diunduh'],
            ['/phpinfo.php', '/phpinfo\(\)|PHP Version/i', 'phpinfo() membocorkan konfigurasi server dan path internal'],
            ['/.DS_Store', '/Bud1|\x00\x00\x00/', 'File .DS_Store membocorkan daftar nama file di folder'],
            ['/backup.zip', '/^PK\x03\x04/', 'File backup bisa diunduh siapa saja'],
            ['/backup.sql', '/(CREATE TABLE|INSERT INTO)/i', 'Dump database bisa diunduh siapa saja'],
            ['/.env.bak', '/APP_KEY|DB_/i', 'Cadangan file .env bisa diakses publik'],
            ['/config.php.bak', '/<\?php|define\(/i', 'Cadangan file konfigurasi bisa diakses publik'],
            ['/server-status', '/Apache Server Status|Scoreboard/i', 'Halaman server-status membocorkan request dan IP pengunjung'],
            ['/.htaccess', '/RewriteEngine|<Files|Options /i', 'File .htaccess bisa dibaca dan membocorkan aturan server'],
            ['/wp-config.php.bak', '/DB_PASSWORD|DB_NAME/i', 'Cadangan wp-config membocorkan kredensial WordPress'],
        ];

        $findings = [];
        $exposedCount = 0;
        foreach ($targets as [$path, $signature, $risk]) {
            try {
                $res = $this->http->fetch(rtrim($baseUrl, '/') . $path);
            } catch (\Throwable $e) {
                continue;
            }
            if ($res['status'] !== 200) {
                continue;
            }
            // skip if the site returns 200 for everything (soft 404) unless content matches a signature
            if ($baseline['soft404'] && !preg_match($signature, $res['body'])) {
                continue;
            }
            if (!preg_match($signature, $res['body'])) {
                continue;
            }
            $exposedCount++;
            preg_match($signature, $res['body'], $hit, PREG_OFFSET_CAPTURE);
            $evidence = $this->snippet($res['body'], $hit[0][1] ?? 0);
            $findings[] = $this->finding('file-' . trim($path, '/.'), "Terekspos: $path", 'critical',
                $risk . '.',
                "Blokir akses ke $path di konfigurasi server, dan keluarkan file ini dari web root. Ganti kredensial apa pun yang sempat terekspos.",
                "GET {$path}  (HTTP 200)\n" . $evidence);
        }

        if ($exposedCount === 0) {
            $findings[] = $this->finding('files-ok', 'Tidak ada file sensitif yang terekspos', 'ok',
                count($targets) . ' path umum diperiksa, tidak ada yang bisa diakses.', '');
        }
        return $findings;
    }

    /** @return array<array> */
    public function cors(string $baseUrl): array
    {
        try {
            $res = $this->http->fetch($baseUrl, 'GET', ['Origin' => 'https://evil.example']);
        } catch (\Throwable $e) {
            return [];
        }
        $acao = $res['headers']['access-control-allow-origin'] ?? null;
        $acac = strtolower($this->str($res['headers']['access-control-allow-credentials'] ?? ''));
        if ($acao === null) {
            return [];
        }
        if (trim($acao) === 'https://evil.example') {
            $sev = $acac === 'true' ? 'high' : 'medium';
            return [$this->finding('cors-reflect', 'CORS memantulkan Origin sembarangan', $sev,
                'Server menerima Origin apa pun' . ($acac === 'true' ? ' sambil mengizinkan kredensial, sehingga situs lain bisa membaca data pengguna yang sudah login.' : '.'),
                'Jangan pantulkan Origin. Pakai daftar putih domain yang diizinkan, dan jangan gabungkan Access-Control-Allow-Origin: * dengan credentials.')];
        }
        if (trim($acao) === '*' && $acac === 'true') {
            return [$this->finding('cors-wildcard', 'CORS wildcard dengan kredensial', 'high',
                'Kombinasi Allow-Origin: * dan Allow-Credentials: true berbahaya.',
                'Ganti wildcard dengan daftar domain tertentu.')];
        }
        return [];
    }

    /**
     * Discover directories and paths from the site's own signals (robots.txt,
     * sitemap.xml, and links on the homepage) - no wordlist, no blind guessing.
     * Then checks the discovered directories for open directory listing.
     * @return array<array>
     */
    public function discovery(string $baseUrl, string $landingBody): array
    {
        $base = rtrim($baseUrl, '/');
        $findings = [];
        $paths = [];        // every path we learned about
        $robotsHidden = []; // paths an admin tried to hide via robots.txt

        // 1. robots.txt - often lists admin/backup paths the owner wants hidden
        try {
            $r = $this->http->fetch("$base/robots.txt");
            if ($r['status'] === 200 && stripos($r['headers']['content-type'] ?? '', 'html') === false) {
                foreach (preg_split('/\r?\n/', $r['body']) as $line) {
                    if (preg_match('/^\s*(dis)?allow\s*:\s*(\S+)/i', $line, $m)) {
                        $p = $m[2];
                        $paths[] = $p;
                        if (stripos($line, 'disallow') === 0 && $p !== '/' && $p !== '') {
                            $robotsHidden[] = $p;
                        }
                    }
                    if (preg_match('#^\s*sitemap\s*:\s*(\S+)#i', $line, $m)) {
                        $paths = array_merge($paths, $this->fetchSitemap($m[1]));
                    }
                }
            }
        } catch (\Throwable $e) {
        }

        // 2. sitemap.xml at the default location
        $paths = array_merge($paths, $this->fetchSitemap("$base/sitemap.xml"));

        // 3. links on the homepage
        if (preg_match_all('/(?:href|src|action)\s*=\s*["\']([^"\'#?]+)/i', $landingBody, $m)) {
            foreach ($m[1] as $href) {
                $p = $this->sameOriginPath($baseUrl, $href);
                if ($p !== null) {
                    $paths[] = $p;
                }
            }
        }

        if ($robotsHidden) {
            $findings[] = $this->finding('robots-hidden', 'robots.txt menyebut path tersembunyi', 'low',
                'robots.txt memberitahu siapa pun direktori yang ingin kamu sembunyikan. Penyerang membaca file ini lebih dulu.',
                'Jangan menaruh path rahasia di robots.txt. Lindungi direktori sensitif dengan autentikasi, bukan dengan menyembunyikannya di sini.',
                "GET /robots.txt\nDisallow:\n  " . implode("\n  ", array_slice(array_unique($robotsHidden), 0, 12)));
        }

        // derive unique directories from everything we found
        $dirs = [];
        foreach ($paths as $p) {
            $p = '/' . ltrim(parse_url($p, PHP_URL_PATH) ?? '', '/');
            $dir = rtrim(substr($p, 0, strrpos($p, '/') + 1), '/');
            if ($dir !== '' && !isset($dirs[$dir])) {
                $dirs[$dir] = true;
            }
        }
        $dirs = array_slice(array_keys($dirs), 0, 12); // stay bounded and polite

        $listing = [];
        foreach ($dirs as $dir) {
            try {
                $res = $this->http->fetch("$base$dir/");
            } catch (\Throwable $e) {
                continue;
            }
            if ($res['status'] === 200 && preg_match('#<title>\s*Index of|<h1>\s*Index of|Directory listing for#i', $res['body'], $hit, PREG_OFFSET_CAPTURE)) {
                $listing[] = $dir;
                $findings[] = $this->finding('listing-' . trim($dir, '/'), "Directory listing terbuka: $dir/", 'medium',
                    "Isi folder $dir/ bisa dilihat siapa saja, membocorkan nama file yang tidak seharusnya terlihat.",
                    'Matikan directory listing: "Options -Indexes" di Apache, atau "autoindex off;" di nginx.',
                    "GET $dir/  (HTTP 200)\n" . $this->snippet($res['body'], $hit[0][1]));
            }
        }

        $found = count($dirs);
        if ($found > 0) {
            $findings[] = $this->finding('discovery', "Ditemukan $found direktori dari petunjuk situs", 'info',
                'Direktori ini terbaca dari robots.txt, sitemap.xml, dan link di halaman, tanpa menebak.',
                $listing ? 'Periksa direktori yang directory listing-nya terbuka di atas.' : 'Tidak ada yang directory listing-nya terbuka.',
                implode("\n", array_map(fn($d) => "$d/", $dirs)));
        }

        return $findings;
    }

    /** @return string[] paths from a sitemap URL */
    private function fetchSitemap(string $url): array
    {
        try {
            $res = $this->http->fetch($url);
        } catch (\Throwable $e) {
            return [];
        }
        if ($res['status'] !== 200) {
            return [];
        }
        preg_match_all('#<loc>\s*([^<\s]+)#i', $res['body'], $m);
        return $m[1] ?? [];
    }

    /** Return the path if href is same-origin (or relative), else null. */
    private function sameOriginPath(string $baseUrl, string $href): ?string
    {
        $href = trim($href);
        if ($href === '' || str_starts_with($href, 'data:') || str_starts_with($href, 'mailto:') || str_starts_with($href, 'javascript:') || str_starts_with($href, 'tel:')) {
            return null;
        }
        $baseHost = parse_url($baseUrl, PHP_URL_HOST);
        if (preg_match('#^https?://#i', $href)) {
            return parse_url($href, PHP_URL_HOST) === $baseHost ? (parse_url($href, PHP_URL_PATH) ?: '/') : null;
        }
        if (str_starts_with($href, '//')) {
            return null;
        }
        return str_starts_with($href, '/') ? $href : '/' . $href;
    }

    /** A short, redacted snippet of response text as evidence. */
    private function snippet(string $body, int $offset = 0): string
    {
        $start = max(0, $offset - 20);
        $chunk = substr($body, $start, 400);
        $chunk = $this->redact($chunk);
        $chunk = preg_replace('/[^\P{C}\n]/u', '', $chunk) ?? $chunk; // drop control chars, keep newlines
        $chunk = trim($chunk);
        return strlen($body) > $start + 400 ? $chunk . ' ...' : $chunk;
    }

    /** Mask secret-looking values so evidence never prints real credentials. */
    private function redact(string $text): string
    {
        // KEY=secret  ->  KEY=***
        $text = preg_replace('/((?:password|passwd|pwd|secret|token|api[_-]?key|app[_-]?key|db[_-]?password)\s*[=:]\s*)\S+/i', '$1***', $text);
        return $text;
    }

    private function softNotFoundBaseline(string $baseUrl): array
    {
        $random = '/' . bin2hex(random_bytes(12)) . '-not-found';
        try {
            $res = $this->http->fetch(rtrim($baseUrl, '/') . $random);
            return ['soft404' => $res['status'] === 200];
        } catch (\Throwable $e) {
            return ['soft404' => false];
        }
    }

    private function finding(string $id, string $title, string $severity, string $detail, string $fix, string $evidence = ''): array
    {
        return compact('id', 'title', 'severity', 'detail', 'fix', 'evidence');
    }

    private function str(mixed $v): string
    {
        if (is_array($v)) {
            $v = implode('; ', $v);
        }
        $s = trim((string) $v);
        // truncate to 300 chars without needing the mbstring extension
        return preg_match('/^.{0,300}/su', $s, $m) ? $m[0] : substr($s, 0, 300);
    }
}
