<?php

/** One shared SOCKS5 profile, independent of the server's primary VPN. */
class Socks5Proxy
{
    public const SLUG = 'socks5';
    public const IMAGE = 'ghcr.io/xtls/xray-core:26.10.31';
    public const JOB_TYPES = ['socks5_install', 'socks5_uninstall'];

    public static function isAdmin(array $user): bool
    {
        return ($user['role'] ?? '') === 'admin';
    }

    public static function visibleProtocols(array $rows, array $user): array
    {
        return self::isAdmin($user) ? $rows : array_values(array_filter($rows,
            static fn (array $row): bool => ($row['slug'] ?? '') !== self::SLUG));
    }

    public static function clientProtocols(array $rows): array
    {
        return array_values(array_filter($rows, static fn (array $row): bool => ($row['slug'] ?? '') !== self::SLUG));
    }

    public static function latestJob(int $serverId): ?array
    {
        $stmt = DB::conn()->prepare("SELECT * FROM panel_jobs WHERE server_id = ? AND type IN ('socks5_install', 'socks5_uninstall') ORDER BY id DESC LIMIT 1");
        $stmt->execute([$serverId]);
        return $stmt->fetch() ?: null;
    }

    public static function assertBulkRemovalAllowed(int $serverId, array $protocols, array $user): void
    {
        $job = self::latestJob($serverId);
        $pending = $job && in_array($job['status'], ['pending', 'running'], true);
        if ((in_array(self::SLUG, array_column($protocols, 'slug'), true) || $pending) && !self::isAdmin($user)) {
            throw new RuntimeException('Удаление SOCKS5 доступно только администратору', 403);
        }
        if ($pending) {
            throw new RuntimeException('Дождитесь завершения операции SOCKS5', 409);
        }
    }

    /** Lock the server row so simultaneous clicks cannot enqueue duplicate operations. */
    public static function enqueue(int $serverId, string $action, array $user): int
    {
        if (!self::isAdmin($user)) {
            throw new RuntimeException('SOCKS5 доступен только администратору');
        }
        $type = 'socks5_' . $action;
        if (!in_array($type, self::JOB_TYPES, true)) {
            throw new InvalidArgumentException('Unknown SOCKS5 operation');
        }
        $pdo = DB::conn();
        $pdo->beginTransaction();
        try {
            $stmt = $pdo->prepare('SELECT id FROM vpn_servers WHERE id = ? FOR UPDATE');
            $stmt->execute([$serverId]);
            if (!$stmt->fetchColumn()) {
                throw new RuntimeException('Server not found');
            }
            $pending = $pdo->prepare("SELECT id, type FROM panel_jobs WHERE server_id = ? AND type IN ('socks5_install', 'socks5_uninstall') AND status IN ('pending', 'running') ORDER BY id LIMIT 1");
            $pending->execute([$serverId]);
            $job = $pending->fetch();
            if ($job && $job['type'] !== $type) {
                throw new RuntimeException('Дождитесь завершения текущей операции SOCKS5');
            }
            $id = $job ? (int) $job['id'] : JobQueue::enqueue($type, ['server_id' => $serverId], (int) $user['id'], $serverId);
            $pdo->commit();
            return $id;
        } catch (Throwable $e) {
            if ($pdo->inTransaction()) $pdo->rollBack();
            throw $e;
        }
    }

    public static function runJob(array $job): array
    {
        // Recheck role at execution time (an administrator may have been demoted).
        $stmt = DB::conn()->prepare('SELECT role FROM users WHERE id = ?');
        $stmt->execute([(int) $job['user_id']]);
        if ($stmt->fetchColumn() !== 'admin') {
            throw new RuntimeException('SOCKS5 доступен только администратору');
        }
        $server = new VpnServer((int) $job['server_id']);
        return self::apply($server, $job['type'] === 'socks5_install' ? 'install' : 'uninstall');
    }

    /** Called only by the authorised job worker; never log the returned remote profile. */
    public static function apply(VpnServer $server, string $action): array
    {
        if (!in_array($action, ['install', 'uninstall'], true)) throw new InvalidArgumentException('Unknown SOCKS5 operation');
        $pdo = DB::conn();
        $stmt = $pdo->prepare("SELECT p.id, sp.config_data FROM protocols p LEFT JOIN server_protocols sp ON sp.protocol_id = p.id AND sp.server_id = ? WHERE p.slug = 'socks5'");
        $stmt->execute([$server->getId()]);
        $row = $stmt->fetch();
        if (!$row) throw new RuntimeException('SOCKS5 protocol is not registered');
        $saved = json_decode($row['config_data'] ?? '{}', true) ?: [];
        $request = [
            'action' => $action,
            'image' => self::IMAGE,
            'username' => $saved['extras']['username'] ?? ('proxy_' . bin2hex(random_bytes(6))),
            'password' => $saved['extras']['password'] ?? bin2hex(random_bytes(24)),
            'port' => $saved['server_port'] ?? null,
        ];
        $source = file_get_contents(__DIR__ . '/../scripts/socks5_remote.py');
        if ($source === false) throw new RuntimeException('SOCKS5 installer is unavailable');
        $source = str_replace('# PANEL_REQUEST', 'REQUEST = json.loads(base64.b64decode("' . base64_encode(json_encode($request, JSON_THROW_ON_ERROR)) . '"))', $source);
        // Restrict the whole remote operation, including bootstrap, to less than the job deadline.
        $bootstrap = $action === 'install' ? <<<'SH'
if ! command -v python3 >/dev/null || ! command -v docker >/dev/null || ! command -v flock >/dev/null; then
  export DEBIAN_FRONTEND=noninteractive
  apt-get update -qq >/dev/null 2>&1
  apt-get install -y -qq python3 docker.io util-linux ca-certificates >/dev/null 2>&1
fi
systemctl start docker >/dev/null 2>&1 || true
SH : 'command -v python3 >/dev/null';
        $marker = '__SOCKS5_EXIT_' . bin2hex(random_bytes(12)) . '__';
        $command = "timeout --signal=TERM --kill-after=10s 840s bash <<'SOCKS5_SETUP'\nset -e\numask 077\n"
            . $bootstrap . "\nmkdir -p /opt/amnezia\nflock -w 10 /opt/amnezia/.socks5.lock python3 - <<'SOCKS5_PY'\n"
            . $source . "\nSOCKS5_PY\nSOCKS5_SETUP\nprintf '\\n" . $marker . "%s\\n' \"$?\"";
        $output = $server->executeCommand($command, true);
        if (!preg_match('/\n' . preg_quote($marker, '/') . '(\d+)\s*$/', $output, $match, PREG_OFFSET_CAPTURE)) {
            throw new RuntimeException('SOCKS5: связь с сервером прервана. Повторите операцию после проверки SSH.');
        }
        $body = substr($output, 0, $match[0][1]);
        // Bootstrap/SSH diagnostics are never returned verbatim: they may include secrets.
        $result = json_decode(trim($body), true);
        if ((int) $match[1][0] !== 0 || !is_array($result) || empty($result['success'])) {
            $stage = is_array($result) ? ($result['stage'] ?? '') : '';
            $stages = ['configuration', 'docker', 'image', 'port', 'start', 'authentication', 'connectivity', 'uninstall'];
            throw new RuntimeException('SOCKS5: операция не завершена' . (in_array($stage, $stages, true) ? ' (этап: ' . $stage . ')' : '') . '. Проверьте SSH, Docker и доступ сервера в интернет; повторный запуск сохранит профиль.');
        }
        if ($action === 'uninstall') {
            $pdo->prepare('DELETE FROM server_protocols WHERE server_id = ? AND protocol_id = ?')->execute([$server->getId(), (int) $row['id']]);
        } else {
            $profile = $result['profile'] ?? [];
            if (!self::validProfile($profile)) throw new RuntimeException('SOCKS5: сервер вернул некорректный профиль');
            $config = [
                'server_host' => $server->getData()['host'],
                'server_port' => (int) $profile['port'],
                'extras' => ['username' => $profile['username'], 'password' => $profile['password'], 'image' => self::IMAGE, 'container_name' => 'amnezia-socks5'],
            ];
            $stmt = $pdo->prepare('INSERT INTO server_protocols (server_id, protocol_id, config_data, applied_at, created_at) VALUES (?, ?, ?, NOW(), NOW()) ON DUPLICATE KEY UPDATE config_data = VALUES(config_data), applied_at = NOW()');
            $stmt->execute([$server->getId(), (int) $row['id'], json_encode($config, JSON_THROW_ON_ERROR)]);
        }
        return ['success' => true, 'server_id' => $server->getId(), 'message' => $action === 'install' ? 'SOCKS5 установлен' : 'SOCKS5 удалён'];
    }

    public static function validProfile(array $profile): bool
    {
        return isset($profile['port'], $profile['username'], $profile['password'])
            && is_numeric($profile['port']) && (int) $profile['port'] >= 1 && (int) $profile['port'] <= 65535
            && is_string($profile['username']) && preg_match('/^[a-zA-Z0-9_-]{1,64}$/D', $profile['username'])
            && is_string($profile['password']) && preg_match('/^[a-zA-Z0-9_-]{16,128}$/D', $profile['password']);
    }

    public static function connectionLinks(string $host, int $port, string $username, string $password): array
    {
        $host = trim($host, '[]');
        $uriHost = strpos($host, ':') !== false ? '[' . $host . ']' : $host;
        return [
            'uri' => 'socks5://' . rawurlencode($username) . ':' . rawurlencode($password) . '@' . $uriHost . ':' . $port,
            'telegram' => 'tg://socks?' . http_build_query(['server' => $host, 'port' => $port, 'user' => $username, 'pass' => $password], '', '&', PHP_QUERY_RFC3986),
        ];
    }
}
