<?php
/**
 * Executes panel_jobs by type.
 */
class JobProcessor
{
    public static function run(array $job): void
    {
        $jobId = (int) $job['id'];
        $type = (string) $job['type'];
        $payload = JobQueue::decodePayload($job);

        try {
            $result = match ($type) {
                'socks5_install', 'socks5_uninstall' => Socks5Proxy::runJob($job),
                'client_create' => self::handleClientCreate($payload, (int) $job['user_id']),
                'client_bulk_assign' => self::handleClientBulkAssign($payload, (int) $job['user_id']),
                'client_revoke' => self::handleClientRevoke($payload),
                'client_restore' => self::handleClientRestore($payload),
                'client_delete' => self::handleClientDelete($payload),
                'server_sync_stats' => self::handleServerSyncStats($payload),
                default => throw new RuntimeException('Unknown job type: ' . $type),
            };
            JobQueue::complete($jobId, $result);
        } catch (Throwable $e) {
            error_log("Job #{$jobId} ({$type}) failed: " . $e->getMessage());
            JobQueue::fail($jobId, $e->getMessage());
        }
    }

    private static function handleClientCreate(array $payload, int $userId): array
    {
        $serverId = (int) ($payload['server_id'] ?? 0);
        $clientName = trim((string) ($payload['client_name'] ?? ''));
        if ($serverId <= 0 || $clientName === '') {
            throw new InvalidArgumentException('Invalid client_create payload');
        }

        $expiresInDays = isset($payload['expires_in_days']) ? (int) $payload['expires_in_days'] : null;
        if ($expiresInDays === 0) {
            $expiresInDays = null;
        }
        $protocolId = isset($payload['protocol_id']) && $payload['protocol_id'] !== '' && $payload['protocol_id'] !== null
            ? (int) $payload['protocol_id']
            : null;
        $username = isset($payload['username']) ? trim((string) $payload['username']) : null;
        $login = isset($payload['login']) ? trim((string) $payload['login']) : null;
        $trafficLimitBytes = isset($payload['traffic_limit_bytes']) ? (int) $payload['traffic_limit_bytes'] : null;

        if ($protocolId) {
            $pdo = DB::conn();
            $chk = $pdo->prepare('SELECT 1 FROM server_protocols WHERE server_id = ? AND protocol_id = ?');
            $chk->execute([$serverId, $protocolId]);
            if (!$chk->fetchColumn()) {
                $protocolId = null;
            }
        }

        $clientId = VpnClient::create($serverId, $userId, $clientName, $expiresInDays, $protocolId, $username, $login);

        if ($trafficLimitBytes !== null && $trafficLimitBytes > 0) {
            $client = new VpnClient($clientId);
            $client->setTrafficLimit($trafficLimitBytes);
        }

        return [
            'client_id' => $clientId,
            'redirect' => '/clients/' . $clientId,
        ];
    }

    /** Create selected AWG client groups on one server and keep a per-client result. */
    private static function handleClientBulkAssign(array $payload, int $userId): array
    {
        $serverId = (int) ($payload['server_id'] ?? 0);
        $protocolId = (int) ($payload['protocol_id'] ?? 0);
        $names = is_array($payload['client_names'] ?? null) ? $payload['client_names'] : [];
        $names = array_values(array_unique(array_filter(array_map(static fn ($name): string => trim((string) $name), $names))));
        if ($serverId <= 0 || $protocolId <= 0 || $names === []) {
            throw new InvalidArgumentException('Invalid client_bulk_assign payload');
        }

        $server = new VpnServer($serverId);
        $serverData = $server->getData();
        if (!$serverData || (int) ($serverData['user_id'] ?? 0) !== $userId || ($serverData['status'] ?? '') !== 'active') {
            throw new RuntimeException('Target AWG server is unavailable');
        }

        $pdo = DB::conn();
        $installed = $pdo->prepare('SELECT 1 FROM server_protocols WHERE server_id = ? AND protocol_id = ?');
        $installed->execute([$serverId, $protocolId]);
        if (!$installed->fetchColumn()) {
            throw new RuntimeException('AWG2 is not installed on the target server');
        }

        $expiresInDays = isset($payload['expires_in_days']) && (int) $payload['expires_in_days'] > 0
            ? (int) $payload['expires_in_days']
            : null;
        $trafficLimitBytes = isset($payload['traffic_limit_bytes']) && (int) $payload['traffic_limit_bytes'] > 0
            ? (int) $payload['traffic_limit_bytes']
            : null;
        $exists = $pdo->prepare('SELECT 1 FROM vpn_clients WHERE server_id = ? AND name = ? LIMIT 1');
        $source = $pdo->prepare("SELECT 1 FROM vpn_clients c INNER JOIN protocols p ON p.id = c.protocol_id WHERE c.user_id = ? AND c.name = ? AND p.slug = 'awg2' LIMIT 1");

        $created = [];
        $skipped = [];
        $failed = [];
        foreach ($names as $name) {
            $source->execute([$userId, $name]);
            if (!$source->fetchColumn()) {
                $failed[] = ['name' => $name, 'error' => 'Клиент недоступен'];
                continue;
            }
            $exists->execute([$serverId, $name]);
            if ($exists->fetchColumn()) {
                $skipped[] = ['name' => $name, 'reason' => 'Клиент уже добавлен на сервер'];
                continue;
            }
            try {
                $clientId = VpnClient::create($serverId, $userId, $name, $expiresInDays, $protocolId, '', $name);
                if ($trafficLimitBytes !== null) {
                    (new VpnClient($clientId))->setTrafficLimit($trafficLimitBytes);
                }
                $created[] = ['name' => $name, 'client_id' => $clientId];
            } catch (Throwable $e) {
                $failed[] = ['name' => $name, 'error' => $e->getMessage()];
            }
        }

        return ['created' => $created, 'skipped' => $skipped, 'failed' => $failed];
    }

    private static function handleClientRevoke(array $payload): array
    {
        $clientId = (int) ($payload['client_id'] ?? 0);
        if ($clientId <= 0) {
            throw new InvalidArgumentException('Invalid client_revoke payload');
        }
        $client = new VpnClient($clientId);
        if (!$client->revoke()) {
            throw new RuntimeException('Failed to revoke client');
        }
        $data = $client->getData();
        return [
            'client_id' => $clientId,
            'server_id' => (int) ($data['server_id'] ?? 0),
            'message' => 'Client revoked',
        ];
    }

    private static function handleClientRestore(array $payload): array
    {
        $clientId = (int) ($payload['client_id'] ?? 0);
        if ($clientId <= 0) {
            throw new InvalidArgumentException('Invalid client_restore payload');
        }
        $client = new VpnClient($clientId);
        if (!$client->restore()) {
            throw new RuntimeException('Failed to restore client');
        }
        $data = $client->getData();
        return [
            'client_id' => $clientId,
            'server_id' => (int) ($data['server_id'] ?? 0),
            'message' => 'Client restored',
        ];
    }

    private static function handleClientDelete(array $payload): array
    {
        $clientId = (int) ($payload['client_id'] ?? 0);
        if ($clientId <= 0) {
            throw new InvalidArgumentException('Invalid client_delete payload');
        }
        $client = new VpnClient($clientId);
        $data = $client->getData();
        $serverId = (int) ($data['server_id'] ?? 0);
        if (!$client->delete()) {
            throw new RuntimeException('Failed to delete client');
        }
        return [
            'client_id' => $clientId,
            'server_id' => $serverId,
            'message' => 'Client deleted',
        ];
    }

    private static function handleServerSyncStats(array $payload): array
    {
        $serverId = (int) ($payload['server_id'] ?? 0);
        if ($serverId <= 0) {
            throw new InvalidArgumentException('Invalid server_sync_stats payload');
        }
        $synced = VpnClient::syncAllStatsForServer($serverId);
        return [
            'server_id' => $serverId,
            'synced' => $synced,
        ];
    }
}
