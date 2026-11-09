<?php
/**
 * MySQL-backed job queue for long-running SSH operations.
 */
class JobQueue
{
    public const STATUS_PENDING = 'pending';
    public const STATUS_RUNNING = 'running';
    public const STATUS_DONE = 'done';
    public const STATUS_FAILED = 'failed';

    /** Job types that must not overlap on the same server_id. */
    private const SERVER_SERIAL_TYPES = [
        'client_create',
        'client_bulk_assign',
        'client_revoke',
        'client_restore',
        'client_delete',
        'server_sync_stats',
        'socks5_install',
        'socks5_uninstall',
    ];

    public static function enqueue(string $type, array $payload, int $userId, ?int $serverId = null): int
    {
        $pdo = DB::conn();
        $stmt = $pdo->prepare('
            INSERT INTO panel_jobs (type, payload, status, user_id, server_id)
            VALUES (?, ?, ?, ?, ?)
        ');
        $stmt->execute([
            $type,
            json_encode($payload, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES),
            self::STATUS_PENDING,
            $userId,
            $serverId,
        ]);
        return (int) $pdo->lastInsertId();
    }

    public static function get(int $jobId): ?array
    {
        $pdo = DB::conn();
        $stmt = $pdo->prepare('SELECT * FROM panel_jobs WHERE id = ? LIMIT 1');
        $stmt->execute([$jobId]);
        $row = $stmt->fetch(PDO::FETCH_ASSOC);
        return $row ?: null;
    }

    public static function canUserView(array $job, array $user): bool
    {
        if (in_array($job['type'] ?? '', Socks5Proxy::JOB_TYPES, true)) {
            return Socks5Proxy::isAdmin($user);
        }
        if (($user['role'] ?? '') === 'admin' || !empty($user['is_admin'])) {
            return true;
        }
        return (int) ($job['user_id'] ?? 0) === (int) ($user['id'] ?? 0);
    }

    /**
     * Claim next pending job (transaction + SKIP LOCKED).
     */
    public static function claimNext(int $maxJobSeconds = 120): ?array
    {
        $pdo = DB::conn();
        $pdo->beginTransaction();
        try {
            self::failStaleRunningJobs($pdo, $maxJobSeconds);

            $serialTypes = self::SERVER_SERIAL_TYPES;
            $placeholders = implode(',', array_fill(0, count($serialTypes), '?'));

            $sql = "
                SELECT j.id FROM panel_jobs j
                WHERE j.status = ?
                AND (
                    j.server_id IS NULL
                    OR j.type NOT IN ($placeholders)
                    OR NOT EXISTS (
                        SELECT 1 FROM panel_jobs r
                        WHERE r.status = ?
                          AND r.server_id = j.server_id
                          AND r.id != j.id
                    )
                )
                ORDER BY j.created_at ASC
                LIMIT 1
                FOR UPDATE SKIP LOCKED
            ";
            $params = array_merge(
                [self::STATUS_PENDING],
                $serialTypes,
                [self::STATUS_RUNNING]
            );
            $stmt = $pdo->prepare($sql);
            $stmt->execute($params);
            $jobId = $stmt->fetchColumn();
            if (!$jobId) {
                $pdo->commit();
                return null;
            }

            $upd = $pdo->prepare('
                UPDATE panel_jobs
                SET status = ?, started_at = NOW()
                WHERE id = ? AND status = ?
            ');
            $upd->execute([self::STATUS_RUNNING, $jobId, self::STATUS_PENDING]);

            $fetch = $pdo->prepare('SELECT * FROM panel_jobs WHERE id = ?');
            $fetch->execute([$jobId]);
            $job = $fetch->fetch(PDO::FETCH_ASSOC);
            $pdo->commit();
            return $job ?: null;
        } catch (Throwable $e) {
            $pdo->rollBack();
            throw $e;
        }
    }

    public static function complete(int $jobId, array $result): void
    {
        $pdo = DB::conn();
        $stmt = $pdo->prepare('
            UPDATE panel_jobs
            SET status = ?, result = ?, finished_at = NOW(), error_message = NULL
            WHERE id = ?
        ');
        $stmt->execute([
            self::STATUS_DONE,
            json_encode($result, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES),
            $jobId,
        ]);
    }

    public static function fail(int $jobId, string $message, ?array $result = null): void
    {
        $pdo = DB::conn();
        $stmt = $pdo->prepare('
            UPDATE panel_jobs
            SET status = ?, error_message = ?, result = ?, finished_at = NOW()
            WHERE id = ?
        ');
        $stmt->execute([
            self::STATUS_FAILED,
            $message,
            $result !== null ? json_encode($result, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES) : null,
            $jobId,
        ]);
    }

    public static function decodePayload(array $job): array
    {
        $raw = $job['payload'] ?? '{}';
        if (is_array($raw)) {
            return $raw;
        }
        $decoded = json_decode((string) $raw, true);
        return is_array($decoded) ? $decoded : [];
    }

    public static function decodeResult(array $job): array
    {
        $raw = $job['result'] ?? null;
        if (is_array($raw)) {
            return $raw;
        }
        if ($raw === null || $raw === '') {
            return [];
        }
        $decoded = json_decode((string) $raw, true);
        return is_array($decoded) ? $decoded : [];
    }

    public static function toApiArray(array $job): array
    {
        return [
            'id' => (int) $job['id'],
            'type' => $job['type'],
            'status' => $job['status'],
            'server_id' => $job['server_id'] !== null ? (int) $job['server_id'] : null,
            'error' => $job['error_message'],
            'result' => self::decodeResult($job),
            'created_at' => $job['created_at'],
            'started_at' => $job['started_at'],
            'finished_at' => $job['finished_at'],
        ];
    }

    private static function failStaleRunningJobs(PDO $pdo, int $maxSeconds): void
    {
        $stmt = $pdo->prepare('
            UPDATE panel_jobs
            SET status = ?, error_message = ?, finished_at = NOW()
            WHERE status = ?
              AND started_at IS NOT NULL
              AND started_at < DATE_SUB(NOW(), INTERVAL (CASE WHEN type IN (\'socks5_install\', \'socks5_uninstall\') THEN 900 ELSE ? END) SECOND)
        ');
        $stmt->execute([
            self::STATUS_FAILED,
            'Job timed out',
            self::STATUS_RUNNING,
            $maxSeconds,
        ]);
    }
}
