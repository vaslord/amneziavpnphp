<?php
/**
 * Public HMAC-based links for AWG2 clients (no panel auth).
 */
class Awg2ClientLink
{
    public static function getSecret(): string
    {
        $secret = Config::get('CLIENT_LINK_SECRET');
        if ($secret === null || $secret === '') {
            $secret = Config::get('JWT_SECRET');
        }
        if ($secret === null || $secret === '') {
            throw new RuntimeException('CLIENT_LINK_SECRET or JWT_SECRET must be configured');
        }
        return $secret;
    }

    public static function normalizeClientName(string $name): string
    {
        return str_replace(' ', '_', trim($name));
    }

    public static function tokenForClientName(string $name): string
    {
        $normalized = self::normalizeClientName($name);
        $raw = hash_hmac('sha256', $normalized, self::getSecret(), true);
        return rtrim(strtr(base64_encode($raw), '+/', '-_'), '=');
    }

    /**
     * @return list<array<string, mixed>>
     */
    public static function findClientsByToken(string $token): array
    {
        $pdo = DB::conn();
        $stmt = $pdo->query("
            SELECT c.*, s.name AS server_name, s.host AS server_host
            FROM vpn_clients c
            INNER JOIN protocols p ON p.id = c.protocol_id
            INNER JOIN vpn_servers s ON s.id = c.server_id
            WHERE p.slug = 'awg2' AND c.status = 'active'
        ");
        $rows = $stmt->fetchAll(PDO::FETCH_ASSOC) ?: [];
        $matched = [];
        foreach ($rows as $row) {
            $rowToken = self::tokenForClientName((string) ($row['name'] ?? ''));
            if (hash_equals($rowToken, $token)) {
                $matched[] = $row;
            }
        }
        return $matched;
    }

    /**
     * @return array<string, mixed>|null
     */
    public static function resolveClient(string $token, int $serverId): ?array
    {
        foreach (self::findClientsByToken($token) as $row) {
            if ((int) ($row['server_id'] ?? 0) === $serverId) {
                return $row;
            }
        }
        return null;
    }

    public static function sendNoIndexHeaders(): void
    {
        header('X-Robots-Tag: noindex, nofollow, noarchive');
    }

    public static function publicUrlForClientName(string $name): string
    {
        $token = self::tokenForClientName($name);
        return '/awg2/clients-links/' . $token;
    }
}
