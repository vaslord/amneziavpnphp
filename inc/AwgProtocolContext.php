<?php

/**
 * Paths and tooling for AmneziaWG / AmneziaWG 2.0 (awg2) inside Docker containers.
 */
class AwgProtocolContext
{
    public bool $isAwg2;
    public string $protocolSlug;
    public string $containerName;
    /** Config directory inside the container (volume mount target). */
    public string $containerConfigDir;
    /** Config directory on the Docker host (awg2 only). */
    public string $hostConfigDir;
    public string $configFile;
    public string $interfaceName;
    public string $wgTool;
    public string $quickTool;

    private function __construct(
        bool $isAwg2,
        string $protocolSlug,
        string $containerName,
        string $containerConfigDir,
        string $hostConfigDir,
        string $configFile
    ) {
        $this->isAwg2 = $isAwg2;
        $this->protocolSlug = $protocolSlug;
        $this->containerName = $containerName;
        $this->containerConfigDir = $containerConfigDir;
        $this->hostConfigDir = $hostConfigDir;
        $this->configFile = $configFile;
        $this->interfaceName = str_replace('.conf', '', $configFile);
        $this->wgTool = $isAwg2 ? 'awg' : 'wg';
        $this->quickTool = $isAwg2 ? 'awg-quick' : 'wg-quick';
    }

    public static function fromProtocolSlug(
        string $protocolSlug,
        array $serverData = [],
        ?array $protocolMetadata = null
    ): self {
        $slug = trim($protocolSlug) !== '' ? trim($protocolSlug) : (string) ($serverData['install_protocol'] ?? 'amnezia-wg');
        $isAwg2 = ($slug === 'awg2');

        $meta = is_array($protocolMetadata) ? $protocolMetadata : [];
        $containerName = trim((string) ($meta['container_name'] ?? ''));
        if ($containerName === '') {
            $containerName = trim((string) ($serverData['container_name'] ?? ''));
        }
        if ($containerName === '') {
            $containerName = $isAwg2 ? 'amnezia-awg2' : 'amnezia-awg';
        } elseif ($isAwg2 && stripos($containerName, 'awg2') === false && stripos($containerName, 'aivpn') === false) {
            // Multi-protocol row may point at another container; prefer awg2 metadata default.
            if (!empty($meta['container_name'])) {
                $containerName = trim((string) $meta['container_name']);
            } else {
                $containerName = 'amnezia-awg2';
            }
        }

        $containerConfigDir = '/opt/amnezia/awg';
        $hostConfigDir = $isAwg2 ? '/opt/amnezia/awg2' : '/opt/amnezia/awg';
        $configFile = $isAwg2 ? 'awg0.conf' : 'wg0.conf';

        return new self($isAwg2, $slug, $containerName, $containerConfigDir, $hostConfigDir, $configFile);
    }

    public static function fromProtocolRow(?array $protocolRow, array $serverData = []): self
    {
        $slug = (string) ($protocolRow['slug'] ?? ($serverData['install_protocol'] ?? 'amnezia-wg'));
        $meta = [];
        if ($protocolRow && !empty($protocolRow['definition'])) {
            $def = $protocolRow['definition'];
            if (is_string($def)) {
                $def = json_decode($def, true) ?: [];
            }
            if (is_array($def)) {
                $meta = $def['metadata'] ?? [];
            }
        }

        return self::fromProtocolSlug($slug, $serverData, $meta);
    }

    public function configPathInContainer(?string $configFile = null): string
    {
        $file = $configFile ?? $this->configFile;

        return $this->containerConfigDir . '/' . $file;
    }

    /**
     * @return list<string> Preferred config filenames (awg2: awg0 then wg0).
     */
    public function configFileCandidates(): array
    {
        if ($this->isAwg2) {
            return ['awg0.conf', 'wg0.conf'];
        }

        return ['wg0.conf'];
    }

    /**
     * Resolve which config file exists in the container.
     *
     * @param callable(string): string $execute docker exec via VpnServer::executeCommand
     */
    public function resolveConfigFile(callable $execute): string
    {
        $containerArg = escapeshellarg($this->containerName);
        foreach ($this->configFileCandidates() as $candidate) {
            $path = $this->configPathInContainer($candidate);
            $content = trim((string) $execute(
                "docker exec -i {$containerArg} cat " . escapeshellarg($path) . ' 2>/dev/null'
            ));
            if ($content !== '' && strpos($content, '[Interface]') !== false) {
                $this->configFile = $candidate;
                $this->interfaceName = str_replace('.conf', '', $candidate);

                return $candidate;
            }
        }

        return $this->configFile;
    }

    public static function interfaceNameFromConfigFile(string $configFile): string
    {
        return str_replace('.conf', '', $configFile);
    }

    /**
     * Probe whether the WireGuard/AWG interface is up (grep runs inside the container).
     */
    public function interfaceUpProbeCommand(): string
    {
        $inner = sprintf(
            '%s show %s 2>/dev/null | grep -q "listening port" && echo up || echo down',
            $this->wgTool,
            $this->interfaceName
        );

        return sprintf(
            'docker exec %s sh -c %s',
            escapeshellarg($this->containerName),
            escapeshellarg($inner)
        );
    }

    public function dumpCommand(bool $allInterfaces = false): string
    {
        if ($allInterfaces) {
            return sprintf(
                'docker exec %s %s show all dump 2>/dev/null',
                escapeshellarg($this->containerName),
                $this->wgTool
            );
        }

        return sprintf(
            'docker exec %s %s show %s dump 2>/dev/null',
            escapeshellarg($this->containerName),
            $this->wgTool,
            escapeshellarg($this->interfaceName)
        );
    }

    public function showCommand(): string
    {
        return sprintf(
            'docker exec %s %s show %s 2>/dev/null',
            escapeshellarg($this->containerName),
            $this->wgTool,
            escapeshellarg($this->interfaceName)
        );
    }

    /**
     * Whether stored awg_params in DB should be replaced from server config.
     *
     * @param array<string, mixed>|null $stored
     */
    public function awgParamsNeedSync(?array $stored): bool
    {
        if (!$this->isAwg2) {
            return empty($stored);
        }
        if (!is_array($stored) || $stored === []) {
            return true;
        }
        foreach (['H1', 'H2', 'H3', 'H4'] as $hk) {
            $val = $stored[$hk] ?? $stored[strtolower($hk)] ?? null;
            if ($val === null || $val === '') {
                return true;
            }
            if (is_numeric($val)) {
                return true;
            }
            if (is_string($val) && !preg_match('/^\d+-\d+$/', $val)) {
                return true;
            }
        }

        return false;
    }
}
