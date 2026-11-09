#!/usr/bin/env php
<?php
/**
 * Process panel_jobs queue (SSH-heavy client operations).
 * Run via cron or long-lived loop.
 */

require_once __DIR__ . '/../vendor/autoload.php';
require_once __DIR__ . '/../inc/Config.php';
Config::load(__DIR__ . '/../.env');
require_once __DIR__ . '/../inc/DB.php';
require_once __DIR__ . '/../inc/VpnServer.php';
require_once __DIR__ . '/../inc/VpnClient.php';
require_once __DIR__ . '/../inc/JobQueue.php';
require_once __DIR__ . '/../inc/JobProcessor.php';

date_default_timezone_set('UTC');

// Writable by www-data (cron user); /var/run lock breaks after a root run
$lockFile = getenv('JOB_WORKER_LOCK_FILE') ?: (__DIR__ . '/../logs/process_panel_jobs.lock');
$lockDir = dirname($lockFile);
if (!is_dir($lockDir)) {
    @mkdir($lockDir, 0775, true);
}
$lockFp = @fopen($lockFile, 'c');
if (!$lockFp || !flock($lockFp, LOCK_EX | LOCK_NB)) {
    exit(0);
}

$maxRuntime = (int) (getenv('JOB_WORKER_MAX_RUNTIME') ?: 55);
$idleSleep = (int) (getenv('JOB_WORKER_IDLE_SLEEP') ?: 2);
$deadline = time() + $maxRuntime;
$processed = 0;

while (time() < $deadline) {
    try {
        $job = JobQueue::claimNext(120);
    } catch (Throwable $e) {
        error_log('JobQueue claim failed: ' . $e->getMessage());
        sleep($idleSleep);
        continue;
    }

    if ($job === null) {
        sleep($idleSleep);
        continue;
    }

    JobProcessor::run($job);
    $processed++;
}

flock($lockFp, LOCK_UN);
fclose($lockFp);

if ($processed > 0) {
    echo '[' . date('Y-m-d H:i:s') . "] Processed {$processed} job(s)\n";
}
