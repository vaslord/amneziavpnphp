<?php
/** php scripts/test_socks5.php [--database]
 * --database creates and drops a separate database using DB_ROOT_PASSWORD.
 * No production rows are read or modified; only table definitions are copied.
 */
require __DIR__ . '/../vendor/autoload.php';

function check(bool $ok, string $message): void {
    if (!$ok) throw new RuntimeException($message);
}
function rejects(callable $call, string $message): void {
    try { $call(); } catch (RuntimeException | InvalidArgumentException $e) { return; }
    throw new RuntimeException($message);
}
$admin = ['id' => 1, 'role' => 'admin'];
$user = ['id' => 1, 'role' => 'user'];
$rows = [['slug' => 'awg2'], ['slug' => 'socks5', 'config_data' => 'private']];
check(count(Socks5Proxy::visibleProtocols($rows, $admin)) === 2, 'Admin catalogue');
check(Socks5Proxy::visibleProtocols($rows, $user) === [['slug' => 'awg2']], 'Profile disclosure to non-admin');
check(Socks5Proxy::clientProtocols($rows) === [['slug' => 'awg2']], 'Client protocol selection');
check(!JobQueue::canUserView(['type' => 'socks5_install', 'user_id' => 1], $user), 'Demoted job owner must not view SOCKS5 job');
check(JobQueue::canUserView(['type' => 'socks5_install', 'user_id' => 2], $admin), 'Admin job visibility');
check(Socks5Proxy::validProfile(['port' => 54321, 'username' => 'proxy_test', 'password' => str_repeat('a', 48)]), 'Valid profile');
check(!Socks5Proxy::validProfile(['port' => 70000, 'username' => 'proxy_test', 'password' => 'short']), 'Invalid profile');
$links = Socks5Proxy::connectionLinks('2001:db8::1', 54321, 'a+b', 'p&x');
check(str_contains($links['uri'], 'a%2Bb:p%26x@[2001:db8::1]:54321'), 'IPv6 URL escaping');
check(str_contains($links['telegram'], 'pass=p%26x'), 'Telegram escaping');

$twig = new Twig\Environment(new Twig\Loader\FilesystemLoader(__DIR__ . '/../templates'), ['autoescape' => 'html']);
$twig->addFunction(new Twig\TwigFunction('t', fn ($key, ...$args) => $key));
$twig->addFunction(new Twig\TwigFunction('getFlag', fn ($key) => $key));
$twig->addFilter(new Twig\TwigFilter('bytes_format', fn ($value) => $value));
$twig->addFilter(new Twig\TwigFilter('trans', fn ($key) => $key));
$secret = 'test_password_123456789';
$profile = ['protocol_id' => 2, 'slug' => 'socks5', 'name' => 'SOCKS5 Proxy', 'server_host' => 'proxy.example', 'server_port' => 54321,
    'extras' => ['username' => 'test_user', 'password' => $secret],
    'socks5_links' => Socks5Proxy::connectionLinks('proxy.example', 54321, 'test_user', $secret)];
$context = ['server' => ['id' => 1, 'name' => 'Test', 'host' => 'proxy.example', 'status' => 'active'], 'clients' => [],
    'server_protocols' => [$profile], 'client_protocols' => [], 'available_protocols' => [], 'user' => $admin];
$html = $twig->render('servers/view.twig', $context);
check(str_contains($html, 'type="password" value="' . $secret . '"'), 'Masked profile rendering');
check(str_contains($html, 'tg://socks?'), 'Telegram link rendering');
$context['user'] = $user;
$htmlUser = $twig->render('servers/view.twig', $context);
check(!str_contains($htmlUser, $secret), 'Template password disclosure');
if ($output = getenv('SOCKS5_TEST_HTML')) file_put_contents($output, $html);
echo "PASS: visibility, profile validation, URI escaping, template rendering\n";

if (!in_array('--database', $argv, true)) exit(0);
Config::load(__DIR__ . '/../.env');
$original = Config::get('DB_DATABASE', 'amnezia_panel');
check((bool) preg_match('/^[a-zA-Z0-9_]+$/D', $original), 'Unexpected source schema name');
$root = new PDO('mysql:host=' . Config::get('DB_HOST', 'db') . ';port=' . Config::get('DB_PORT', '3306'), 'root', Config::get('DB_ROOT_PASSWORD'), [PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION]);
$database = 'amnezia_socks5_test_' . bin2hex(random_bytes(6));
$root->exec("CREATE DATABASE `$database` CHARACTER SET utf8mb4");
try {
    foreach (['users', 'vpn_servers', 'protocols', 'server_protocols', 'panel_jobs'] as $table) {
        $root->exec("CREATE TABLE `$database`.`$table` LIKE `$original`.`$table`");
    }
    $db = new PDO('mysql:host=' . Config::get('DB_HOST', 'db') . ';port=' . Config::get('DB_PORT', '3306') . ';dbname=' . $database, 'root', Config::get('DB_ROOT_PASSWORD'), [PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION, PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC, PDO::ATTR_EMULATE_PREPARES => false]);
    $property = new ReflectionProperty(DB::class, 'pdo');
    $property->setAccessible(true);
    $property->setValue(null, $db);
    $migration = file_get_contents(__DIR__ . '/../migrations/076_add_socks5_proxy.sql');
    $db->exec($migration);
    $db->exec($migration);
    check((int) $db->query("SELECT COUNT(*) FROM protocols WHERE slug='socks5'")->fetchColumn() === 1, 'Idempotent migration');
    $protocolId = (int) $db->query("SELECT id FROM protocols WHERE slug='socks5'")->fetchColumn();
    $db->exec("INSERT INTO users (id, name, email, password_hash, role, status) VALUES (1,'Test','socks-test@example.invalid','unused','admin','active')");
    $data = ['user_id' => 1, 'name' => 'Test', 'host' => '127.0.0.1', 'port' => 22, 'username' => 'root', 'password' => 'unused', 'install_protocol' => 'awg2'];
    $serverId = VpnServer::create($data);
    $db->exec("UPDATE vpn_servers SET status='active', vpn_port=54814, server_public_key='existing-vpn-key' WHERE id=$serverId");
    rejects(fn () => VpnServer::create(array_merge($data, ['install_protocol' => 'socks5'])), 'Primary SOCKS5 must be rejected');
    rejects(fn () => VpnClient::create($serverId, 1, 'Forbidden client', null, $protocolId), 'SOCKS5 client creation must be rejected');
    rejects(fn () => Socks5Proxy::enqueue($serverId, 'install', $user), 'Non-admin enqueue');
    rejects(fn () => Socks5Proxy::assertBulkRemovalAllowed($serverId, $rows, $user), 'Non-admin bulk removal');
    Socks5Proxy::assertBulkRemovalAllowed($serverId, $rows, $admin);
    $id = Socks5Proxy::enqueue($serverId, 'install', $admin);
    rejects(fn () => Socks5Proxy::assertBulkRemovalAllowed($serverId, [], $user), 'Non-admin bulk removal during pending installation');
    rejects(fn () => Socks5Proxy::assertBulkRemovalAllowed($serverId, [], $admin), 'Bulk removal during pending installation');
    check((int) Socks5Proxy::latestJob($serverId)['id'] === $id, 'Pending job survives page reload');
    check(Socks5Proxy::enqueue($serverId, 'install', $admin) === $id, 'Duplicate job');
    rejects(fn () => Socks5Proxy::enqueue($serverId, 'uninstall', $admin), 'Conflicting operation');
    $job = JobQueue::claimNext();
    check((int) $job['id'] === $id, 'Queue claim');
    $db->exec("UPDATE panel_jobs SET started_at=DATE_SUB(NOW(), INTERVAL 3 MINUTE) WHERE id=$id");
    $clientJob = JobQueue::enqueue('client_create', [], 1, $serverId);
    check(JobQueue::claimNext() === null, 'Server operation serialization');
    check(JobQueue::get($id)['status'] === 'running', 'SOCKS5 must survive normal 120 second deadline');
    $other = JobQueue::enqueue('server_sync_stats', [], 1, null);
    $db->exec("UPDATE panel_jobs SET status='running', started_at=DATE_SUB(NOW(), INTERVAL 3 MINUTE) WHERE id=$other");
    JobQueue::claimNext();
    check(JobQueue::get($other)['status'] === 'failed', 'Normal job timeout unchanged');
    $db->exec("UPDATE panel_jobs SET started_at=DATE_SUB(NOW(), INTERVAL 16 MINUTE) WHERE id=$id");
    check((int) JobQueue::claimNext()['id'] === $clientJob, 'SOCKS5 timeout releases next job');
    check(JobQueue::get($id)['status'] === 'failed', 'SOCKS5 15 minute deadline');
    $db->exec("UPDATE users SET role='user' WHERE id=1");
    rejects(fn () => Socks5Proxy::runJob(['user_id' => 1, 'server_id' => $serverId, 'type' => 'socks5_install']), 'Worker must recheck role');
    $db->exec("UPDATE users SET role='admin' WHERE id=1");

    class FakeSocksServer extends VpnServer {
        public bool $fail = false;
        public bool $disconnect = false;
        public string $action = 'install';
        public function executeCommand(string $command, bool $sudo = null): string {
            $process = proc_open(['bash', '-n'], [['pipe', 'r'], ['pipe', 'w'], ['pipe', 'w']], $pipes);
            fwrite($pipes[0], $command);
            fclose($pipes[0]);
            stream_get_contents($pipes[1]); fclose($pipes[1]);
            stream_get_contents($pipes[2]); fclose($pipes[2]);
            check(proc_close($process) === 0, 'Generated SSH wrapper syntax');
            if ($this->disconnect) return 'connection lost';
            preg_match('/__SOCKS5_EXIT_[a-f0-9]+__/', $command, $match);
            if ($this->fail) return 'DO NOT LEAK test_password_123456789' . "\n" . $match[0] . '1';
            $result = ['success' => true];
            if ($this->action === 'install') $result['profile'] = ['port' => 54321, 'username' => 'test_user', 'password' => 'test_password_123456789'];
            return json_encode($result) . "\n" . $match[0] . '0';
        }
    }
    $server = new FakeSocksServer($serverId);
    $before = $db->query("SELECT * FROM vpn_servers WHERE id=$serverId")->fetch();
    $result = Socks5Proxy::apply($server, 'install');
    check(!str_contains(json_encode($result), $secret), 'Job result contains credentials');
    Socks5Proxy::apply($server, 'install');
    check((int) $db->query("SELECT COUNT(*) FROM server_protocols WHERE server_id=$serverId")->fetchColumn() === 1, 'One profile per server');
    $saved = json_decode($db->query("SELECT config_data FROM server_protocols WHERE server_id=$serverId")->fetchColumn(), true);
    check($saved['extras']['password'] === $secret, 'Credentials persisted');
    $server->fail = true;
    try { Socks5Proxy::apply($server, 'install'); throw new LogicException('Failure accepted'); }
    catch (RuntimeException $e) { check(!str_contains($e->getMessage(), $secret), 'Failure exposed credentials'); }
    $server->fail = false;
    $server->disconnect = true;
    rejects(fn () => Socks5Proxy::apply($server, 'install'), 'Lost SSH response must fail');
    $server->disconnect = false;
    $server->action = 'uninstall';
    Socks5Proxy::apply($server, 'uninstall');
    check((int) $db->query("SELECT COUNT(*) FROM server_protocols WHERE server_id=$serverId")->fetchColumn() === 0, 'Removal cleanup');
    check($before === $db->query("SELECT * FROM vpn_servers WHERE id=$serverId")->fetch(), 'Primary VPN state changed');
    echo "PASS: migration, queue deduplication/serialization/timeouts, role recheck, persistence, failure redaction, VPN isolation\n";
} finally {
    $root->exec("DROP DATABASE `$database`");
}
