-- One administrator-managed proxy profile per server. No VPN client records.
INSERT INTO protocols (slug, name, description, definition, is_active)
SELECT 'socks5', 'SOCKS5 Proxy', 'Общий SOCKS5-прокси с логином и паролем для браузера и Telegram (TCP)',
       JSON_OBJECT('engine', 'socks5', 'metadata', JSON_OBJECT('container_name', 'amnezia-socks5', 'image', 'ghcr.io/xtls/xray-core:26.10.31', 'auxiliary', true)), 1
WHERE NOT EXISTS (SELECT 1 FROM protocols WHERE slug = 'socks5');
