ALTER TABLE vpn_servers
  ADD COLUMN keys_synced_at TIMESTAMP NULL COMMENT 'Last SSH sync of keys/AWG params from container' AFTER last_check_at,
  ADD COLUMN online_clients_json JSON NULL COMMENT 'Cached online client logins from monitoring' AFTER keys_synced_at,
  ADD COLUMN online_clients_at TIMESTAMP NULL COMMENT 'When online_clients_json was updated' AFTER online_clients_json;
