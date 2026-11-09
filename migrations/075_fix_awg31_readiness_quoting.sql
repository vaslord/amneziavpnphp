-- Repair the stored recipe on panels that have already applied migration 073.
-- This changes future installs only; running VPN containers are untouched.
UPDATE protocols
SET install_script = REPLACE(
    install_script,
    CONCAT('grep -Eq ', CHAR(34), ':${VPN_PORT}([[:space:]]|$)', CHAR(34)),
    CONCAT('grep -Eq ', CHAR(39), ':${VPN_PORT}([[:space:]]|$)', CHAR(39))
)
WHERE slug = 'awg2';
