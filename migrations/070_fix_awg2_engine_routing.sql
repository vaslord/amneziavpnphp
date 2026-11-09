-- Ensure AWG2 protocol definition uses shell engine (amneziawg-go install script).
UPDATE protocols
SET definition = JSON_SET(COALESCE(definition, '{}'), '$.engine', 'shell')
WHERE slug = 'awg2';
