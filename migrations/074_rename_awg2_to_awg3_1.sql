-- Keep the awg2 slug for compatibility while presenting the installed engine accurately.
UPDATE protocols
SET name = 'AmneziaWG 3.1',
    description = 'AmneziaWG 3.1 (amneziawg-go v3.1.20260828)'
WHERE slug = 'awg2';
