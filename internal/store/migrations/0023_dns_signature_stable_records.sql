-- Reset DNS baselines for the stable-records signature scheme.
--
-- DNSSignature now hashes only the control/delegation records (NS/MX/TXT) and excludes A/AAAA,
-- because CDN front-ends rotate A/AAAA constantly and that produced false "dns changed" yellows.
-- The hash bytes therefore differ from the previous scheme, so every existing baseline would read
-- as "dns changed" once after upgrade. Clearing them lets the next probe silently re-establish each
-- baseline under the new scheme; only real NS/MX/TXT changes warn again.

UPDATE domains SET dns_last_signature = '';

INSERT OR IGNORE INTO schema_versions (version, label) VALUES (23, 'dns_signature_stable_records');
