-- Reset DNS baselines to the new order-stable signature scheme.
--
-- The DNS signature hash changed (sets are now sorted before hashing) so that reordering a
-- record set does not look like a change. Old baselines were computed with an order-sensitive
-- hash and would falsely read as "dns changed" once after upgrade. Clearing them lets the next
-- probe silently re-establish each baseline under the new scheme; only real changes warn again.

UPDATE domains SET dns_last_signature = '';

INSERT OR IGNORE INTO schema_versions (version, label) VALUES (19, 'dns_signature_reset');
