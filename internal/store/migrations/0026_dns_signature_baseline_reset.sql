-- Reset all DNS baselines once more.
--
-- The DNS signature algorithm is now final (NS/MX/TXT only) and the DomainEvaluator no longer moves
-- the baseline (it is read-only; the lazy-set + explicit-ack model in computeDomainHealth owns it).
-- Some baselines in the field were written by an EARLIER algorithm (A/AAAA included) or by the
-- evaluator before the read-only fix, so they never match the current signature and read as a
-- permanent "dns changed" even though the records are stable. Clearing them lets the next probe
-- silently re-establish each baseline under the final algorithm; with the read-only evaluator that
-- baseline now sticks, so dns_changed is true only for a genuine NS/MX/TXT change.

UPDATE domains SET dns_last_signature = '';

INSERT OR IGNORE INTO schema_versions (version, label) VALUES (26, 'dns_signature_baseline_reset_2');
