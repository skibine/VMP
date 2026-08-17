-- 0028: alerts no longer create in-app NOTIFICATION rows (they were a duplicate of the alerts
-- journal and polluted the bell's notification list). Fired alerts surface exclusively in the
-- bell's "alerts" tab (unack badge). Purge the legacy kind='alert' notification rows.
DELETE FROM notifications WHERE kind = 'alert';
