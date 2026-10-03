-- Local demo role: no memory access, write privilege, or ownership.
DO $$ BEGIN
  IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'aicl_grafana') THEN
    CREATE ROLE aicl_grafana LOGIN PASSWORD 'local-grafana-password';
  END IF;
END $$;
