ALTER TABLE tenants ADD COLUMN kind TEXT NOT NULL DEFAULT 'client';
ALTER TABLE tenants ADD COLUMN owner_email TEXT;
CREATE UNIQUE INDEX IF NOT EXISTS internal_workspace_owner ON streamlined_vault.tenants(owner_email) WHERE kind='internal';
CREATE TABLE IF NOT EXISTS service_settings(id TEXT PRIMARY KEY,value TEXT NOT NULL,updated TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS workspace_plans(tenant TEXT PRIMARY KEY REFERENCES tenants(id),policy TEXT NOT NULL,updated TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS transfer_events(id TEXT PRIMARY KEY,tenant TEXT NOT NULL REFERENCES tenants(id),direction TEXT NOT NULL,period TEXT NOT NULL,reserved BIGINT NOT NULL DEFAULT 0,bytes BIGINT NOT NULL DEFAULT 0,status TEXT NOT NULL,created TEXT NOT NULL,expires BIGINT NOT NULL DEFAULT 0);
CREATE INDEX IF NOT EXISTS transfer_workspace_period ON streamlined_vault.transfer_events(tenant,period,direction);
CREATE TABLE IF NOT EXISTS provider_inventory(id TEXT PRIMARY KEY,status TEXT NOT NULL,cursor TEXT,snapshot TEXT,lease_token TEXT,lease_until BIGINT NOT NULL DEFAULT 0,updated TEXT NOT NULL);
