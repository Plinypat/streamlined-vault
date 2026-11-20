CREATE TABLE backup_history(id TEXT PRIMARY KEY,object_key TEXT NOT NULL UNIQUE,digest TEXT NOT NULL,key_id TEXT NOT NULL,bytes BIGINT NOT NULL,plaintext_bytes BIGINT NOT NULL,status TEXT NOT NULL,trigger TEXT NOT NULL,created TEXT NOT NULL,verified TEXT,error_code TEXT);
CREATE INDEX backup_created ON streamlined_vault.backup_history(created);
CREATE TABLE alert_deliveries(id TEXT PRIMARY KEY,alert_id TEXT NOT NULL,generation TEXT NOT NULL,category TEXT NOT NULL,severity TEXT NOT NULL,status TEXT NOT NULL,attempts INTEGER NOT NULL DEFAULT 0,next_attempt BIGINT NOT NULL,created TEXT NOT NULL,accepted TEXT,provider_id TEXT,UNIQUE(alert_id,generation));
CREATE INDEX alert_delivery_due ON streamlined_vault.alert_deliveries(status,next_attempt);
CREATE TABLE readiness_evidence(id TEXT PRIMARY KEY,reviewer TEXT NOT NULL,created TEXT NOT NULL,expires TEXT NOT NULL,reference TEXT NOT NULL);
