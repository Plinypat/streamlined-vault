CREATE TABLE member_invitations(id TEXT PRIMARY KEY,email TEXT NOT NULL,tenant TEXT NOT NULL,actor TEXT NOT NULL,status TEXT NOT NULL,kind TEXT NOT NULL,provider_id TEXT,created TEXT NOT NULL,expires TEXT,error_code TEXT);
CREATE INDEX member_invitation_email ON streamlined_vault.member_invitations(email,created);
CREATE INDEX member_invitation_actor ON streamlined_vault.member_invitations(actor,created);
