import { randomUUID, createHash } from 'node:crypto';
const fail = (message, status = 409) => Object.assign(Error(message), { status });
export function createMemberInvitations({db, clerk, env, origin, audit, demo = false, fetcher = fetch, clock = () => Date.now()}) {
  const normalize = value => String(value || '').trim().toLowerCase();
  async function view(email) {
    const identity = await db.one('SELECT clerk_id FROM clerk_identities WHERE email=?', email);
    const row = await db.one('SELECT * FROM member_invitations WHERE email=? ORDER BY created DESC LIMIT 1', email);
    let status = row?.status || 'not_invited';
    if (!['failed','sending','revocation_pending'].includes(status)) {
      if (identity || (row?.kind === 'instructions' && status === 'accepted')) status = 'ready';
      else if (status === 'accepted' && row.expires && Date.parse(row.expires) < clock()) status = 'expired';
    }
    return {status,lastSent:row?.created || null,kind:row?.kind || null,retryAfter:row ? Math.max(0,60000 - (clock() - Date.parse(row.created))) : 0};
  }
  async function send(tenant, input, user) {
    if (!user.msp) throw fail('Only MSP administrators can send invitations', 403);
    const email = normalize(input);
    if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) throw fail('Valid email required', 400);
    let result;
    await db.transaction(async () => {
      await db.lock('invitation-actor:' + user.email);
      await db.lock('invitation-email:' + email);
      if (!await db.one('SELECT email FROM members WHERE tenant=? AND email=?', tenant, email)) throw fail('Assign this user to the practice first', 404);
      const last = await db.one('SELECT created FROM member_invitations WHERE email=? ORDER BY created DESC LIMIT 1', email);
      if (last && clock() - Date.parse(last.created) < 60000) throw fail('Wait one minute before sending again', 429);
      const count = await db.one('SELECT COUNT(*) AS count FROM member_invitations WHERE actor=? AND created>?', user.email, new Date(clock() - 3600000).toISOString());
      if (Number(count.count) >= 20) throw fail('Hourly invitation limit reached', 429);
      const id = randomUUID(), at = new Date(clock()).toISOString();
      await db.run("INSERT INTO member_invitations(id,email,tenant,actor,status,kind,created) VALUES(?,?,?,?,'sending','enrollment',?)", id, email, tenant, user.email, at);
      try {
        const existing = demo ? false : await clerk.invitationAccountExists(email);
        let providerId, expires = null, kind = existing ? 'instructions' : 'enrollment';
        if (demo) providerId = 'synthetic-' + id;
        else if (existing) {
          if (!env.RESEND_API_KEY || !env.ALERT_EMAIL_FROM) throw Error('Email configuration missing');
          const response = await fetcher('https://api.resend.com/emails', {method:'POST', signal:AbortSignal.timeout(10000), headers:{Authorization:'Bearer ' + env.RESEND_API_KEY,'Content-Type':'application/json','Idempotency-Key':id},body:JSON.stringify({from:env.ALERT_EMAIL_FROM,to:[email],subject:'Streamlined Vault: your workspace access',text:`Your administrator has assigned workspace access.\nOpen ${origin}/ and choose Client access, then Returning user.\nSign in with this email and complete MFA.\nIf you did not expect this message, contact your administrator.`})});
          if (!response.ok) throw Error('Email rejected');
          providerId = (await response.json()).id;
        } else {
          const old = await db.q("SELECT id,provider_id FROM member_invitations WHERE email=? AND kind='enrollment' AND status='accepted'", email);
          const invitation = await clerk.createInvitation(email);
          providerId = invitation.id;
          expires = new Date(clock() + 7 * 86400000).toISOString();
          for (const previous of old) if (previous.provider_id && previous.provider_id !== providerId) {
            let status = 'revoked';
            try { await clerk.revokeInvitation(previous.provider_id); } catch { status = 'revocation_pending'; }
            await db.run('UPDATE member_invitations SET status=? WHERE id=?',status,previous.id);
          }
        }
        if (!providerId) throw Error('Provider acceptance unavailable');
        await db.run("UPDATE member_invitations SET status='accepted',kind=?,provider_id=?,expires=? WHERE id=?", kind, providerId, expires, id);
        result = {ok:true,kind,status:'accepted'};
      } catch {
        await db.run("UPDATE member_invitations SET status='failed',error_code='SEND_FAILED' WHERE id=?", id);
        result = {ok:false,status:'failed'};
      }
      await audit(tenant,user.email,result.ok ? 'User email accepted by provider' : 'User invitation send failed',createHash('sha256').update(email).digest('hex'));
    });
    return result;
  }
  async function remove(tenant, email) {
    email = normalize(email);
    await db.transaction(async () => {
      await db.lock('invitation-email:' + email);
      const others = await db.one('SELECT COUNT(*) AS count FROM members WHERE email=? AND tenant<>?', email, tenant);
      if (!Number(others.count)) {
        const rows = await db.q("SELECT provider_id FROM member_invitations WHERE email=? AND status='accepted' AND kind='enrollment'",email);
        let failed = false;
        for (const row of rows) if (row.provider_id && !demo) {
          try { await clerk.revokeInvitation(row.provider_id); } catch { failed = true; }
        }
        await db.run("UPDATE member_invitations SET status=? WHERE email=? AND status='accepted' AND kind='enrollment'", failed ? 'revocation_pending' : 'revoked',email);
      }
      await db.run('DELETE FROM members WHERE tenant=? AND email=?',tenant,email);
    });
  }
  async function retryRevocations() {
    const rows = await db.q("SELECT id,email,provider_id FROM member_invitations WHERE status='revocation_pending' LIMIT 20");
    for (const row of rows) {
      if (!demo && row.provider_id) await clerk.revokeInvitation(row.provider_id);
      await db.run("UPDATE member_invitations SET status='revoked' WHERE id=?",row.id);
    }
  }
  return {view,send,remove,retryRevocations};
}
