import {test} from 'node:test';
import assert from 'node:assert/strict';
import {mkdtempSync,rmSync} from 'node:fs';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {openDatabase} from '../server/database.mjs';
import {createMemberInvitations} from '../server/member-invitations.mjs';
async function fixture(t, overrides={}) {
 const data=mkdtempSync(join(tmpdir(),'sv-invites-'));
 const db=await openDatabase({env:{},demo:true,data});
 t.after(async()=>{await db.close();rmSync(data,{recursive:true,force:true});});
 await db.run("INSERT INTO members VALUES('practice','user@example.test','viewer')");
 let now=Date.now(), calls=0;const revoked=[];
 const service=createMemberInvitations({db,env:{RESEND_API_KEY:'synthetic',ALERT_EMAIL_FROM:'Vault <alerts@example.test>'},origin:'https://vault.example.test',audit:async()=>{},clock:()=>now,clerk:{invitationAccountExists:async()=>false,createInvitation:async()=>({id:'inv-'+(++calls)}),revokeInvitation:async id=>revoked.push(id)},...overrides});
 return {db,service,revoked,calls:()=>calls,advance:()=>now+=61000,user:{email:'admin@example.test',msp:true}};
}
test('invitation requires MSP and existing membership, serializes duplicate sends and expires',async t=>{
 const f=await fixture(t);
 await assert.rejects(()=>f.service.send('practice','user@example.test',{msp:false}),e=>e.status===403);
 await assert.rejects(()=>f.service.send('other','user@example.test',f.user),e=>e.status===404);
 const results=await Promise.allSettled([f.service.send('practice','user@example.test',f.user),f.service.send('practice','user@example.test',f.user)]);
 assert.equal(results.filter(r=>r.status==='fulfilled').length,1);assert.equal(f.calls(),1);
 assert.equal((await f.service.view('user@example.test')).status,'accepted');
 await f.db.run("UPDATE member_invitations SET expires='2000-01-01T00:00:00.000Z'");
 assert.equal((await f.service.view('user@example.test')).status,'expired');
 f.advance();await f.service.send('practice','user@example.test',f.user);assert.deepEqual(f.revoked,['inv-1']);
});
test('failed provider sends persist safe failure and cooldown without leaking provider errors',async t=>{
 const f=await fixture(t,{clerk:{invitationAccountExists:async()=>{throw Error('private-provider-secret');}}});
 assert.equal((await f.service.send('practice','user@example.test',f.user)).ok,false);
 const state=await f.service.view('user@example.test');assert.equal(state.status,'failed');assert.ok(!JSON.stringify(state).includes('private-provider-secret'));
 await assert.rejects(()=>f.service.send('practice','user@example.test',f.user),e=>e.status===429);
});
test('existing identities receive generic sign-in email using stable provider idempotency',async t=>{
 let mail;
 const f=await fixture(t,{clerk:{invitationAccountExists:async()=>true},fetcher:async(url,options)=>{mail=options;return {ok:true,json:async()=>({id:'mail-test'})};}});
 const sent=await f.service.send('practice','user@example.test',f.user);assert.equal(sent.kind,'instructions');
 const body=JSON.parse(mail.body);assert.deepEqual(body.to,['user@example.test']);assert.ok(body.text.includes('Returning user'));assert.ok(!body.text.includes('practice'));assert.ok(mail.headers['Idempotency-Key']);
});
test('last membership removal revokes enrollment, other memberships preserve it',async t=>{
 const f=await fixture(t);await f.service.send('practice','user@example.test',f.user);
 await f.db.run("INSERT INTO members VALUES('other','user@example.test','viewer')");
 await f.service.remove('practice','user@example.test');assert.equal(f.revoked.length,0);
 await f.service.remove('other','user@example.test');assert.deepEqual(f.revoked,['inv-1']);assert.equal((await f.service.view('user@example.test')).status,'revoked');
});
test('hourly per-administrator cap is enforced durably',async t=>{
 const f=await fixture(t);
 for(let i=0;i<20;i++)await f.db.run("INSERT INTO member_invitations(id,email,tenant,actor,status,kind,created) VALUES(?,?,'practice',?,'accepted','instructions',?)",'seed-'+i,'other'+i+'@example.test',f.user.email,new Date().toISOString());
 await assert.rejects(()=>f.service.send('practice','user@example.test',f.user),e=>e.status===429);
});

test('provider revocation outage never preserves practice access',async t=>{
 let failed=true;
 const f=await fixture(t,{clerk:{invitationAccountExists:async()=>false,createInvitation:async()=>({id:'pending-inv'}),revokeInvitation:async()=>{if(failed)throw Error('offline');}}});
 await f.service.send('practice','user@example.test',f.user);
 await f.service.remove('practice','user@example.test');
 assert.equal(await f.db.one("SELECT email FROM members WHERE email='user@example.test'"),undefined);
 assert.equal((await f.service.view('user@example.test')).status,'revocation_pending');
 failed=false;await f.service.retryRevocations();assert.equal((await f.service.view('user@example.test')).status,'revoked');
});
