import {test} from 'node:test';
import assert from 'node:assert/strict';
import {createClerkClient} from '@clerk/backend';
import {generateKeyPair,exportSPKI,SignJWT} from 'jose';
import {createClerkAuth,clerkConfiguration,contentSecurityPolicy} from '../server/clerk-auth.mjs';

const origin='https://portal.example.test',issuer='https://test-instance.clerk.accounts.dev';
const {privateKey,publicKey}=await generateKeyPair('RS256');
const jwtKey=await exportSPKI(publicKey);
const env={CLERK_PUBLISHABLE_KEY:'pk_test_'+Buffer.from('test-instance.clerk.accounts.dev$').toString('base64'),CLERK_SECRET_KEY:'sk_test_synthetic_not_a_real_key',CLERK_JWT_KEY:jwtKey};
const verifier=createClerkClient({publishableKey:env.CLERK_PUBLISHABLE_KEY,secretKey:env.CLERK_SECRET_KEY,telemetry:{disabled:true}});
async function token(overrides={}){return await new SignJWT({sub:'user_test',sid:'sess_test',azp:origin,fva:[0,0],v:2,...overrides}).setProtectedHeader({alg:'RS256',typ:'JWT',kid:'synthetic-test',cat:'cl_B7d4PD111AAA'}).setIssuer(overrides.iss||issuer).setIssuedAt().setExpirationTime('1m').setNotBefore(0).sign(privateKey);}
function fixture({status='active',verified=true,banned=false,resolveIdentity=()=>({msp:false})}={}){
 const client={authenticateRequest:(...args)=>verifier.authenticateRequest(...args),sessions:{getSession:async()=>({id:'sess_test',status,userId:'user_test'}),revokeSession:async()=>({status:'revoked'})},users:{getUser:async()=>({id:'user_test',primaryEmailAddressId:'email_test',emailAddresses:[{id:'email_test',emailAddress:'Staff@Example.test',verification:{status:verified?'verified':'unverified'}}],firstName:'Test',banned,publicMetadata:{msp:true},unsafeMetadata:{role:'admin'}})}};
 return createClerkAuth({env,origin,client,resolveIdentity});
}
const req=t=>({url:'/api/me',method:'GET',headers:{authorization:'Bearer '+t}});
test('official SDK verifies signed session and app owns authorization',async()=>{
 let identity;const auth=fixture({resolveIdentity:v=>{identity=v;return {msp:false};}});const user=await auth.authenticate(req(await token()));
 assert.deepEqual(identity,{clerkId:'user_test',email:'staff@example.test'});assert.equal(user.clerkSessionId,'sess_test');assert.equal(user.msp,false);
});
test('forged token and unapproved frontend origins are denied',async()=>{
 const auth=fixture();await assert.rejects(auth.authenticate(req('not-a-signed-token')),e=>e.status===401);
 await assert.rejects(auth.authenticate(req(await token({azp:'https://attacker.example.test'}))),e=>e.status===401);
 await assert.rejects(auth.authenticate(req(await token({iss:'https://other.clerk.accounts.dev'}))),e=>e.status===401);
});
test('pending sessions, missing MFA and stale second factors cannot access files',async()=>{
 const auth=fixture();await assert.rejects(auth.authenticate(req(await token({sts:'pending'}))),e=>e.status===401);
 for(const fva of [[0,-1],[0,16],undefined,[0,'0']])await assert.rejects(auth.authenticate(req(await token({fva}))),e=>e.status===403&&e.code==='MFA_REQUIRED');
});
test('revocation and unverified/banned accounts fail closed',async()=>{
 const t=await token();await assert.rejects(fixture({status:'revoked'}).authenticate(req(t)),e=>e.status===401);
 await assert.rejects(fixture({verified:false}).authenticate(req(t)),e=>e.status===403);
 await assert.rejects(fixture({banned:true}).authenticate(req(t)),e=>e.status===403);
});
test('application membership denial is not bypassed by Clerk user metadata',async()=>{
 const auth=fixture({resolveIdentity:()=>{throw Object.assign(Error('Not assigned'),{status:403});}});
 await assert.rejects(auth.authenticate(req(await token())),e=>e.status===403);
});
test('Clerk configuration does not expose secret keys and pins CSP to configured host',()=>{
 const c=clerkConfiguration(env);assert.ok(!JSON.stringify(c).includes(env.CLERK_SECRET_KEY));
 const csp=contentSecurityPolicy(c.frontendApi);assert.ok(csp.includes(issuer));assert.ok(!csp.includes('unsafe-eval'));assert.ok(!csp.includes('script-src https:'));
 assert.throws(()=>clerkConfiguration({...env,NODE_ENV:'production'}),/live/);
});

test('production key diagnostics identify the setting without revealing credentials',()=>{
 const live={...env,NODE_ENV:'production',CLERK_PUBLISHABLE_KEY:'pk_live_'+Buffer.from('clerk.example.test$').toString('base64'),CLERK_SECRET_KEY:'sk_live_synthetic_not_a_real_key'};
 assert.equal(clerkConfiguration(live).frontendApi,'https://clerk.example.test');
 for(const name of ['CLERK_PUBLISHABLE_KEY','CLERK_SECRET_KEY']){
  assert.throws(()=>clerkConfiguration({...live,[name]:env[name]}),error=>error.message.includes(name)&&!error.message.includes(env[name]));
 }
 assert.deepEqual(clerkConfiguration({...live,CLERK_PUBLISHABLE_KEY:' \n'+live.CLERK_PUBLISHABLE_KEY+'\n',CLERK_SECRET_KEY:' '+live.CLERK_SECRET_KEY+'\n'}),clerkConfiguration(live));
 assert.throws(()=>clerkConfiguration({...live,CLERK_SECRET_KEY:'"'+live.CLERK_SECRET_KEY+'"'}),/CLERK_SECRET_KEY/);
});

test('NEXT_PUBLIC Clerk key takes priority over the legacy variable',()=>{
 const preferred='pk_live_'+Buffer.from('clerk.preferred.test$').toString('base64');
 const config=clerkConfiguration({...env,NODE_ENV:'production',NEXT_PUBLIC_CLERK_PUBLISHABLE_KEY:preferred,CLERK_SECRET_KEY:'sk_live_synthetic'});
 assert.equal(config.publishableKey,preferred);
 assert.equal(config.frontendApi,'https://clerk.preferred.test');
 const onlyPublic={...env,NEXT_PUBLIC_CLERK_PUBLISHABLE_KEY:env.CLERK_PUBLISHABLE_KEY};delete onlyPublic.CLERK_PUBLISHABLE_KEY;
 assert.equal(clerkConfiguration(onlyPublic).publishableKey,env.CLERK_PUBLISHABLE_KEY);
});
