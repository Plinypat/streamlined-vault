import {test} from 'node:test';
import assert from 'node:assert/strict';
import {recoveryRequestAllowed,createRateLimiter,canManageUpload,uploadPrincipal} from '../server/request-security.mjs';
test('isolated recovery permits diagnostics and sign-in, never transfers or scheduled writes',()=>{
 for(const [path,method] of [['/internal/metadata-backup','GET'],['/internal/security-maintenance','GET'],['/api/device-enroll','POST'],['/api/tenants/x/uploads/id','GET'],['/api/tenants/x/uploads/id/parts/1/sign','POST'],['/api/msp/security/storage-check','POST']])assert.equal(recoveryRequestAllowed(path,method),false,path);
 for(const [path,method] of [['/health','GET'],['/app.js','GET'],['/auth/complete','POST'],['/api/msp/security','GET']])assert.equal(recoveryRequestAllowed(path,method),true);
});
test('upload-only principals cannot take over another upload, including legacy ownerless rows',()=>{
 const first={email:'agent:a',agent:true,tokenId:'a'},second={email:'agent:b',agent:true,tokenId:'b'};
 const file={upload_actor:uploadPrincipal(first)};
 assert.equal(canManageUpload(first,{role:'uploader'},file),true);
 assert.equal(canManageUpload(second,{role:'uploader'},file),false);
 assert.equal(canManageUpload(first,{role:'uploader'},{upload_actor:null}),false);
 assert.equal(canManageUpload(second,{role:'admin'},file),true);
});
test('rate limiter caps keys and request counts, then expires old state',()=>{
 let now=100;const limiter=createRateLimiter({limit:2,maxKeys:2,windowMs:10,clock:()=>now});
 assert.equal(limiter.allow('a'),true);assert.equal(limiter.allow('a'),true);assert.equal(limiter.allow('a'),false);
 assert.equal(limiter.allow('b'),true);assert.equal(limiter.allow('c'),false);assert.equal(limiter.size(),2);
 now+=10;assert.equal(limiter.allow('c'),true);assert.equal(limiter.size(),1);
});
