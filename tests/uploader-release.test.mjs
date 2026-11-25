import {test} from 'node:test';
import assert from 'node:assert/strict';
import {randomBytes} from 'node:crypto';
import {releaseMetadata,createUploaderRelease} from '../server/uploader-release.mjs';
import {sealCredentials} from '../server/workspace-storage.mjs';
function fixture() {
 const master=randomBytes(32),sha256='a'.repeat(64);
 const config={purpose:'uploader-distribution',version:'0.3.1',sha256,bytes:100,key:`releases/0.3.1/${sha256}/installer.zip`,bucket:'sv-software-'+'b'.repeat(24),endpoint:'https://s3.us-west-004.backblazeb2.com',region:'us-west-004',publishedAt:new Date().toISOString(),credential:sealCredentials({keyId:'test-reader',applicationKey:'test-secret'},master,'uploader-distribution-credential')};
 let quarantined=false,headGood=true,audits=0;
 const service=createUploaderRelease({env:{STORAGE_CREDENTIAL_ENCRYPTION_KEY:master.toString('base64')},db:{one:async(sql)=>sql.includes('recovery_review_required')?(quarantined?{id:'recovery_review_required'}:null):{value:JSON.stringify(config)}},audit:async()=>audits++,adapter:{head:async()=>({size:headGood?100:200,encryption:'AES256'}),signDownload:async(key,version,name)=>{assert.equal(key,config.key);assert.equal(name,'Streamlined-Vault-Windows-0.3.1.zip');return {url:'https://downloads.example.test/signed',expiresIn:60};}}});
 return {config,service,quarantine:()=>quarantined=true,damage:()=>headGood=false,audits:()=>audits};
}
test('installer metadata never includes storage credentials or locations',async()=>{
 const f=fixture();const metadata=await f.service.status();assert.equal(metadata.configured,true);
 for(const value of ['test-secret','test-reader','credential','bucket','endpoint',f.config.key])assert.ok(!JSON.stringify(metadata).includes(value));
 assert.equal((await f.service.download('practice','operator')).expiresIn,60);assert.equal(f.audits(),1);
});
test('installer configuration is bound to its artifact hash, approved bucket and region',()=>{
 const {config}=fixture();
 for(const change of [{key:'client-files/secret'},{bucket:'patient-files'},{endpoint:'https://example.test/'},{region:'eu-central-003'},{sha256:'bad'},{version:'../bad'},{bytes:65*1024*1024}])assert.throws(()=>releaseMetadata({...config,...change}));
});
test('quarantine and mismatched stored artifacts cannot issue download links',async()=>{
 const f=fixture();f.damage();await assert.rejects(()=>f.service.download('p','a'),/verification failed/);assert.equal(f.audits(),0);
 const g=fixture();g.quarantine();await assert.rejects(()=>g.service.download('p','a'),/Isolated recovery/);assert.equal(g.audits(),0);
});
