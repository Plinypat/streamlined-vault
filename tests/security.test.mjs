import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { createHash } from 'node:crypto';

const port=14173,origin=`http://127.0.0.1:${port}`,dir=mkdtempSync(join(tmpdir(),'vault-tests-'));let proc,admin,client;
async function request(path,method='GET',body,session,extra={}){const r=await fetch(origin+path,{method,headers:{Origin:origin,...(session?{Cookie:session.cookie,'X-CSRF-Token':session.csrf}:{}),...(body!==undefined?{'Content-Type':Buffer.isBuffer(body)?'application/octet-stream':'application/json'}:{}),...extra},body:body===undefined?undefined:Buffer.isBuffer(body)?body:JSON.stringify(body)});const type=r.headers.get('content-type')||'';return {status:r.status,headers:r.headers,value:type.includes('application/json')?await r.json():await r.arrayBuffer()};}
async function sign(role){const r=await request('/auth/demo','POST',{role});return {cookie:r.headers.get('set-cookie').split(';')[0],csrf:r.value.csrf};}
before(async()=>{proc=spawn(process.execPath,['server/index.mjs'],{env:{...process.env,DEMO_MODE:'true',NODE_ENV:'test',PORT:String(port),APP_ORIGIN:origin,DATA_DIRECTORY:dir},stdio:'pipe'});let output='';proc.stderr.on('data',b=>output+=b);await new Promise((ok,bad)=>{const timeout=setTimeout(()=>bad(Error(output||'Startup timed out')),10000);proc.stdout.on('data',()=>{clearTimeout(timeout);ok();});proc.on('exit',code=>{clearTimeout(timeout);bad(Error(output+' exit '+code));});});admin=await sign('msp');client=await sign('client');});
after(()=>{proc?.kill();setTimeout(()=>{try{rmSync(dir,{recursive:true,force:true});}catch{}},500).unref();});
test('anonymous API access fails; state changes require both origin and CSRF',async()=>{
 assert.equal((await request('/api/me')).status,401);
 assert.equal((await request('/api/tenants','POST',{name:'Denied'},admin,{'X-CSRF-Token':'wrong'})).status,403);
 assert.equal((await request('/api/tenants','POST',{name:'Denied'},admin,{Origin:'https://elsewhere.test'})).status,403);
});
test('MSP provisioning does not grant other practices access',async()=>{
 const created=await request('/api/tenants','POST',{name:'Isolation test'},admin);assert.equal(created.status,201);
 const t=created.value.id;assert.equal((await request(`/api/tenants/${t}/files`,'GET',undefined,client)).status,403);
 assert.equal((await request('/api/tenants','POST',{name:'Forbidden'},client)).status,403);
 const me=await request('/api/me','GET',undefined,client);assert.ok(!me.value.tenants.some(x=>x.id===t));
});
test('multipart upload checks integrity and size, preserves bytes and supports trash restore',async()=>{
 const base='/api/tenants/northside';const bytes=Buffer.from('Synthetic imaging bytes. No patient data.');
 const start=await request(base+'/uploads','POST',{name:'sample.dcm',folder:'Testing',size:bytes.length},client);assert.equal(start.status,201);const f=start.value.id;
 assert.equal((await request(`${base}/uploads/${f}/complete`,'POST',{},client)).status,409);
 assert.equal((await request(`${base}/uploads/${f}/parts/1`,'PUT',bytes,client,{'X-Content-SHA256':'0'.repeat(64)})).status,400);
 const digest=createHash('sha256').update(bytes).digest('hex');assert.equal((await request(`${base}/uploads/${f}/parts/1`,'PUT',bytes,client,{'X-Content-SHA256':digest})).status,200);
 assert.equal((await request(`${base}/uploads/${f}/complete`,'POST',{},client)).status,200);
 const download=await request(`${base}/files/${f}/download`,'GET',undefined,client);assert.deepEqual(Buffer.from(download.value),bytes);
 assert.ok(!JSON.stringify([...download.headers]).toLowerCase().includes('backblaze'));
 const range=await request(`${base}/files/${f}/download`,'GET',undefined,client,{Range:'bytes=0-8'});assert.equal(range.status,206);assert.deepEqual(Buffer.from(range.value),bytes.subarray(0,9));
 assert.equal((await request(`/api/tenants/oakvalley/files/${f}/download`,'GET',undefined,client)).status,404);
 assert.equal((await request(`${base}/files/${f}`,'DELETE',{},client)).status,200);
 assert.equal((await request(`${base}/files/${f}/download`,'GET',undefined,client)).status,404);
 assert.equal((await request(`${base}/files/${f}/restore`,'POST',{},client)).status,200);
 assert.equal((await request(`${base}/files/${f}/download`,'GET',undefined,client)).status,200);
});
test('server quota reserves concurrent uploads and cancellation releases reservation',async()=>{
 const start=await request('/api/tenants','POST',{name:'Quota test'},admin),base=`/api/tenants/${start.value.id}`;
 // 23 reservations at 160,000 MiB fit in 4 TB; the 24th does not.
 let first;
 for(let i=0;i<23;i++){const r=await request(base+'/uploads','POST',{name:'reservation.bin',folder:'Test',size:167772160000},admin);assert.equal(r.status,201);first??=r.value.id;}
 assert.equal((await request(base+'/uploads','POST',{name:'overflow.bin',folder:'Test',size:167772160000},admin)).status,409);
 assert.equal((await request(base+'/uploads/'+first,'DELETE',{},admin)).status,200);
 assert.equal((await request(base+'/uploads','POST',{name:'fits-again.bin',folder:'Test',size:167772160000},admin)).status,201);
});
test('automation tokens are scoped, cannot administer, and revoke immediately',async()=>{
 const base='/api/tenants/northside';const r=await request(base+'/tokens','POST',{label:'Test device',scope:'upload',days:1},client);assert.equal(r.status,201);const auth={Authorization:'Bearer '+r.value.token};
 assert.equal((await request(base+'/files','GET',undefined,undefined,auth)).status,403);
 assert.equal((await request('/api/tenants/oakvalley/uploads','POST',{name:'x',folder:'x',size:1},undefined,auth)).status,403);
 assert.equal((await request(base+'/members','POST',{email:'x@example.test',role:'admin'},undefined,auth)).status,403);
 const up=await request(base+'/uploads','POST',{name:'agent.txt',folder:'Test',size:1},undefined,auth);assert.equal(up.status,201);
 await request(base+'/tokens/'+r.value.id,'DELETE',{},client);
 assert.equal((await request(`${base}/uploads/${up.value.id}`,'GET',undefined,undefined,auth)).status,401);
 const listed=await request(base+'/tokens','GET',undefined,client);assert.ok(!JSON.stringify(listed.value).includes(r.value.token));
});
test('scheduled capacity automation runs and records its outcome',async()=>{
 const base='/api/tenants/northside';const a=await request(base+'/automations','POST',{name:'Capacity',type:'capacity',interval:3600000},client);assert.equal(a.status,201);
 assert.equal((await request(base+'/automations/'+a.value.id+'/run','POST',{},client)).status,200);
 const list=await request(base+'/automations','GET',undefined,client);assert.match(list.value[0].result,/Capacity checked/);
 const audit=await request(base+'/audit','GET',undefined,client);assert.ok(audit.value.some(e=>e.action==='Automation completed'));
});
test('upload initialization and completion retries do not duplicate data or quota',async()=>{
 const base='/api/tenants/northside',payload={name:'idempotent.txt',folder:'Test',size:1,requestId:'aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee'};
 const a=await request(base+'/uploads','POST',payload,client),b=await request(base+'/uploads','POST',payload,client);assert.equal(a.value.id,b.value.id);assert.equal(b.status,200);
 assert.equal((await request(base+'/uploads','POST',{...payload,size:2},client)).status,409);
 const content=Buffer.from('x');await request(`${base}/uploads/${a.value.id}/parts/1`,'PUT',content,client,{'X-Content-SHA256':createHash('sha256').update(content).digest('hex')});
 assert.equal((await request(`${base}/uploads/${a.value.id}/complete`,'POST',{},client)).status,200);
 assert.equal((await request(`${base}/uploads/${a.value.id}/complete`,'POST',{},client)).status,200);
 const list=await request(base+'/files','GET',undefined,client);assert.equal(list.value.files.filter(f=>f.id===a.value.id).length,1);
});
test('viewer membership permits listing but denies upload and membership changes',async()=>{
 const t=await request('/api/tenants','POST',{name:'Viewer boundary'},admin),base=`/api/tenants/${t.value.id}`;
 await request(base+'/members','POST',{email:'client@example.test',role:'viewer'},admin);
 assert.equal((await request(base+'/files','GET',undefined,client)).status,200);
 assert.equal((await request(base+'/uploads','POST',{name:'denied.txt',folder:'Test',size:1},client)).status,403);
 assert.equal((await request(base+'/members','POST',{email:'client@example.test',role:'admin'},client)).status,403);
});
