// Synthetic, in-memory demonstration. Nothing here is uploaded to cloud storage.
const uid=()=>crypto.randomUUID(), now=()=>new Date().toISOString();
const seedFiles=[['CT study — SAMPLE-001.zip','Imaging',842_000_000],['Panoramic scan — SAMPLE-002.dcm','Imaging',128_000_000],['Practice handbook.pdf','Documents',2_400_000],['Referral packet — SAMPLE.pdf','Documents',8_700_000],['Equipment inventory.xlsx','Operations',450_000]];
const tenants=[{id:'northside',name:'Northside Medical',quota:4e12,status:'active'},{id:'oakvalley',name:'Oak Valley Dental',quota:4e12,status:'active'},{id:'lakeside',name:'Lakeside Imaging',quota:4e12,status:'active'}];
const files=tenants.flatMap(t=>seedFiles.map(([name,folder,size],i)=>({id:uid(),tenant:t.id,name,folder,size,status:'ready',created:new Date(Date.now()-(i+1)*3600000).toISOString(),sample:true})));
const events=[],automations=tenants.flatMap(t=>[{id:uid(),tenant:t.id,name:'Daily storage check',type:'capacity',interval:86400000,enabled:1,last:'Never',result:'Not run'},{id:uid(),tenant:t.id,name:'Weekly file inventory',type:'inventory',interval:604800000,enabled:1,last:'Never',result:'Not run'}]),tokens=[],members=tenants.map(t=>({tenant:t.id,email:'client@example.test',role:'admin'})),blobs=new Map(),uploads=new Map();
let user;
const event=(t,action,resource='')=>events.unshift({id:uid(),tenant:t,actor:user?.email||'demo',action,resource,created:now()});
tenants.forEach(t=>{event(t.id,'Sample files added');event(t.id,'Workspace configured');});
const used=t=>files.filter(f=>f.tenant===t&&['ready','trash','uploading'].includes(f.status)).reduce((a,f)=>a+f.size,0);
export async function request(path,method='GET',b={}){
 if(path==='/auth/demo'){user={email:b.role==='msp'?'admin@example.test':'client@example.test',name:b.role==='msp'?'MSP Administrator':'Practice Administrator',msp:b.role==='msp',csrf:'demo'};return user;}
 if(path==='/api/logout'){user=null;return {ok:true};}
 if(path==='/api/me'){if(!user)throw Error('Please sign in');return {...user,tenants:tenants.map(t=>({...t,used:used(t.id),role:'admin'}))};}
 if(path==='/api/tenants'){const t={id:uid(),name:b.name,quota:4e12,status:'active'};tenants.push(t);event(t.id,'Workspace created');return t;}
 const m=/^\/api\/tenants\/([^/]+)(.*)$/.exec(path);if(!m)throw Error('Preview route unavailable');const t=m[1],suffix=m[2];
 if(suffix.startsWith('/files?')||suffix==='/files')return {files:files.filter(f=>f.tenant===t&&f.status===(suffix.includes('trash=true')?'trash':'ready')).map(f=>({...f})),used:used(t),quota:4e12};
 if(suffix==='/audit')return events.filter(e=>e.tenant===t);
 if(suffix==='/notices')return [];
 if(suffix==='/members'){if(method==='POST'){const old=members.find(m=>m.tenant===t&&m.email===b.email);if(old)old.role=b.role;else members.push({tenant:t,...b});event(t,'Member access assigned');}if(method==='DELETE'){const i=members.findIndex(m=>m.tenant===t&&m.email===b.email);if(i>=0)members.splice(i,1);event(t,'Member access removed');}return members.filter(m=>m.tenant===t);}
 if(suffix==='/automations'){if(method==='POST'){automations.push({id:uid(),tenant:t,...b,enabled:1,last:'Never',result:'Not run'});event(t,'Automation created');}return automations.filter(a=>a.tenant===t).map(a=>({...a}));}
 if(suffix.startsWith('/automations/')){const a=automations.find(a=>a.id===suffix.split('/')[2]);if(method==='PATCH')a.enabled=b.enabled?1:0;else{a.last=now();a.result=a.type==='capacity'?'Demo capacity check completed':a.type==='cleanup'?'Demo upload cleanup completed':'Demo inventory completed — synthetic files';event(t,'Demo automation completed',a.id);}return {ok:true};}
 if(suffix==='/tokens'){if(method==='POST'){const token={id:uid(),tenant:t,...b,expires:Date.now()+b.days*86400000,revoked:0};tokens.push(token);event(t,'Demo automation credential created',token.id);return {...token,token:'PREVIEW-ONLY-NOT-A-VALID-CREDENTIAL'};}return tokens.filter(k=>k.tenant===t);}
 if(suffix.startsWith('/tokens/')){const k=tokens.find(k=>k.id===suffix.split('/')[2]);k.revoked=1;event(t,'Demo credential revoked',k.id);return {ok:true};}
 if(suffix==='/uploads'){if(used(t)+b.size>4e12)throw Error('Storage allowance exceeded');if(b.size>100*1024*1024)throw Error('Browser preview is limited to 100 MB per synthetic file');const f={id:uid(),tenant:t,...b,status:'uploading',created:now()};files.unshift(f);uploads.set(f.id,{parts:new Map()});event(t,'Demo upload started',f.id);return {id:f.id,partSize:16*1024*1024};}
 if(suffix.startsWith('/uploads/')){const fid=suffix.split('/')[2],u=uploads.get(fid),f=files.find(f=>f.id===fid);if(method==='PUT'){u.parts.set(Number(suffix.split('/')[4]),b);return {ok:true};}if(method==='DELETE'){files.splice(files.indexOf(f),1);uploads.delete(fid);return {ok:true};}if(suffix.endsWith('/complete')){blobs.set(fid,new Blob([...u.parts.entries()].sort((a,b)=>a[0]-b[0]).map(v=>v[1])));f.status='ready';event(t,'Demo upload completed',fid);uploads.delete(fid);return f;}return {id:fid,partSize:16*1024*1024,parts:[...u.parts.keys()].map(number=>({number}))};}
 if(suffix.startsWith('/files/')){const f=files.find(f=>f.id===suffix.split('/')[2]);if(method==='DELETE'){f.status='trash';event(t,'File moved to trash',f.id);}if(method==='PATCH'){f.name=b.name;event(t,'File renamed',f.id);}if(method==='POST'){f.status='ready';event(t,'File restored',f.id);}return {ok:true};}
 throw Error('This action needs a connected server');
}
export function download(id){const f=files.find(f=>f.id===id);event(f.tenant,'Demo download requested',f.id);return {blob:blobs.get(id)||new Blob([`Streamlined Vault — synthetic preview\nCollection: ${f.name}\nThis text is a sample, not an actual imaging study.\n`],{type:'text/plain'}),name:blobs.has(id)?f.name:'sample-readme.txt'};}
