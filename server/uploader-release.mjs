import {CloudStorage} from './storage.mjs';
import {openCredentials,encryptionKey,storageEndpoint} from './workspace-storage.mjs';
const fail = (message,status=503) => Object.assign(Error(message),{status});
export function releaseMetadata(config) {
  if (!config || config.purpose !== 'uploader-distribution' ||
      !/^\d+\.\d+\.\d+$/.test(config.version) || !/^[a-f0-9]{64}$/.test(config.sha256) ||
      !Number.isSafeInteger(config.bytes) || config.bytes < 1 || config.bytes > 64*1024*1024 ||
      config.key !== `releases/${config.version}/${config.sha256}/installer.zip` ||
      !/^sv-software-[a-f0-9]{24}$/.test(config.bucket) ||
      storageEndpoint(config.endpoint).region !== 'us-west-004' || config.region !== 'us-west-004')
    throw fail('Windows installer release is not configured or verified');
  return {version:config.version,sha256:config.sha256,bytes:config.bytes,publishedAt:config.publishedAt,platform:'Windows x64',pilot:true,signed:false,filename:`Streamlined-Vault-Windows-${config.version}.zip`};
}
export function createUploaderRelease({db,env,demo=false,audit,adapter}) {
  async function config() {
    const row=await db.one("SELECT value FROM security_state WHERE id='uploader_release'");
    if (!row) throw fail('Windows installer is not published yet');
    const value=JSON.parse(row.value); releaseMetadata(value); return value;
  }
  async function status() {
    if(demo)return {configured:true,version:'0.3.1',sha256:'0'.repeat(64),bytes:25*1024*1024,platform:'Windows x64',pilot:true,signed:false,filename:'Streamlined-Vault-Windows-0.3.1.zip'};
    try{return {configured:true,...releaseMetadata(await config())};}
    catch{return {configured:false,message:'The current Windows installer is not available. Contact your MSP administrator.'};}
  }
  async function download(tenant,actor) {
    if (await db.one("SELECT id FROM security_state WHERE id='recovery_review_required' AND value<>'null'")) throw fail('Isolated recovery cannot authorize installer downloads');
    if(demo)return {demo:true,...await status()};
    const c=await config(),metadata=releaseMetadata(c);
    const secret=openCredentials(c.credential,encryptionKey(env),'uploader-distribution-credential');
    const storage=adapter || new CloudStorage({STORAGE_BUCKET:c.bucket,STORAGE_ENDPOINT:c.endpoint,STORAGE_REGION:c.region,STORAGE_KEY_ID:secret.keyId,STORAGE_APPLICATION_KEY:secret.applicationKey});
    const head=await storage.head(c.key);
    if(head.size!==c.bytes||head.encryption!=='AES256')throw fail('Installer release verification failed; download is unavailable');
    const grant=await storage.signDownload(c.key,'',metadata.filename);
    await audit(tenant,actor,'Windows installer download authorized','uploader-'+c.version);
    return {...metadata,...grant};
  }
  return {status,download};
}
