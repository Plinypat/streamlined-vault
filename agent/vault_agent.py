#!/usr/bin/env python3
"""Streamlined Vault background uploader, pilot release. No remote code execution."""
import argparse, base64, ctypes, hashlib, importlib.util, json, os, sys, threading, time, uuid
from datetime import datetime
from pathlib import Path
from types import SimpleNamespace
from urllib.parse import urlparse
import urllib.request, urllib.error
from schedule import due, mark_attempt

VERSION='0.3.0'

class PortalError(RuntimeError):
    def __init__(self,status):self.status=status;super().__init__('Portal request failed (HTTP '+str(status)+')')

def validate_portal(portal, allow_local=False):
    u=urlparse(portal)
    if u.username or u.password or u.query or u.fragment or u.path not in ['', '/']:raise ValueError('Use the portal origin only')
    if u.scheme=='https' and u.hostname:return portal.rstrip('/')
    if allow_local and u.scheme=='http' and u.hostname in ['127.0.0.1','localhost','::1']:return portal.rstrip('/')
    raise ValueError('The portal must use HTTPS')

def request(portal,path,token=None,value=None):
    headers={'Content-Type':'application/json'}
    if token:headers['Authorization']='Bearer '+token
    req=urllib.request.Request(portal+path,data=json.dumps(value or {}).encode(),headers=headers,method='POST')
    class NoRedirect(urllib.request.HTTPRedirectHandler):
        def redirect_request(self,*args,**kwargs):return None
    try:
        with urllib.request.build_opener(NoRedirect).open(req,timeout=30) as response:return json.load(response)
    except urllib.error.HTTPError as e:raise PortalError(e.code) from None
    except (urllib.error.URLError,TimeoutError):raise RuntimeError('Portal unreachable') from None

def atomic_json(path,value):
    path=Path(path);tmp=path.with_name(path.name+'.tmp')
    tmp.write_text(json.dumps(value),encoding='utf-8');os.replace(tmp,path)
    if os.name!='nt':path.chmod(0o600)

def dpapi(value, decrypt=False):
    """Machine-bound encryption; installer restricts file ACL to SYSTEM/admins."""
    if os.name!='nt':raise RuntimeError('Windows DPAPI is required for device credentials')
    from ctypes import wintypes
    class Blob(ctypes.Structure):_fields_=[('size',wintypes.DWORD),('data',ctypes.POINTER(ctypes.c_ubyte))]
    buf=(ctypes.c_ubyte*len(value)).from_buffer_copy(value);source=Blob(len(value),buf);result=Blob()
    lib=ctypes.WinDLL('crypt32',use_last_error=True);kernel=ctypes.WinDLL('kernel32',use_last_error=True)
    kernel.LocalFree.argtypes=[ctypes.c_void_p];kernel.LocalFree.restype=ctypes.c_void_p
    if decrypt:
        fn=lib.CryptUnprotectData
        fn.argtypes=[ctypes.POINTER(Blob),ctypes.c_void_p,ctypes.c_void_p,ctypes.c_void_p,ctypes.c_void_p,wintypes.DWORD,ctypes.POINTER(Blob)]
        ok=fn(ctypes.byref(source),None,None,None,None,1,ctypes.byref(result))
    else:
        fn=lib.CryptProtectData
        fn.argtypes=[ctypes.POINTER(Blob),wintypes.LPCWSTR,ctypes.c_void_p,ctypes.c_void_p,ctypes.c_void_p,wintypes.DWORD,ctypes.POINTER(Blob)]
        ok=fn(ctypes.byref(source),'Streamlined Vault',None,None,None,5,ctypes.byref(result))
    if not ok:raise RuntimeError('Device credential protection failed')
    try:return ctypes.string_at(result.data,result.size)
    finally:kernel.LocalFree(ctypes.cast(result.data,ctypes.c_void_p))

class InstanceLock:
    def __init__(self,path):self.path=path;self.file=None
    def __enter__(self):
        self.file=open(self.path,'a+b');self.file.seek(0);self.file.write(b'0');self.file.flush();self.file.seek(0)
        try:
            if os.name=='nt':
                import msvcrt;msvcrt.locking(self.file.fileno(),msvcrt.LK_NBLCK,1)
            else:
                import fcntl;fcntl.flock(self.file.fileno(),fcntl.LOCK_EX|fcntl.LOCK_NB)
        except OSError:self.file.close();raise RuntimeError('Another uploader instance is already running') from None
        return self
    def __exit__(self,*args):
        if self.file:
            if os.name=='nt':
                import msvcrt;self.file.seek(0);msvcrt.locking(self.file.fileno(),msvcrt.LK_UNLCK,1)
            else:
                import fcntl;fcntl.flock(self.file.fileno(),fcntl.LOCK_UN)
            self.file.close()

def source_path(value):
    p=Path(value)
    if not p.is_absolute() or str(p).startswith(('\\\\','//')):raise ValueError('Pilot supports local absolute folders only')
    if p.is_symlink() or not p.is_dir():raise ValueError('Source must be an existing local folder')
    resolved=p.resolve()
    if str(resolved).startswith(('\\\\','//')):raise ValueError('Network folders are not supported by the pilot')
    return resolved

def load_transfer():
    here=Path(__file__).resolve().parent
    path=here/'vault_transfer.py'
    if not path.exists():path=here.parent/'tools'/'vault-uploader.py'
    spec=importlib.util.spec_from_file_location('vault_transfer',path);module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module);return module

def enroll(args):
    portal=validate_portal(args.portal,args.allow_local_test)
    sources=[str(source_path(v)) for v in args.source]
    root=Path(args.config).resolve().parent;root.mkdir(parents=True,exist_ok=True)
    if any(root.is_relative_to(Path(s)) or Path(__file__).resolve().parent.is_relative_to(Path(s)) for s in sources):
        raise ValueError('Source folders cannot contain uploader configuration or program files')
    # Supplied on stdin by the installer; never a command-line argument or log item.
    code=sys.stdin.readline().strip()
    result=request(portal,'/api/device-enroll',value={'code':code})
    encrypted=dpapi(result['token'].encode())
    secret=root/'credential.dpapi';secret.write_bytes(encrypted)
    atomic_json(args.config,{'portal':portal,'device':result['device'],'workspace':result['workspace'],'credential':secret.name,'sources':sources,'include':args.include,'settle_seconds':120})
    print('Streamlined Vault device enrolled. Credential protected on this computer.')

class Agent:
    def __init__(self,config,token,root,transport=request,transfer=None):
        self.config=config;self.token=token;self.root=Path(root);self.transport=transport;self.transfer=transfer or load_transfer()
        self.statepath=self.root/'agent-state.json';self.state=json.loads(self.statepath.read_text()) if self.statepath.exists() else {}
        self.paused=True;self.policy=None;self.status='idle';self.connected=False;self.thread=None;self.guard=threading.Lock();self.stop=threading.Event()
    def save(self):atomic_json(self.statepath,self.state)
    def heartbeat(self):
        r=self.transport(self.config['portal'],'/api/device/heartbeat',self.token,{'status':'paused' if self.paused else self.status,'version':VERSION})
        with self.guard:
            self.connected=True;self.paused=r['paused'];self.policy=r['policy'];self.state['revision']=r['revision']
            pending=self.state.get('pending_run')
        if pending:
            self.transport(self.config['portal'],'/api/device/runs',self.token,pending)
            with self.guard:self.state.pop('pending_run',None);self.save()
        with self.guard:
            # Do not start again until the last summary has been acknowledged.
            if self.thread and self.thread.is_alive():return
            if self.paused:return
            command=r['command'];manual=command>self.state.get('command',0)
            if manual or due(self.policy['schedule'],self.state):
                policy=json.loads(json.dumps(self.policy));self.state['command']=command;mark_attempt(policy['schedule'],self.state);self.save()
                self.thread=threading.Thread(target=self.upload,args=(policy,),daemon=True);self.thread.start()
    def checkpoint(self):return self.connected and not self.paused and not self.stop.is_set()
    def upload(self,policy):
        self.status='uploading';summary={'id':str(uuid.uuid4()),'status':'success','uploaded':0,'skipped':0,'failed':0}
        try:
            for index,value in enumerate(self.config['sources']):
                source=source_path(value)
                if not self.checkpoint():summary['status']='paused';break
                # Only local, explicitly enrolled sources are used. Remote policy cannot change them.
                folder=policy['folder']+(('/Source '+str(index+1)) if len(self.config['sources'])>1 else '')
                state=self.root/('source-'+hashlib.sha256(str(source).encode()).hexdigest()[:16]+'.json')
                a=SimpleNamespace(portal=self.config['portal'],workspace=self.config['workspace'],source=source,token_file=self.root/self.config['credential'],state=state,folder=folder,include=self.config.get('include','*'),settle_seconds=self.config.get('settle_seconds',120))
                counts=self.transfer.run_upload(a,token=self.token,checkpoint=self.checkpoint)
                for k in ['uploaded','skipped','failed']:summary[k]+=counts[k]
                if counts['status']!='success':summary['status']=counts['status']
                if counts['status']=='paused':break
        except Exception:
            summary['failed']+=1;summary['status']='failed'
        finally:
            self.status='error' if summary['status']=='failed' else 'idle'
            with self.guard:self.state['pending_run']=summary;self.save()
    def loop(self):
        while not self.stop.is_set():
            try:self.heartbeat()
            except PortalError as e:
                self.connected=False
                if e.status in [401,403,423]:self.paused=True
                # Bounded error codes only: no credentials, filenames or raw upstream errors.
                print('Uploader contact failed: HTTP '+str(e.status),file=sys.stderr,flush=True)
            except Exception:
                self.connected=False;print('Uploader contact failed: retrying',file=sys.stderr,flush=True)
            self.stop.wait(30)

def main():
    p=argparse.ArgumentParser(description='Streamlined Vault Uploader')
    sub=p.add_subparsers(dest='action',required=True)
    e=sub.add_parser('enroll');e.add_argument('--portal',required=True);e.add_argument('--source',action='append',required=True);e.add_argument('--config',required=True);e.add_argument('--include',default='*');e.add_argument('--allow-local-test',action='store_true')
    r=sub.add_parser('run');r.add_argument('--config',required=True)
    args=p.parse_args()
    if args.action=='enroll':enroll(args);return
    config=json.loads(Path(args.config).read_text());validate_portal(config['portal'])
    root=Path(args.config).resolve().parent
    token=dpapi((root/config['credential']).read_bytes(),decrypt=True).decode()
    with InstanceLock(root/'agent.lock'):
        agent=Agent(config,token,root)
        try:agent.loop()
        except KeyboardInterrupt:agent.stop.set()

if __name__=='__main__':
    try:main()
    except Exception:print('Uploader setup failed. Check local configuration and enrollment status.',file=sys.stderr);sys.exit(1)
