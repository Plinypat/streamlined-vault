#!/usr/bin/env python3
"""Streamlined Vault uploader. Python 3.10+, standard library only.
Run on a practice computer with a protected token file and a protected state file.
Uploads new/changed files; never deletes cloud or source files. No provider credentials.
"""
import argparse, hashlib, json, os, sys, time, uuid, urllib.request, urllib.error
from pathlib import Path

def main():
    p=argparse.ArgumentParser(description='Streamlined Vault scheduled folder uploader')
    p.add_argument('--portal',required=True,help='https://portal.streamlinedvault.com')
    p.add_argument('--workspace',required=True)
    p.add_argument('--source',required=True,type=Path)
    p.add_argument('--token-file',required=True,type=Path)
    p.add_argument('--state',required=True,type=Path)
    p.add_argument('--folder',default='Automated uploads')
    p.add_argument('--include',default='*',help='Recursive pathlib glob, e.g. *.dcm')
    p.add_argument('--settle-seconds',type=int,default=120)
    a=p.parse_args()
    if not a.portal.startswith('https://'):
        p.error('HTTPS is required')
    if not a.source.is_dir(): p.error('Source must be an existing folder')
    return run_upload(a)

def run_upload(a, token=None, checkpoint=None):
    token=token if token is not None else a.token_file.read_text().strip()
    state=json.loads(a.state.read_text()) if a.state.exists() else {}
    # Prevent accidental state reuse against a different workspace or portal.
    identity=hashlib.sha256((a.portal.rstrip('/')+'|'+a.workspace+'|'+str(a.source.resolve())).encode()).hexdigest()
    if state and state.get('identity')!=identity:p.error('State belongs to another source or workspace')
    state.setdefault('identity',identity);state.setdefault('files',{})
    base=a.portal.rstrip('/')+'/api/tenants/'+a.workspace
    def save():
        a.state.parent.mkdir(parents=True,exist_ok=True)
        tmp=a.state.with_suffix('.tmp');tmp.write_text(json.dumps(state));os.replace(tmp,a.state)
    def call(path,method='GET',body=None):
        raw=isinstance(body,bytes)
        payload=body if raw else json.dumps(body).encode() if body is not None else None
        headers={'Authorization':'Bearer '+token}
        if payload is not None:headers['Content-Type']='application/octet-stream' if raw else 'application/json'
        if raw:headers['X-Content-SHA256']=hashlib.sha256(body).hexdigest()
        req=urllib.request.Request(base+path,data=payload,method=method,headers=headers)
        for attempt in range(3):
            try:
                # Do not follow redirects with credentials to another origin.
                class NoRedirect(urllib.request.HTTPRedirectHandler):
                    def redirect_request(self,*args,**kwargs):return None
                with urllib.request.build_opener(NoRedirect).open(req,timeout=600) as r:return json.load(r)
            except urllib.error.HTTPError as e:
                if e.code<500 or attempt==2:raise RuntimeError('Portal rejected request (HTTP '+str(e.code)+')') from None
            except (TimeoutError,urllib.error.URLError):
                if attempt==2:raise RuntimeError('Portal is unreachable') from None
            time.sleep(2**attempt)
    completed=failed=skipped=0
    paused=False
    for path in sorted(a.source.rglob(a.include)):
        if checkpoint and not checkpoint():
            paused=True;break
        if not path.is_file() or path.is_symlink():continue
        if path.resolve() in [a.token_file.resolve(),a.state.resolve(),a.state.with_suffix('.tmp').resolve()]:continue
        # Also reject files reached through a symlinked parent outside the source tree.
        if not path.resolve().is_relative_to(a.source.resolve()):continue
        st=path.stat()
        if not st.st_size or time.time()-st.st_mtime<max(a.settle_seconds,30):skipped+=1;continue
        relative=str(path.relative_to(a.source));fingerprint=str(st.st_size)+':'+str(st.st_mtime_ns)
        local_id=hashlib.sha256(relative.encode()).hexdigest();entry=state['files'].get(local_id,{})
        if entry.get('fingerprint')==fingerprint and entry.get('done'):skipped+=1;continue
        try:
            if entry.get('fingerprint')!=fingerprint:
                if entry.get('upload') and not entry.get('done'):
                    try:call('/uploads/'+entry['upload'],'DELETE')
                    except RuntimeError:raise RuntimeError('Prior transfer requires administrator review')
                entry={'fingerprint':fingerprint,'requestId':str(uuid.uuid4())};state['files'][local_id]=entry;save()
            if not entry.get('upload'):
                parent=path.relative_to(a.source).parent.as_posix()
                folder=a.folder+('/'+parent if parent!='.' else '')
                entry.setdefault('requestId',str(uuid.uuid4()));save()
                up=call('/uploads','POST',{'name':path.name,'size':st.st_size,'folder':folder,'requestId':entry['requestId']})
                entry.update(upload=up['id'],partSize=up['partSize']);save()
            up=call('/uploads/'+entry['upload'])
            if up.get('status')=='ready':
                entry['done']=True;save();completed+=1;continue
            sent={x['number'] for x in up['parts']}
            with path.open('rb') as f:
                n=1
                while True:
                    if checkpoint and not checkpoint():
                        paused=True;break
                    chunk=f.read(entry['partSize'])
                    if not chunk:break
                    if n not in sent:call('/uploads/'+entry['upload']+'/parts/'+str(n),'PUT',chunk)
                    n+=1
            if paused:break
            current=path.stat()
            if current.st_mtime_ns!=st.st_mtime_ns or current.st_size!=st.st_size:
                call('/uploads/'+entry['upload'],'DELETE');entry.pop('upload',None);save();raise RuntimeError('Source changed during transfer; retry on next run')
            call('/uploads/'+entry['upload']+'/complete','POST',{})
            entry['done']=True;save();completed+=1
        except Exception as e:
            failed+=1
            # Do not emit filenames, tokens, provider responses or file contents into scheduler logs.
            print('Transfer '+local_id[:12]+' failed: '+(str(e) if isinstance(e,RuntimeError) else 'Local file access failed'),file=sys.stderr)
    summary={'uploaded':completed,'skipped':skipped,'failed':failed,'status':'paused' if paused else 'failed' if failed else 'success'}
    if checkpoint is not None:return summary
    print(json.dumps(summary))
    return 1 if failed else 0

if __name__=='__main__':sys.exit(main())
