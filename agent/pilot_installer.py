"""Interactive x64 Windows pilot installer. Build only; installation requires the operator."""
import ctypes, hashlib, json, os, shutil, subprocess, sys, zipfile
from pathlib import Path
RUNTIME_SHA256='90905e64a840557d8c1bc4f5b74db3d7ee85e3ffb217611cac1c7813acea4159'
PORTAL='https://www.streamlinedvault.com'
TASK='Streamlined Vault Uploader'

def validate_source(value):
    p=Path(value)
    if not p.is_absolute() or str(p).startswith(('\\\\','//')) or p.is_symlink() or (hasattr(p,'is_junction') and p.is_junction()):raise ValueError('Choose a regular local folder.')
    if not p.is_dir() or any(p.iterdir()):raise ValueError('Choose a new empty folder for non-patient pilot files only.')
    return p.resolve()

def verify_runtime(path):
    if hashlib.sha256(Path(path).read_bytes()).hexdigest()!=RUNTIME_SHA256:raise ValueError('Bundled runtime verification failed. Obtain a fresh package.')

def command(args,**kwargs):
    result=subprocess.run(args,stdout=subprocess.PIPE,stderr=subprocess.PIPE,creationflags=getattr(subprocess,'CREATE_NO_WINDOW',0),**kwargs)
    if result.returncode:raise RuntimeError('A protected installation step failed. Review folder permissions and enrollment status.')
    return result

def protect(path):
    command(['icacls.exe',str(path),'/inheritance:r','/grant:r','*S-1-5-18:(OI)(CI)F','*S-1-5-32-544:(OI)(CI)F'])

def install(source,code,bundle):
    source=validate_source(source)
    if not isinstance(code,str) or not code.strip() or len(code)>199:raise ValueError('Enter a fresh one-time enrollment credential.')
    if sys.platform!='win32' or os.environ.get('PROCESSOR_ARCHITECTURE','').upper()=='ARM64':raise ValueError('This package supports Windows x64 only.')
    if not ctypes.windll.shell32.IsUserAnAdmin():raise ValueError('Run this installer with administrator approval.')
    root=Path(os.environ['ProgramFiles'])/'Streamlined Vault Uploader';state=Path(os.environ['ProgramData'])/'StreamlinedVault'
    if (state/'config.json').exists() or (root/'python').exists():raise ValueError('A previous installation exists. Review it before re-enrollment.')
    query=subprocess.run(['schtasks.exe','/Query','/TN',TASK],stdout=subprocess.PIPE,stderr=subprocess.PIPE,creationflags=subprocess.CREATE_NO_WINDOW)
    if query.returncode==0:raise ValueError('An uploader task already exists. Review it before installing again.')
    runtime=Path(bundle)/'python-runtime.zip';verify_runtime(runtime)
    for p in [root,state]:p.mkdir(parents=True,exist_ok=True);protect(p)
    for name in ['vault_agent.py','schedule.py','vault_transfer.py']:shutil.copyfile(Path(bundle)/name,root/name)
    runtime_root=root/'python';runtime_root.mkdir()
    with zipfile.ZipFile(runtime) as archive:
        for item in archive.infolist():
            destination=(runtime_root/item.filename).resolve()
            if not destination.is_relative_to(runtime_root.resolve()):raise ValueError('Runtime archive path rejected.')
        archive.extractall(runtime_root)
    (runtime_root/'python314._pth').write_text('python314.zip\n.\n..\n',encoding='ascii')
    python=runtime_root/'python.exe'
    command([str(python),'-c','import ssl,ctypes,hashlib,urllib.request; import vault_agent'])
    # Enrollment passes through stdin and never through command-line arguments.
    command([str(python),str(root/'vault_agent.py'),'enroll','--portal',PORTAL,'--config',str(state/'config.json'),'--source',str(source)],input=code.strip().encode()+b'\n')
    fixtures={}
    for name,size in [('Synthetic-pilot-note.txt',256),('Synthetic-pilot-17MiB.bin',17*1024*1024)]:
        path=source/name;digest=hashlib.sha256()
        with path.open('xb') as output:
            remaining=size
            while remaining:
                data=os.urandom(min(remaining,1024*1024));output.write(data);digest.update(data);remaining-=len(data)
        fixtures[name]=digest.hexdigest()
    (state/'pilot-checksums.json').write_text(json.dumps(fixtures,indent=2),encoding='utf8')
    executable=subprocess.list2cmdline([str(python),str(root/'vault_agent.py'),'run','--config',str(state/'config.json')])
    command(['schtasks.exe','/Create','/TN',TASK,'/SC','ONSTART','/RU','SYSTEM','/RL','HIGHEST','/TR',executable])
    command(['schtasks.exe','/Run','/TN',TASK])
    return state/'pilot-checksums.json'

def main():
    import tkinter as tk
    from tkinter import filedialog,messagebox
    window=tk.Tk();window.title('Streamlined Vault - Sorski pilot');window.geometry('640x390');window.resizable(False,False)
    tk.Label(window,text='Streamlined Vault pilot setup',font=('Segoe UI',17,'bold')).pack(pady=14)
    tk.Label(window,text='Select a new empty local test folder. Synthetic test files will be created.\nIn the portal select Sorski, create an uploader and confirm daily 9 p.m.\nPaste its fresh one-time enrollment credential below.',font=('Segoe UI',10),justify='left').pack(pady=8)
    folder=tk.StringVar();code=tk.StringVar()
    row=tk.Frame(window);row.pack(fill='x',padx=25,pady=8);tk.Entry(row,textvariable=folder,width=62).pack(side='left');tk.Button(row,text='Choose folder',command=lambda:folder.set(filedialog.askdirectory(mustexist=True))).pack(side='right')
    tk.Label(window,text='One-time enrollment credential (not your password)').pack(anchor='w',padx=25)
    tk.Entry(window,textvariable=code,show='*',width=75).pack(padx=25,pady=7)
    status=tk.StringVar(value='Keep this computer awake and online for the scheduled pilot.')
    tk.Label(window,textvariable=status,wraplength=590).pack(padx=20,pady=8)
    def run():
        button.config(state='disabled');status.set('Installing and enrolling...');window.update_idletasks()
        try:
            bundle=Path(getattr(sys,'_MEIPASS',Path(__file__).resolve().parent))/'payload'
            receipt=install(folder.get(),code.get(),bundle);code.set('');status.set('Installed. Confirm device contact in the portal.')
            messagebox.showinfo('Uploader installed','Confirm the device is online in Streamlined Vault. Run once and verify downloads before the two nightly tests.\n\nChecksum receipt: '+str(receipt))
        except Exception as e:
            code.set('');status.set('Setup stopped. No success is claimed.');messagebox.showerror('Setup stopped',str(e) if isinstance(e,(ValueError,RuntimeError)) else 'Setup failed. Review the existing installation before retrying.')
        finally:button.config(state='normal')
    button=tk.Button(window,text='Install and enroll',command=run,font=('Segoe UI',11));button.pack(pady=8)
    window.mainloop()
if __name__=='__main__':main()
