import json, os, sys, tempfile, threading, unittest
from datetime import datetime, timezone
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from schedule import due,mark_attempt
from vault_agent import Agent,InstanceLock,validate_portal,dpapi

class Schedules(unittest.TestCase):
    def test_interval_and_daily_windows(self):
        now=datetime(2026,11,17,20,0,tzinfo=timezone.utc) # Tuesday
        s={'kind':'interval','minutes':15};state={};self.assertTrue(due(s,state,now));mark_attempt(s,state,now);self.assertFalse(due(s,state,now));self.assertTrue(due(s,state,now.replace(minute=15)))
        daily={'kind':'daily','time':'20:00','days':[1]};self.assertFalse(due(daily,{},now.replace(hour=19)));self.assertTrue(due(daily,{},now));mark_attempt(daily,state,now);self.assertFalse(due(daily,state,now.replace(fold=1)));self.assertFalse(due(daily,{},now.replace(day=18)))
    def test_portal_does_not_accept_insecure_or_credential_urls(self):
        self.assertEqual(validate_portal('https://portal.example.test/'),'https://portal.example.test')
        for url in ['http://example.test','https://user:password@example.test','https://example.test/path','https://example.test?secret=value']:
            with self.assertRaises(ValueError):validate_portal(url)
        self.assertEqual(validate_portal('http://127.0.0.1:14173',True),'http://127.0.0.1:14173')
    def test_single_instance_lock(self):
        with tempfile.TemporaryDirectory() as root:
            with InstanceLock(Path(root)/'lock'):
                with self.assertRaises(RuntimeError):
                    with InstanceLock(Path(root)/'lock'):pass
    @unittest.skipUnless(os.name=='nt','Windows credential test')
    def test_windows_secret_is_machine_protected_and_roundtrips(self):
        secret=b'synthetic-device-secret';encrypted=dpapi(secret)
        self.assertNotIn(secret,encrypted);self.assertEqual(dpapi(encrypted,True),secret)
    def test_agent_reports_and_does_not_repeat_manual_command(self):
        with tempfile.TemporaryDirectory() as root:
            source=Path(root)/'source';source.mkdir();config={'portal':'https://example.test','workspace':'test','credential':'protected','sources':[str(source)]};calls=[]
            policy={'schedule':{'kind':'interval','minutes':15},'folder':'Imaging'}
            def transport(portal,path,token,value):
                calls.append((path,value))
                return {'paused':False,'policy':policy,'revision':1,'command':1} if path.endswith('heartbeat') else {'ok':True}
            class Transfer:
                n=0
                def run_upload(self,a,token,checkpoint):
                    self.n+=1;self.assertion=checkpoint();return {'status':'success','uploaded':2,'skipped':1,'failed':0}
            transfer=Transfer();agent=Agent(config,'synthetic',root,transport,transfer)
            agent.heartbeat();agent.thread.join(3);agent.heartbeat()
            self.assertEqual(transfer.n,1);self.assertTrue(transfer.assertion)
            reports=[v for path,v in calls if path.endswith('/runs')];self.assertEqual(len(reports),1);self.assertEqual(reports[0]['uploaded'],2)
            self.assertNotIn('source',json.dumps(reports));self.assertNotIn('synthetic',Path(root,'agent-state.json').read_text())
    def test_paused_device_does_not_start_or_read_new_sources(self):
        with tempfile.TemporaryDirectory() as root:
            config={'portal':'https://example.test','sources':[]};policy={'schedule':{'kind':'interval','minutes':15},'folder':'Imaging'}
            def transport(*args):return {'paused':True,'policy':policy,'revision':1,'command':1}
            agent=Agent(config,'secret',root,transport,object());agent.heartbeat();self.assertIsNone(agent.thread)

if __name__=='__main__':unittest.main()
