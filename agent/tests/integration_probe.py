"""Synthetic integration harness; not an installed agent entry point."""
import json, os, sys
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from vault_agent import Agent,validate_portal

settings=json.load(sys.stdin)
validate_portal(settings['portal'],allow_local=True)
root=Path(settings['root']);root.mkdir(parents=True,exist_ok=True)
source=root/'source';source.mkdir(exist_ok=True)
sample=source/'synthetic-study.txt'
if not sample.exists():
    sample.write_text('Synthetic scheduled upload. No patient information.',encoding='utf-8')
    os.utime(sample,(1000000000,1000000000))
config={'portal':settings['portal'],'workspace':settings['workspace'],'device':settings['device'],'sources':[str(source)],'credential':'unused-test-secret','settle_seconds':120}
agent=Agent(config,settings['token'],root)
agent.heartbeat()
if agent.thread:agent.thread.join(15)
if agent.thread and agent.thread.is_alive():raise RuntimeError('Integration transfer timed out')
summary=agent.state.get('pending_run')
agent.heartbeat() # Acknowledge the result with the portal.
print(json.dumps(summary))
