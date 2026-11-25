import sys,tempfile,unittest
from pathlib import Path
from unittest.mock import patch
from types import SimpleNamespace
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from pilot_installer import validate_source,verify_runtime,install
class InstallerSafety(unittest.TestCase):
    def test_rejects_nonempty_and_relative_sources(self):
        with tempfile.TemporaryDirectory() as d:
            folder=Path(d);self.assertEqual(validate_source(d),folder.resolve())
            (folder/'existing.txt').write_text('existing data')
            with self.assertRaises(ValueError):validate_source(d)
        with self.assertRaises(ValueError):validate_source('relative')
    def test_runtime_tampering_is_rejected(self):
        with tempfile.TemporaryDirectory() as d:
            archive=Path(d)/'runtime.zip';archive.write_bytes(b'not a trusted runtime')
            with self.assertRaises(ValueError):verify_runtime(archive)
    def test_preexisting_state_folder_is_never_reused_or_repermissioned(self):
        with tempfile.TemporaryDirectory() as d:
            base=Path(d);source=base/'test-source';source.mkdir();programs=base/'programs';programs.mkdir();state=base/'state';state.mkdir();(state/'StreamlinedVault').mkdir()
            fake_windows=SimpleNamespace(shell32=SimpleNamespace(IsUserAnAdmin=lambda:True))
            with patch.dict('pilot_installer.os.environ',{'ProgramFiles':str(programs),'ProgramData':str(state),'PROCESSOR_ARCHITECTURE':'AMD64'}),patch('pilot_installer.sys.platform','win32'),patch('pilot_installer.known_folder',side_effect=lambda n: programs if n==0x26 else state),patch('pilot_installer.ctypes.windll',fake_windows,create=True),patch('pilot_installer.command') as command:
                with self.assertRaises(ValueError):install(source,'one-time-code',base)
                command.assert_not_called()
    def test_empty_enrollment_never_executes_installation_commands(self):
        with tempfile.TemporaryDirectory() as d,patch('pilot_installer.command') as command:
            with self.assertRaises(ValueError):install(d,'',Path(d))
            command.assert_not_called()
if __name__=='__main__':unittest.main()
