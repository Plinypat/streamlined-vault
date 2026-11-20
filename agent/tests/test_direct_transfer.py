import base64
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import tempfile
import time
from types import SimpleNamespace
import unittest
from unittest.mock import patch

spec = importlib.util.spec_from_file_location('vault_transfer_direct_test', Path(__file__).resolve().parents[2] / 'tools' / 'vault-uploader.py')
transfer = importlib.util.module_from_spec(spec)
spec.loader.exec_module(transfer)


class DirectTransfer(unittest.TestCase):
    def test_direct_upload_keeps_portal_token_off_storage_and_does_not_persist_links(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            source = root / 'source'
            source.mkdir()
            sample = source / 'synthetic.bin'
            sample.write_bytes(b'x' * (6 * 1024 * 1024))
            os.utime(sample, (time.time() - 300, time.time() - 300))
            args = SimpleNamespace(source=source, state=root / 'state.json', token_file=root / 'token', portal='https://portal.example.test', workspace='practice', include='*', settle_seconds=30, folder='General')
            direct_calls = []
            portal_calls = []

            class Reply(io.BytesIO):
                status = 200

            class Opener:
                def open(self, req, timeout):
                    if req.full_url.startswith('https://s3.us-west-004.backblazeb2.com/'):
                        direct_calls.append(req)
                        if req.get_header('Authorization'):
                            raise AssertionError('Portal credential reached storage')
                        if req.get_header('Content-md5') != base64.b64encode(hashlib.md5(req.data).digest()).decode():
                            raise AssertionError('Incorrect checksum')
                        return Reply(b'')
                    portal_calls.append(req)
                    path = req.full_url.split('/api/tenants/practice', 1)[1]
                    if path == '/uploads':
                        result = {'id': 'upload', 'partSize': 16 * 1024 * 1024}
                    elif path == '/uploads/upload' and req.method == 'GET':
                        result = {'status': 'uploading', 'transport': 'direct', 'parts': []}
                    elif path.endswith('/sign'):
                        digest = json.loads(req.data)['md5']
                        result = {'url': 'https://s3.us-west-004.backblazeb2.com/synthetic/opaque?temporary-secret', 'headers': {'Content-MD5': digest}}
                    else:
                        result = {'ok': True}
                    return Reply(json.dumps(result).encode())

            with patch.object(transfer.urllib.request, 'build_opener', return_value=Opener()):
                result = transfer.run_upload(args, token='synthetic-portal-token', checkpoint=lambda: True)
            self.assertEqual(result['uploaded'], 1)
            self.assertEqual(len(direct_calls), 1)
            self.assertEqual(len(direct_calls[0].data), sample.stat().st_size)
            self.assertTrue(all(req.get_header('Authorization') == 'Bearer synthetic-portal-token' for req in portal_calls))
            self.assertNotIn('temporary-secret', args.state.read_text())
            self.assertNotIn('synthetic-portal-token', args.state.read_text())


if __name__ == '__main__':
    unittest.main()
