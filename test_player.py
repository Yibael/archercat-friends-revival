import copy
import importlib.util
import json
from pathlib import Path
import unittest
from unittest.mock import patch
import player

class PlayerTests(unittest.TestCase):
    def setUp(self):
        self.ready = dict(status='ok', pid=1234, arch='arm64', hookMode='light',
            persistentHooks=player.HOOKS[:], profileFixture=player.FIXTURE,
            expectedLoginProfileLength=2000,
            criticalHooks=dict.fromkeys(['getaddrinfo','connect','postResponseProcess','responseDecrypt'],True),
            profileBasePoint=0, profileMapClearTuples=[],profileEventIds=[],
            profileDungeonRecords=[],profileSkillRecords=[],profileItemRecords=[],
            profileIngredientRecords=[],profileCalendar={'curTick':1720000000000})
    def test_ready_rejects_wrong_process_or_partial_hooks(self):
        player.validate_ready(self.ready, 1234)
        for key,value in [('pid',999),('hookMode','full'),('persistentHooks',player.HOOKS[:-1]),('profileFixture','ordinary-all')]:
            with self.subTest(key=key), self.assertRaises(RuntimeError):
                player.validate_ready({**self.ready,key:value},1234)
    def test_login_requires_matching_fixture_and_real_local_response(self):
        audit={**self.ready,'outputLength':2000,'expectedOutputLength':2000,'containsLocalGuest':True}
        player.validate_login(audit,self.ready)
        for key,value in [('outputLength',2),('profileItemRecords',[{'id':1}]),('containsLocalGuest',False)]:
            with self.subTest(key=key),self.assertRaises(RuntimeError):
                player.validate_login({**audit,key:value},self.ready)
    def test_cleanup_refuses_reused_pid(self):
        identity=type('Identity',(),{'pid':1234})()
        with patch.object(player,'verify_process_batch_token'),patch.object(player,'read_process_identity'),patch.object(player,'process_identity_mismatches',return_value=['start_token']),patch.object(player.os,'kill') as kill:
            with self.assertRaises(RuntimeError): player.stop_owned(identity,'token',lambda *a,**k:None)
            kill.assert_not_called()
    def test_cleanup_refuses_foreign_token(self):
        identity=type('Identity',(),{'pid':1234})()
        with patch.object(player,'verify_process_batch_token',side_effect=RuntimeError('token mismatch')),patch.object(player.os,'kill') as kill:
            with self.assertRaises(RuntimeError): player.stop_owned(identity,'token',lambda *a,**k:None)
            kill.assert_not_called()
    def test_cleanup_sends_one_sigterm_after_identity_check(self):
        identity=type('Identity',(),{'pid':1234})()
        with patch.object(player,'assert_owned') as owned,patch.object(player,'read_process_identity',side_effect=player.SidecarError('target_exited','gone')),patch.object(player.os,'kill') as kill:
            player.stop_owned(identity,'token',lambda *a,**k:None)
            owned.assert_called_once_with(identity,'token')
            kill.assert_called_once_with(1234,player.signal.SIGTERM)
    def test_smoke_fails_on_premature_exit(self):
        with self.assertRaises(RuntimeError):
            player.validate_smoke_exit(30, 100.0, 81.0, True)
        player.validate_smoke_exit(30, 100.0, 101.0, False)
        player.validate_smoke_exit(0, None, 81.0, True)

    def test_mock_server_status_and_login_wire_shape(self):
        path=Path(__file__).parent/'runtime-revive/playcover-spike/mock-server/server.py'
        spec=importlib.util.spec_from_file_location('mock_server',path)
        mod=importlib.util.module_from_spec(spec);spec.loader.exec_module(mod)
        status=mod.build_http_response({'path':'/GetServerStatus'},b'{}')
        payload=json.loads(status.split(b'\r\n\r\n',1)[1])
        self.assertEqual((payload['status'],payload['msg']),('ok',''))
        login=mod.build_http_response({'path':'/LoginUser/test'},b'{}')
        self.assertTrue(login.endswith(b'AAAAAAAAAAAAAAAAAAAAAA=='))
        self.assertIn(b'Content-Type: text/plain',login)

if __name__=='__main__': unittest.main()
