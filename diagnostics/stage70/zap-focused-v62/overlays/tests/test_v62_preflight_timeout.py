"""V62 fail-closed transport classifications and early independent browser proof."""
import importlib.util,copy,subprocess,json,unittest
from pathlib import Path
from unittest.mock import patch
src=Path(__file__).resolve().parents[1]/'zap_focus_vm.py'
spec=importlib.util.spec_from_file_location('v62vm',src)
m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
class V62Tests(unittest.TestCase):
    def test_api_bridge_timeout_has_redacted_classification_and_trace(self):
        a=m.ContainerAPI('TOP_SECRET',{('context','action','includeInContext')},set())
        with patch.object(m,'docker_http',side_effect=subprocess.TimeoutExpired(['SECRET_COMMAND'],17)):
            with self.assertRaises(m.Blocked) as exc:
                a.call('context','action','includeInContext',{'contextName':'Stage70_Day03_Fixture'})
        self.assertEqual(str(exc.exception),'ZAP_API_BRIDGE_TIMEOUT_context.action.includeInContext')
        self.assertEqual(a.records[0]['error'],'DOCKER_EXEC_TIMEOUT')
        self.assertEqual(a.records[0]['result'],'TIMEOUT')
        self.assertNotIn('SECRET',json.dumps(a.records))
    def test_no_api_retry_on_action_timeout(self):
        a=m.ContainerAPI('test',{('context','action','includeInContext')},set())
        with patch.object(m,'docker_http',side_effect=subprocess.TimeoutExpired(['a'],17)) as fn:
            with self.assertRaises(m.Blocked): a.call('context','action','includeInContext')
            self.assertEqual(fn.call_count,1)
    def test_bridge_failure_record_is_classified(self):
        a=m.ContainerAPI('token',set(),{('core','view','version')})
        with patch.object(m,'docker_http',side_effect=m.Blocked('sensitive string')):
            with self.assertRaises(m.Blocked):a.call('core','view','version')
        self.assertEqual(a.records[0]['error'],'DOCKER_EXEC_BRIDGE_FAILURE')
        self.assertNotIn('sensitive',str(a.records))
    def test_existing_transport_api_proves_valid_reply(self):
        a=m.ContainerAPI('token',set(),{('core','view','version')})
        with patch.object(m,'docker_http',return_value={'ok':True,'data':{'version':'2.17.0'}}):
            self.assertEqual(a.call('core','view','version')['version'],'2.17.0')
        self.assertEqual(a.records[0]['result'],'PASS')
    def test_api_rejects_unauthorized_methods(self):
        a=m.ContainerAPI('x',set(),set())
        with patch.object(m,'docker_http') as fn:
            with self.assertRaises(m.Blocked):a.call('ascan','action','scan')
            fn.assert_not_called()
    def test_preflight_occurs_before_context_and_spider(self):
        s=src.read_text()
        p=s.index("state['checks']['phase']='NATIVE_MARIONETTE_PREFLIGHT'")
        ctx=s.index("state['checks']['phase']='CONTEXT_CREATE'")
        spider=s.index("state['checks']['phase']='SPIDER_AND_FIRST_PASSIVE'")
        assert p<ctx<spider
        self.assertIn("state['checks']['native_marionette_preflight']",s)
    def test_preflight_still_diagnostic_not_admission(self):
        s=src.read_text()
        self.assertIn("gate(evidence['webdriver_session_created'],'FIREFOX_WEBDRIVER_SESSION_FAILED')",s)
        self.assertIn("gate(evidence['fixture_navigation_confirmed'],'FIREFOX_WEBDRIVER_FIXTURE_NAVIGATION_FAILED')",s)
        self.assertIn("gate(result.get('ajax_spider')=='completed'",s)
        self.assertIn('day03._wait_passive(',s)
    def test_marionette_frame_is_bounded_and_handles_fragmentation(self):
        c=m.MARIONETTE_NATIVE_CONTROL_CODE
        compile(c,'v62-native','exec')
        self.assertIn("while b':' not in frame",c)
        self.assertIn('while len(rest)<length',c)
        self.assertIn('length<=450',c)
        self.assertIn("('127.0.0.1',port)",c)
        self.assertNotIn('MOZ_DISABLE_CONTENT_SANDBOX',c)
    def test_native_control_same_pinned_uid_container(self):
        s=src.read_text()
        self.assertIn("['docker','exec','-i','--user','1000:1000'",s)
        self.assertIn("'cybersec-day03-zap'",s)
        self.assertNotIn('--privileged',s)
        self.assertNotIn('--security-opt',s)
    def test_native_failure_must_not_trigger_ajax(self):
        s=src.read_text()
        self.assertIn("'INFRASTRUCTURE_BLOCKED'",s)
        self.assertIn("'DIAGNOSTIC_BLOCKED'",s)
        self.assertIn("native_marionette_control=True)",s)
    def test_timeout_never_logs_source(self):
        s=src.read_text()
        self.assertIn("state['error']='SUBPROCESS_TIMEOUT_REDACTED'",s)
        self.assertNotIn("type(e).__name__+': '+str(e)[:160]",s)
    def test_rejected_insecure_pass_conditions(self):
        self.assertEqual(m.TARGET,'http://day03-target:8080/')
        self.assertEqual(m.BASE,'9de9fe0c2fc4e31d695aa9f3bd4594a0a5ecf5dd')
        self.assertEqual(m.LAB_SHM_BYTES,256*1024*1024)
if __name__=='__main__':unittest.main()
