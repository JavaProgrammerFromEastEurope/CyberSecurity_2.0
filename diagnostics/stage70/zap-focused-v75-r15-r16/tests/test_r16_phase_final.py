"""Public, deterministic R16 classifier contracts only. No live Ubuntu/ZAP execution."""
import importlib.util
from pathlib import Path
import unittest

HERE = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('r16_phase_final', HERE / 'r16_phase_final.py')
mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)

def sample(phase, moment, denies, max_pids=384):
    return {'phase': phase, 'monotonic_ms': moment, 'pids_current': 50,
            'pids_peak': 50, 'pids_max': max_pids, 'pids_events_max': denies}

def checks(samples, total, start=0):
    return {'r11_pid_ajax_phase': {'samples': samples, 'start_denials': start,
             'end_denials': start+total, 'delta_denials': total},
            'r14_docker_exec_bridge': {'event_count': 0}}

class TestR16Contract(unittest.TestCase):
    def test_malformed_fails_closed(self):
        for value in (None, '', [], {'r11_pid_ajax_phase': {'samples': []}}):
            self.assertEqual('UNVERIFIED', mod.classify(value)['status'])
    def test_positive_control_not_causal_proof(self):
        c = checks([sample('WEBDRIVER_PREFLIGHT',0,0),
                    sample('WEBDRIVER_PREFLIGHT',10,0),
                    sample('AJAX_START',20,0),
                    sample('AJAX_RUNNING',30,0),
                    sample('FINISH',40,0)],0)
        r=mod.classify(c)
        self.assertEqual('FINALIZED_PHASE_WINDOWS_NOT_CAUSAL_PROOF',r['status'])
        self.assertEqual(0,r['ajax_interval_denials'])
        self.assertEqual('NOT_PROVEN',r['causality'])
        self.assertEqual('BLOCKED/NO-GO',r['production'])
    def test_preflight_stop_not_zero_ajax(self):
        c=checks([sample('WEBDRIVER_PREFLIGHT',0,0,256),
                  sample('WEBDRIVER_PREFLIGHT',10,75,256),
                  sample('FINISH',20,75,256)],75)
        r=mod.classify(c)
        self.assertEqual('PREFLIGHT_ONLY_STOP_BEFORE_AJAX',r['status'])
        self.assertEqual('NOT_RUN',r['ajax_interval_denials'])
        self.assertEqual(75,r['preflight_denials'])
    def test_ajax_denials_independent(self):
        c=checks([sample('WEBDRIVER_PREFLIGHT',0,0,256),
                  sample('WEBDRIVER_PREFLIGHT',10,2,256),
                  sample('AJAX_START',20,2,256),
                  sample('AJAX_RUNNING',30,4,256),
                  sample('FINISH',40,4,256)],4)
        r=mod.classify(c)
        self.assertEqual(2,r['preflight_denials'])
        self.assertEqual(2,r['ajax_interval_denials'])
        self.assertEqual('NOT_PROVEN',r['causality'])
    def test_invalid_budget_unverified(self):
        c=checks([sample('WEBDRIVER_PREFLIGHT',0,0,999),
                  sample('FINISH',10,0,999)],0)
        self.assertEqual('UNVERIFIED',mod.classify(c)['status'])
    def test_counter_rollback_unverified(self):
        c=checks([sample('WEBDRIVER_PREFLIGHT',0,2),
                  sample('AJAX_START',10,0),
                  sample('FINISH',20,2)],2)
        self.assertEqual('UNVERIFIED',mod.classify(c)['status'])

if __name__ == '__main__':
    unittest.main()
