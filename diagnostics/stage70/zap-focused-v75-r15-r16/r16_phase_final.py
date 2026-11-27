"""R16 final-evidence phase reconstruction; immutable R15 in-VM snapshot retained.

Read-only analysis of finalized R11/R13/R14/R15 evidence. Neither a gate nor a
PID causal claim. An uncompleted phase is never represented as a zero-denial pass.
"""
from __future__ import annotations

PHASES=('WEBDRIVER_PREFLIGHT','AJAX_START','AJAX_RUNNING','AJAX_RESULTS','AJAX_STOP','FINISH')

def num(x):return type(x) is int and x>=0

def classify(checks):
    report={'schema':'stage70-r16-final-evidence-phase-v1','status':'UNVERIFIED',
            'origin':'RECOMPUTED_FROM_FINALIZED_EVIDENCE_NOT_R15_INLINE',
            'preserves_original_r15':True,'preflight_denials':'UNVERIFIED',
            'ajax_interval_denials':'UNVERIFIED','pid_limit':'UNVERIFIED',
            'browser_process_observed':'UNVERIFIED','docker_bridge':'UNVERIFIED',
            'causality':'NOT_PROVEN','production':'BLOCKED/NO-GO'}
    if not isinstance(checks,dict):return report
    bridge=checks.get('r14_docker_exec_bridge')
    if isinstance(bridge,dict) and num(bridge.get('event_count')) and bridge['event_count']<=16:
        report['docker_bridge']='NO_EXIT_OBSERVED' if bridge['event_count']==0 else 'EXIT_OBSERVED_UNATTRIBUTED'
    browser=checks.get('r13_firefox_process_observation')
    if isinstance(browser,dict) and isinstance(browser.get('samples'),list):
        samples=browser['samples']
        if len(samples)<=320 and all(isinstance(s,dict) for s in samples):
            present=any(s.get('phase')=='AJAX_RUNNING' and num(s.get('firefox_count')) and
                        num(s.get('geckodriver_count')) and s['firefox_count']>0 and s['geckodriver_count']>0 for s in samples)
            report['browser_process_observed']='YES_PROCESS_ONLY' if present else 'NO_JOINT_SAMPLE'
    pid=checks.get('r11_pid_ajax_phase')
    if not isinstance(pid,dict) or not isinstance(pid.get('samples'),list):return report
    samples=pid['samples']
    if not 1<=len(samples)<=320:return report
    prev_ms=prev_events=-1;budget=None
    for s in samples:
        if not isinstance(s,dict) or s.get('phase') not in PHASES or any(not num(s.get(k)) for k in
             ('monotonic_ms','pids_current','pids_peak','pids_max','pids_events_max')):
            return report
        if budget is None:budget=s['pids_max']
        if (budget not in (256,384) or s['pids_max']!=budget or s['monotonic_ms']<prev_ms
            or s['pids_events_max']<prev_events or s['pids_current']>budget
            or s['pids_peak']<s['pids_current']):return report
        prev_ms=s['monotonic_ms'];prev_events=s['pids_events_max']
    if (not num(pid.get('start_denials')) or not num(pid.get('end_denials')) or
        not num(pid.get('delta_denials')) or samples[0]['pids_events_max']<pid['start_denials'] or
        samples[-1]['pids_events_max']!=pid['end_denials'] or
        pid['end_denials']-pid['start_denials']!=pid['delta_denials']):return report
    pref=[(i,s) for i,s in enumerate(samples) if s['phase']=='WEBDRIVER_PREFLIGHT']
    start=[(i,s) for i,s in enumerate(samples) if s['phase']=='AJAX_START']
    if not pref:return report
    pf=pref[-1][1]['pids_events_max']-pref[0][1]['pids_events_max']
    total=pid['delta_denials']
    report.update(pid_limit=budget,preflight_denials=pf,
                  total_denials=total,pid_peak_observed=max(s['pids_peak'] for s in samples),
                  peak_exceeds_current_limit_any=any(s['pids_peak']>budget for s in samples),
                  sample_count=len(samples),
                  phase_resolution='POINT_IN_TIME_SAMPLING_NOT_EVENT_CAUSALITY')
    if not start:
        if any(s['phase'] in ('AJAX_RUNNING','AJAX_RESULTS','AJAX_STOP') for s in samples):
            return report
        report['status']='PREFLIGHT_ONLY_STOP_BEFORE_AJAX'
        report['preflight_denials']=total
        report['ajax_interval_denials']='NOT_RUN'
        return report
    first=start[0][0]
    active=[(i,s) for i,s in enumerate(samples) if s['phase'] in ('AJAX_RUNNING','AJAX_RESULTS','AJAX_STOP','FINISH') and i>first]
    if not active or pref[-1][0]>=first:return report
    aj=active[-1][1]['pids_events_max']-start[0][1]['pids_events_max']
    if aj<0 or pf<0 or pf+aj>total:return report
    report['status']='FINALIZED_PHASE_WINDOWS_NOT_CAUSAL_PROOF'
    report['ajax_interval_denials']=aj
    report['boundary_gap_denials']=total-pf-aj
    return report
