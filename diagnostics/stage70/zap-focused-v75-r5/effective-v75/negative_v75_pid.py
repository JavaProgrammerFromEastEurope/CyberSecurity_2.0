#!/usr/bin/env python3
import sys
sys.dont_write_bytecode=True
import unittest,copy
from tests.test_v75_pid_recovery import base_compose,changed,cell
import pid_recovery as p
class Negative(unittest.TestCase):pass

def check_budget(a,b):
 with unittest.TestCase().assertRaises(p.BudgetBlocked):
  p.admissible_budgets(a,b,[{'current':20,'max':500}])
for i,(a,b) in enumerate([(0,2),(63,100),(128,128),(129,128),(128,513),(True,256),
                            (128,False),(99,99),(512,513),(-1,256),(1,512),(500,500),
                            (0,0),(1,2),(1024,2048)]):
 setattr(Negative,f'test_budget_bounds_{i:02d}',lambda self,a=a,b=b:check_budget(a,b))

def check_parent(nodes):
 with unittest.TestCase().assertRaises(p.BudgetBlocked):p.admissible_budgets(128,256,nodes)
parents=[None,[],[{}],[{'current':None,'max':400}],[{'current':100,'max':None}],
  [{'current':100,'max':200}],[{'current':300,'max':300}],
  [{'current':400,'max':300}],[{'current':True,'max':400}],
  [{'current':-1,'max':400}],[{'current':10,'max':256}]]
for i,nodes in enumerate(parents):
 setattr(Negative,f'test_parent_{i:02d}',lambda self,nodes=nodes:check_parent(nodes))

def check_compose(tamper):
 c=changed();tamper(c)
 with unittest.TestCase().assertRaises(p.BudgetBlocked):p.compose_pid_delta(base_compose(),c,128)
changes=[lambda c:c['services']['zap'].__setitem__('pids_limit',127),
 lambda c:c['services']['zap'].__setitem__('shm_size',64),
 lambda c:c['services']['zap'].__setitem__('privileged',True),
 lambda c:c['services']['zap'].__setitem__('cap_add',['SYS_ADMIN']),
 lambda c:c['services']['zap'].__setitem__('network_mode','host'),
 lambda c:c['services']['zap'].__setitem__('security_opt',[]),
 lambda c:c['services']['zap'].__setitem__('user','root'),
 lambda c:c['services']['zap'].__setitem__('image','untrusted'),
 lambda c:c['services']['zap'].__setitem__('volumes',['/:/host']),
 lambda c:c['services']['zap'].__setitem__('ports',['8080:8080']),
 lambda c:c['services']['day03-target'].__setitem__('image','untrusted'),
 lambda c:c.__setitem__('name','wrong')]
for i,fn in enumerate(changes):
 setattr(Negative,f'test_compose_{i:02d}',lambda self,fn=fn:check_compose(fn))

def check_runtime(runtime,security,cleanup=True):
 with unittest.TestCase().assertRaises(p.BudgetBlocked):p.verify_runtime_budget(runtime,128,security,cleanup)
for i,(budget,sec,clean) in enumerate([(129,{'seccomp':2,'no_new_privs':1},True),
 (0,{'seccomp':2,'no_new_privs':1},True),(True,{'seccomp':2,'no_new_privs':1},True),
 (128,{'seccomp':0,'no_new_privs':1},True),(128,{'seccomp':1,'no_new_privs':1},True),
 (128,{'seccomp':2,'no_new_privs':0},True),(128,{'seccomp':None,'no_new_privs':1},True),
 (128,{},True),(128,{'seccomp':2,'no_new_privs':1},False),
 (128,{'seccomp':2,'no_new_privs':1},None)][:9]):
 setattr(Negative,f'test_runtime_{i:02d}',lambda self,budget=budget,sec=sec,clean=clean:check_runtime(budget,sec,clean))

def check_cell(mutation):
 cells=[cell(i,arm,role) for i in (1,2,3) for arm in ('A','B') for role in ('NO_CLIENT','ONE_CLIENT','THREE_CLIENTS','WEBDRIVER')]
 mutation(cells)
 with unittest.TestCase().assertRaises(p.BudgetBlocked):p.compare_trials(cells)
changes_cell=[lambda cells:cells.append(copy.deepcopy(cells[0])),
              lambda cells:cells[0].__setitem__('role','EXTERNAL_URL'),
              lambda cells:cells[0].__setitem__('replicate',4),
              lambda cells:cells[0].__setitem__('arm','C'),
              lambda cells:cells[0].__setitem__('pid_denial','POSITIVE'),
              lambda cells:cells[0].__setitem__('quiescence','LIVE'),
              lambda cells:cells[0].__setitem__('outcome','SKIPPED'),
              lambda cells:cells[0].__setitem__('raw_pid',1234),
              lambda cells:cells[0].__setitem__('session_id','secret'),
              lambda cells:cells[0].__setitem__('sandbox_verified',None)]
for i,fn in enumerate(changes_cell):
 setattr(Negative,f'test_cell_{i:02d}',lambda self,fn=fn:check_cell(fn))
if __name__=='__main__':unittest.main(verbosity=2)
