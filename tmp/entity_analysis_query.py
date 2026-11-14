from ida_nexus import DatabaseManager
from ida_nexus.options import DatabaseOpenOptions
import sys
m=DatabaseManager()
m.open_database(r'C:\Users\DELTA\Documents\GitHub\vega\tmp\entity-analysis\70938.i64',set_current=True,options=DatabaseOpenOptions(keepalive=600))
r=m.execute_python(sys.stdin.read(),None,timeout=60)
print(r['stdout'])
if r.get('stderr'):print('STDERR:',r['stderr'])
