from fabric import Connection as fabricConnection
import time
from invoke import UnexpectedExit
import os

c = fabricConnection(os.environ['DEVSTACK_HOST'], user=os.environ['DEVSTACK_USER'])
msg = "Ran {0.command!r} on {0.connection.host}, got stdout:\n{0.stdout}"
pwd = os.path.dirname(os.path.abspath(__file__))
os.system('rsync --delete --exclude ".git" --exclude ".venv" --exclude ".idea" --exclude "__pycache__" --exclude '
          '"*.pyc" '
          '-pthrvz  '
          ''+pwd+
          '/../../../../venafi-openstack-heat-plugin '+os.environ['DEVSTACK_USER']+'@'+os.environ[
              'DEVSTACK_HOST']+':/usr/lib/heat')
result = c.run('sudo systemctl restart devstack@h-eng')
print(msg.format(result))
# TODO: rewrite sleep to check of "systemctl status devstack@h-eng"
time.sleep(10)
try:
    result = c.run('journalctl -q -u devstack@h-eng.service --since '
                   '"2 minutes ago"|grep "OS::Nova::VenafiCertificate"')
except UnexpectedExit as e:
    print(e.result)
    print("Didn't find plugin registration message in the logs")
    exit(code=1)
print(msg.format(result))