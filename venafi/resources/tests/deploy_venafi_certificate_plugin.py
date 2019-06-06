from fabric import Connection as fabricConnection
import time
from invoke import UnexpectedExit

c = fabricConnection('devstack-manager')
msg = "Ran {0.command!r} on {0.connection.host}, got stdout:\n{0.stdout}"
result = c.run('cd /usr/lib/heat/venafi-openstack-heat-plugin/ && git pull')
print(msg.format(result))
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