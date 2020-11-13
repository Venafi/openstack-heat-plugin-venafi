import os
import time

from fabric.api import *
from fabric.contrib.files import exists
from invoke import UnexpectedExit

env.hosts = os.environ['DEVSTACK_HOST']

# Set the username
env.user = os.environ['HOST_USER_NAME']
env.password =os.environ['HOST_USER_PASSWORD']
branchName = os.environ['BRANCH_NAME']
localBranchFolder = os.environ['BRANCH_FOLDER']


def host_type():
    run('uname -s')

def checkoutProjectAndInstall():
    with cd(localBranchFolder):
        if exists(localBranchFolder+"openstack-heat-venafi"):
            run("rm -rf openstack-heat-venafi")
        run("mkdir openstack-heat-venafi")
        with cd("openstack-heat-venafi"):
            run("git clone -b "+branchName+" --single-branch https://github.com/Venafi/openstack-heat-plugin-venafi.git")
            run("pip3 install "+localBranchFolder+"openstack-heat-venafi/"+"openstack-heat-plugin-venafi")


def install():
    checkoutProjectAndInstall()

    result = run('sudo systemctl restart devstack@h-eng')
    print(result)
    # TODO: rewrite sleep to check of "systemctl status devstack@h-eng"
    time.sleep(10)
    try:
        result = run('journalctl -q -u devstack@h-eng.service --since '
                       '"2 minutes ago"|grep "OS::Nova::VenafiCertificate"')
    except UnexpectedExit as e:
        print(e.result)
        print("Didn't find plugin registration message in the logs")
        exit(code=1)
    print(result)