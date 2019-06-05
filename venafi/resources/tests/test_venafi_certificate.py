#
# Copyright 2019 Venafi, Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#  http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
from __future__ import with_statement
import re

import mock
import six
from testtools import matchers

from heat.common import exception
from heat.common import template_format
from heat.engine import node_data
from heat.engine import stack as parser
from heat.engine import template
from heat.tests import common
from heat.tests import utils
from fabric import Connection as fabricConnection
import pytest
from invoke import UnexpectedExit
from heatclient import client as heat_client
from keystoneauth1 import loading
from keystoneauth1 import session
import os


class TestVenafiCertificate:

    venafi_fake_cert_defn = '''
    heat_template_version: 2014-10-16


    description: Venafi fake certificate

    resources:

      # This key pair will be bound to the stack lifecycle.
      venafi_certificate:
        type: OS::Nova::VenafiCertificate
        properties:
          name: venafi certificate

    outputs:

      venafi_certificate:
        description: Venafi certificate
        value: { get_attr: [certificate] }

    '''

    def create_stack(self, templ):
        self.stack = self.parse_stack(template_format.parse(templ))
        self.assertIsNone(self.stack.create())
        return self.stack

    def parse_stack(self, t):
        stack_name = 'test_stack'
        tmpl = template.Template(t)
        stack = parser.Stack(utils.dummy_context(), stack_name, tmpl)
        stack.validate()
        stack.store()
        return stack

    def deploy_venafi_cert(self):
        c = fabricConnection('devstack-manager')
        result = c.run('uname -s', hide=True)
        msg = "Ran {0.command!r} on {0.connection.host}, got stdout:\n{0.stdout}"
        formated = msg.format(result)
        return formated

    @mock.patch('sys.stdin', new=open("/dev/null"))
    def test_venafi_fake_cert(self):
        # c = fabricConnection('devstack-manager')
        # msg = "Ran {0.command!r} on {0.connection.host}, got stdout:\n{0.stdout}"
        # result = c.run('cd /usr/lib/heat/venafi-openstack-heat-plugin/ && git pull')
        # print(msg.format(result))
        # result = c.run('sudo systemctl restart devstack@h-eng')
        # print(msg.format(result))
        # try:
        #     result = c.run('journalctl -q -u devstack@h-eng.service --since '
        #                    '"5 minutes ago"|grep "OS::Nova::VenafiCertificate"')
        # except UnexpectedExit as e:
        #     print(e.result)
        #     pytest.fail("Didn't find plugin registration message in the logs")
        # print(msg.format(result))
        # print(result)
        # if result.stdout


        kwargs = {
            'auth_url': os.environ['OS_AUTH_URL'],
            'username':'demo',
            'password': os.environ['OS_PASSWORD'],
            'project_name': 'demo',
            'user_domain_name': 'default',
            'project_domain_name': 'default'
        }
        loader = loading.get_plugin_loader('password')
        auth = loader.load_from_options(**kwargs)
        sess = session.Session(auth=auth, verify=False)
        client = heat_client.Client('1', session=sess, endpoint_type='public', service_type='orchestration')
        for stack in client.stacks.list():
            print(stack)