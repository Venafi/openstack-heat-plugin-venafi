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
import pytest
from heatclient import client as heat_client
from keystoneauth1 import loading
from keystoneauth1 import session
from heatclient.common import template_utils
import yaml
import os
import random
import string
import time

def randomString(stringLength=10):
    """Generate a random string of fixed length """
    letters = string.ascii_lowercase
    return ''.join(random.choice(letters) for i in range(stringLength))

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

    # Testing random string template to check that Heat is operating normally.
    def test_random_string(self):
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
        client = heat_client.Client('1', session=sess,
                                    endpoint_type='public',
                                    service_type='orchestration',
                                    endpoint=os.environ['OS_HEAT_URL'])

        template_path = 'fixtures/random_string.yml'
        stack_name = 'random_string_stack_'+randomString(10)
        print(stack_name)
        # Load the template
        _files, template = template_utils.get_template_contents(template_path)
        # Searlize it into a stream
        s_template = yaml.safe_dump(template)
        client.stacks.create(stack_name=stack_name, template=s_template)
        # TODO: rewrite sleep to check of stack status
        time.sleep(10)
        stack = client.stacks.get(stack_name)
        # print(stack.outputs)
        if stack.outputs[0]['output_value'] == None:
            print(stack.outputs[0]['output_error'])
            print(stack.outputs)
            pytest.fail("No output values found")
        else:
            print(stack.outputs)

    def test_venafi_fake_cert(self):
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
        client = heat_client.Client('1', session=sess,
                                    endpoint_type='public',
                                    service_type='orchestration',
                                    endpoint=os.environ['OS_HEAT_URL'])

        template_path = 'fixtures/test_certificate.yml'
        stack_name = 'fake_cert_stack_'+randomString(10)
        print(stack_name)
        # Load the template
        _files, template = template_utils.get_template_contents(template_path)
        # Searlize it into a stream
        s_template = yaml.safe_dump(template)
        client.stacks.create(stack_name=stack_name, template=s_template)
        # TODO: rewrite sleep to check of stack status
        time.sleep(10)
        stack = client.stacks.get(stack_name)
        # print(stack.outputs)
        if stack.outputs[0]['output_value'] == None:
            print(stack.outputs[0]['output_error'])
            print(stack.outputs)
            pytest.fail("No output values found")
        res = client.resources.get(stack.id, 'fake_certificate')
        if res.resource_status == 'CREATE_COMPLETE':
            print(stack.outputs)
        else:
            print("Resource not found")
        for stack in client.stacks.list():
            print(stack)