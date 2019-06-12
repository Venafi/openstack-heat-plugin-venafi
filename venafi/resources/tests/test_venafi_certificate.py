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
from heat.common import template_format
from heat.engine import stack as parser
from heat.engine import template
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
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.x509.oid import NameOID

PWD = os.path.dirname(os.path.abspath(__file__))

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

    def _prepare_tests(self, fixture, stack_name, stack_parameters):
        kwargs = {
            'auth_url': os.environ['OS_AUTH_URL'],
            'username': 'demo',
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

        template_path = PWD + '/fixtures/' + fixture
        stack_name += randomString(10)
        print(stack_name)
        # Load the template
        _files, template = template_utils.get_template_contents(template_path)
        # Searlize it into a stream
        s_template = yaml.safe_dump(template)
        client.stacks.create(stack_name=stack_name, template=s_template, parameters=stack_parameters)

        # TODO: rewrite sleep to check of stack status
        time.sleep(10)
        stack = client.stacks.get(stack_name)

        if stack.outputs[0]['output_value'] == None:
            print(stack.outputs[0]['output_error'])
            pytest.fail("No output values found")
        else:
            print(stack.outputs)
        return stack, client

    # Testing random string template to check that Heat is operating normally.
    def test_random_string(self):
        self._prepare_tests("random_string.yml", 'random_string_stack_', None)

    def test_venafi_fake_cert(self):
        cn = randomString(10) + '-fake.cert.example.com'
        stack_parameters = {'common_name': cn, 'fake': 'true'}
        stack, client = self._prepare_tests("test_certificate.yml", 'fake_cert_stack_', stack_parameters)
        res = client.resources.get(stack.id, 'fake_certificate')

        if res.resource_status != 'CREATE_COMPLETE':
            pytest.fail("Resource not found")

        cert = x509.load_pem_x509_certificate(stack.outputs[0]['output_value'].encode(), default_backend())
        assert isinstance(cert, x509.Certificate)
        assert cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME) == [
            x509.NameAttribute(
                NameOID.COMMON_NAME, cn
            )
        ]
        print("Cert is fine:\n", stack.outputs[0]['output_value'])

    def test_tpp_enroll_cert(self):
        stack_parameters=None