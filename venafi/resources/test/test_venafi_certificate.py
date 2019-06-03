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


class TestVenafiCeritifcate(common.HeatTestCase):

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

    def test_venafi_fake_cert(self):
        stack = self.create_stack(self.venafi_fake_cert_defn)
        secret1 = stack['secret1']
        self.assertEqual('secret1', secret1.FnGetRefId())
