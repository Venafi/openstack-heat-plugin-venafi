#!/usr/bin/env python3
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
import six

from heat.common import exception
from heat.common.i18n import _
from heat.engine import attributes
from heat.engine import constraints
from heat.engine import properties
from heat.engine import resource
from heat.engine import support
from heat.engine import translation


NOVA_MICROVERSIONS = (MICROVERSION_KEY_TYPE,
                      MICROVERSION_USER) = ('2.2', '2.10')


class VenafiCertificate(resource.Resource):
    """A resource for creating Venafi certificates.
    """

    support_status = support.SupportStatus(version='2014.1')

    PROPERTIES = (
        NAME
    ) = (
        'name',
    )

    ATTRIBUTES = (
        CERTIFICATE_ATTR
    ) = (
        'certificate',
    )

    properties_schema = {
        NAME: properties.Schema(
            properties.Schema.STRING,
            _('The name of the key pair.'),
            required=True,
            constraints=[
                constraints.Length(min=1, max=255)
            ]
        ),
    }

    attributes_schema = {
        CERTIFICATE_ATTR: attributes.Schema(
            _('Venafi certificate.'),
            type=attributes.Schema.STRING
        ),
    }

    default_client_name = 'nova'

    entity = 'venafi_certificate'

    def __init__(self, name, json_snippet, stack):
        super(VenafiCertificate, self).__init__(name, json_snippet, stack)
        self._fake_ceritficate = 'fake certificate here'

    @property
    def venafi_certificate(self):
        """Return Venafi certificate for the resource."""
        return self._fake_ceritficate

    def get_reference_id(self):
        return self.resource_id

def resource_mapping():
    return {'OS::Nova::VenafiCertificate': VenafiCertificate}
