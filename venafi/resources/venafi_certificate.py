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
import time
from oslo_log import log as logging

from vcert import Connection, CertificateRequest

NOVA_MICROVERSIONS = (MICROVERSION_KEY_TYPE,
                      MICROVERSION_USER) = ('2.2', '2.10')

LOG = logging.getLogger(__name__)

class VenafiCertificate(resource.Resource):
    """A resource for creating Venafi certificates.
    """

    support_status = support.SupportStatus(version='2014.1')

    PROPERTIES = (
        NAME,
        CN,
        KEY_PASSWORD,
        KEY_TYPE,
        KEY_LENGTH,
        KEY_CURVE,
        SANs,


        ZONE,
    ) = (
        'name',
        'common_name',
        'key_password',
        'key_type',
        'key_length',
        'key_curve',
        'sans',

        'zone',
    )

    ATTRIBUTES = (
        CERTIFICATE_ATTR,
        PRIVATE_KEY,
        CHAIN,
    ) = (
        'certificate',
        'private_key',
        'chain',
    )

    properties_schema = {
        NAME: properties.Schema(
            properties.Schema.STRING,
            _('The name of certificate'),
            required=True,
            constraints=[
                constraints.Length(min=1, max=255)
            ]
        ),
        CN: properties.Schema(
            properties.Schema.STRING,
            _('The common name of certificate'),
            required=True,
            constraints=[
                constraints.Length(min=1, max=255)
            ]
        ),
        KEY_PASSWORD: properties.Schema(
            properties.Schema.STRING,
            _("Cryptography key password"),
            default=None,
        ),
        KEY_TYPE: properties.Schema(
            properties.Schema.STRING,
            _("Cryptography key type"),
            default="RSA",
            constraints=[constraints.AllowedValues(("RSA", "ECDSA"))],
        ),
        KEY_LENGTH: properties.Schema(
            properties.Schema.INTEGER,
            _("Key length (only for RSA key_type)"),
            default=2048,
            constraints=[constraints.AllowedValues((1024, 2048, 4096, 8192))],
        ),
        KEY_CURVE: properties.Schema(
            properties.Schema.STRING,
            _("Key curve (only for ecdsa key_type)"),
            default="p521",
            constraints=[constraints.AllowedValues(("p521", "p256", "p224", "p384"))],
        ),
        SANs: properties.Schema(
            properties.Schema.LIST,
            _("List of Subject Alternative Names"),
            default=tuple(),
        ),
        ZONE: properties.Schema(
            properties.Schema.STRING,
            _("Venafi Trust Platform or Cloud zone name"),
            required=True,
            constraints=[constraints.Length(min=1, max=255)]
        ),
    }

    attributes_schema = {
        CERTIFICATE_ATTR: attributes.Schema(
            _('Venafi certificate.'),
            type=attributes.Schema.STRING
        ),
        PRIVATE_KEY: attributes.Schema(
            _('Venafi certificate.'),
            type=attributes.Schema.STRING
        ),
        CHAIN: attributes.Schema(
            _('Venafi certificate.'),
            type=attributes.Schema.STRING
        ),
    }

    default_client_name = 'nova'

    entity = 'venafi_certificate'

    def __init__(self, name, json_snippet, stack):
        super(VenafiCertificate, self).__init__(name, json_snippet, stack)
        self._cache = None
        self.conn = Connection(fake=True)

    @property
    def venafi_certificate(self):
        """Return Venafi certificate for the resource."""
        return 'fake certificate here'

    def get_reference_id(self):
        return self.resource_id

    def enroll(self):
        LOG.info("Running enroll")
        common_name = self.properties[self.CN]
        LOG.info("common name is %s", common_name)
        sans = self.properties[self.SANs]
        LOG.info("sans is %s", sans)
        privatekey_passphrase = self.properties[self.KEY_PASSWORD]
        LOG.info("privatekey_passphrase is %s", privatekey_passphrase)
        privatekey_type = self.properties[self.KEY_TYPE]
        LOG.info("privatekey_type is %s", privatekey_type)
        curve = self.properties[self.KEY_CURVE]
        LOG.info("curve is %s", curve)
        key_size = self.properties[self.KEY_LENGTH]
        LOG.info("key_size is %s", key_size)
        zone = self.properties[self.ZONE]
        LOG.info("zone is %s", zone)
        LOG.info("Creating request with CN %s", common_name)
        request = CertificateRequest(
            common_name,
            privatekey_passphrase,
        )


        if privatekey_type:
            key_type = {"RSA": "rsa", "ECDSA": "ec", "EC": "ec"}.get(privatekey_type)
            if not key_type:
                raise Exception("Failed to determine key type: %s. "
                                "Must be RSA or ECDSA" % privatekey_type)
            request.key_type = key_type
            request.key_curve = curve
            request.key_length = key_size

        san_dns = sans  # todo
        ip_addresses = []
        email_addresses = []
        request.ip_addresses = ip_addresses
        request.san_dns = san_dns
        request.email_addresses = email_addresses


        LOG.info("Requesting certificate")
        self.conn.request_cert(request, zone)
        LOG.info("CSR: %s", request.csr)
        while True:
            LOG.info("Trying to retrieve certificate")
            cert = self.conn.retrieve_cert(request)  # vcert.Certificate
            if cert:
                break
            else:
                time.sleep(5)

        LOG.info("Got certificate: %s", cert.cert)
        return {self.CHAIN: cert.chain, self.CERTIFICATE_ATTR: cert.cert, self.PRIVATE_KEY: request.private_key_pem}


    def _resolve_attribute(self, name):

        LOG.info("Trying to get values from cache")
        # if self._cache is None:
        #     self._cache = self.enroll()

        # if name not in self._cache:
        #     raise exception.InvalidTemplateAttribute
        # self._cache = self.enroll()

        self._cache = self.enroll()
        return self._cache[name]
        # d = {'certificate':'cert1111',
        # 'private_key':'pk1',
        # 'chain':'chhh1111',}
        # return d[name]



def resource_mapping():
    return {'OS::Nova::VenafiCertificate': VenafiCertificate}
