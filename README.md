![Venafi](Venafi_logo.png)
[![Apache 2.0 License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)
![Community Supported](https://img.shields.io/badge/Support%20Level-Community-brightgreen)
![Compatible with TPP 17.3+ & Cloud](https://img.shields.io/badge/Compatibility-TPP%2017.3+%20%26%20Cloud-f9a90c)  
_**This open source project is community-supported.** To report a problem or share an idea, use
**[Issues](../../issues)**; and if you have a suggestion for fixing the issue, please include those details, too.
In addition, use **[Pull Requests](../../pulls)** to contribute actual bug fixes or proposed enhancements.
We welcome and appreciate all contributions. Got questions or want to discuss something with our team?
**[Join us on Slack](https://join.slack.com/t/venafi-integrations/shared_invite/zt-i8fwc379-kDJlmzU8OiIQOJFSwiA~dg)**!_

Venafi Heat Plugin for OpenStack
================================

This solution implements an OpenStack [Heat plugin](https://wiki.openstack.org/wiki/Heat/Plugins)
that uses the [VCert-Python](https://github.com/Venafi/vcert-python) library to simplify
enrollment of TLS certificates needed for stacks while ensuring their compliance with enterprise
security policy. The plugin is designed to be a used in a Heat template to request a certificate
from [Venafi Platform](https://www.venafi.com/platform/trust-protection-platform) or
[Venafi Cloud](https://pki.venafi.com/venafi-cloud/) for a Heat resource.

### Installation
You should install pip packages into same python python which is used by heat-engine. Instructions may be different 
for your openstack installation.
1. Switch to openstack user

1. Determine python dist-package directory:
   ```bash
   python -m site
   ```

1. Install the `vcert` and `openstack-heat-plugin-venafi` pip packages for use by the OpenStack instance:
   ```bash
   pip install openstack-heat-plugin-venafi
   ``` 

1. Create the default plugin directory `/usr/lib/heat`:
   ```bash
   mkdir -p /usr/lib/heat
   ```

1. Identify where pip package has been locally installed:
   ```bash
   PIP_PKG_LOC=$(pip show openstack-heat-plugin-venafi | awk '/^Location:/{print $2}')
   ```

1. Create a symbolic link for the installed plugin in the `/usr/lib/heat` directory:
   ```bash
   ln -s ${PIP_PKG_LOC}/openstack-heat-plugin-venafi /usr/lib/heat/
   ```
 
1. Restart the Heat engine:
   ```bash
   sudo systemctl restart openstack-heat-engine.service
   ```

### Usage
Review the provided example YAML [test_certificate.yml](openstack-heat-plugin-venafi/resources/tests/fixtures/test_certificate.yml).
It is strongly recommended to export credentials as variables and add them as hidden parameters to
the stack rather than hardcoding them in your configuration.

#### For Venafi Platform:
In most cases you will need to specify a trust bundle because the Venafi Platform is commonly
secured using a certificate issued by a private enterprise PKI.  In order to specify a
`trust_bundle` you must first base64 encode the file contents:
```bash
cat /path/to/bundle.pem |base64 --wrap=10000
```

```bash
openstack stack create -t venafi/resources/tests/fixtures/test_certificate.yml \
--parameter common_name="common-name.venafi.example" \
--parameter sans="DNS:dns-san-1.venafi.example","DNS:dns-san-2.venafi.example","IP:10.20.30.40","IP:192.168.192.168","email:opensource@venafi.com" \
--parameter venafi_url="https://tpp.venafi.example" \
--parameter access_token="tn1PwE1QTZorXmvnTowSyA==" \
--parameter zone="DevOps\\OpenStack" \
--parameter trust_bundle=LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCk1JSURmVENDQW1XZ0F3SUJBZ0lRVW1ZR0tqdzdmazI1Ylg3K29KZDIyakFOQmdrcWhraUc5dzBCQVFzRkFEQkYKTVNjd0pRWURWUVFMRXg1V1pXNWhabWtnVDNCbGNtRjBhVzl1WVd3Z1EyVnlkR2xtYVdOaGRHVXhHakFZQmdOVgpCQU1URVdoaExYUndjREV1YzNGc2FHRXVZMjl0TUI0WERURTVNRFl4TnpJeE1UVXhPRm9YRFRJd01EWXhOakl4Ck1UVXhPRm93UlRFbk1DVUdBMVVFQ3hNZVZtVnVZV1pwSUU5d1pYSmhkR2x2Ym1Gc0lFTmxjblJwWm1sallYUmwKTVJvd0dBWURWUVFERXhGb1lTMTBjSEF4TG5OeGJHaGhMbU52YlRDQ0FTSXdEUVlKS29aSWh2Y05BUUVCQlFBRApnZ0VQQURDQ0FRb0NnZ0VCQUxTYW5RQ0JFUEtXaG1KYzZ0T1Fod1oweExqN25xbm1KWGwrUjF0am9XN3RKUk5kCjljTzRyQzI0RjNFdFNOdnlmRldtSjBidUxEcWNmbkdKR2tWazFkOWtVZWI0elJKbXU0RlBOa1VzdjRRUkRoSGUKc2FydEowZU8wN2Rpek5nMXU4SG0rek5DcGk3TFZQRDhHRGJHeVN0WTVRblE1ZGU0ZllBMnpaV2NQNldRUjU4VApJblE0Q1NtejhiV01iRXdtQTgxdGlNVVR3YWMwTEFuL0hhYjVjOUVhaDlwc0NqSmMydFJiUjhpbmRRQWVmMmEzCkl3VEE1VUpzSHdpRjBGSHFRY2RDSG56NCtEdUVnVUlaaWZCcUNxSkhWdG53S0xya0YzZTNWZDdLemJBQXkzNlcKd2N0ZUhsdFk5UGlFUlRBSnp5WHRBNklscm5XT1lqNlRzNkVCYWJVQ0F3RUFBYU5wTUdjd0hRWURWUjBPQkJZRQpGRmxVc29uYVpwd25RTE9iTTFFNUYwdzNYamQrTUFrR0ExVWRFd1FDTUFBd0hBWURWUjBSQkJVd0U0SVJhR0V0CmRIQndNUzV6Y1d4b1lTNWpiMjB3SFFZRFZSMGxCQll3RkFZSUt3WUJCUVVIQXdFR0NDc0dBUVVGQndNQ01BMEcKQ1NxR1NJYjNEUUVCQ3dVQUE0SUJBUUJYTnorMEJ1YzFlL2o2bnJoUHlRb0g2RDM3N0ptUmplMjBDQW5TSDlwNwpWMW5FeHlOMS83dGtXL0JTOEJtSlF4Ty84dWhBVXNVQ3FWalpleVZVRnN5czc4VE5YeEVQQncrT3lLMlJLVWJDCmJsYTFPa1dTWkxVb1A3WThoTysyWU80R1BnU25ndDhXMWR3dHdjQ1gvMFZEaFNDUEoxU2N0RXUwMHlkSlZpMWEKYkhqb1I5VG0xYXNyeG53Z0ttcGpxQlpsbWxaUDBvZDZyMTRFVFlIZjJKelFxa24rTjY4UHN5Mm1VZlo0ZDBpRQptajdnU0RwUlpvNlk2NHd0WlBoZU9mWlZCaEg3SjhxRUdRcjk5dW5kc0FvSVlla2NVSkd1RjhBRStFZUVuQllWCmNKQWZtYUE2Zmx0R0puVnZlTUpod29xRDVBNzNrcWpzRlNFeUNvZ3VncTRCCi0tLS0tRU5EIENFUlRJRklDQVRFLS0tLS0K \
venafi-test-stack-01
```

##### ASCIINEMA video:
[![asciicast](https://asciinema.org/a/68jJnqif98QYI4Acn3ot323xt.svg)](https://asciinema.org/a/68jJnqif98QYI4Acn3ot323xt)

#### For Venafi Cloud:
Get the Zone ID value to use from the Venafi Cloud web console.
```bash
openstack stack create -t venafi/resources/tests/fixtures/test_certificate.yml \
--parameter common_name="common-name.venafi.example" \
--parameter sans="DNS:dns-san-1.venafi.example","DNS:dns-san-2.venafi.example" \
--parameter api_key="xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx" \
--parameter zone="zzzzzzzz-zzzz-zzzz-zzzz-zzzzzzzzzzzz" \
venafi-test-stack-02
```

##### ASCIINEMA video:
[![asciicast](https://asciinema.org/a/l3WfHpViFBhyINI3wY0mEyZkC.svg)](https://asciinema.org/a/l3WfHpViFBhyINI3wY0mEyZkC)

## License

Copyright &copy; Venafi, Inc. All rights reserved.

This solution is licensed under the Apache License, Version 2.0. See `LICENSE` for the full license text.

Please direct questions/comments to opensource@venafi.com.
