Venafi Heat Plugin for OpenStack
================================

<img src="https://www.venafi.com/sites/default/files/content/body/Light_background_logo.png" width="330px" height="69px"/>

This UNDER DEVELOPMENT solution implements an OpenStack [Heat plugin](https://wiki.openstack.org/wiki/Heat/Plugins) that uses the [VCert-Python](https://github.com/Venafi/vcert-python) library to simplify certificate enrollment and ensure compliance with enterprise security policy. The plugin is designed to be a used in a Heat template to request a certificate from [Venafi Platform](https://www.venafi.com/platform/trust-protection-platform) or [Venafi Cloud](https://pki.venafi.com/venafi-cloud/) for a Heat resource.

### Installation
1. Add the `vcert` and `openstack-heat-plugin-venafi` pip packages to the OpenStack instance:
```bash
pip install openstack-heat-plugin-venafi
``` 
2. Create the default plugin directory `/usr/lib/heat`
```bash
mkdir -p /usr/lib/heat
```
3. Create a symbolic link for the installed plugin in the `/usr/lib/heat` directory
```bash
ln -s $(python -m site --user-site)/venafi-openstack-heat-plugin /usr/lib/heat/
``` 
4. Restart the Heat engine:
```bash
sudo systemctl restart devstack@h-eng
```

### Usage
Review the provided example YAML [test_certificate.yml](venafi/resources/tests/fixtures/test_certificate.yml).  It is strongly recommended to export credentials as variables and add them as hidden parameters to the stack rather than hardcoding them in your configuration.

#### For Venafi Platform:
In most cases you will need to specify a trust bundle because the Venafi Platform is commonly secured using a certificate issued by a private enterprise PKI.  In order to specify a `trust_bundle` you must base64 encode the file contents:
```bash
cat /opt/venafi/bundle.pem |base64 --wrap=10000
```

```bash
openstack stack create -t venafi/resources/tests/fixtures/test_certificate.yml \
--parameter common_name="tpp-usuu1.venafi.example.com" \
--parameter sans="IP:192.168.1.1","DNS:www.venafi.example.com","DNS:m.venafi.example.com","email:test@venafi.com","IP Address:192.168.2.2" \
--parameter tpp_user=admin \
--parameter tpp_password=${TPP_PASSWORD} \
--parameter venafi_url=https://venafi.example.com/vedsdk \
--parameter zone=devops\\default \
--parameter trust_bundle=LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCk1JSURmVENDQW1XZ0F3SUJBZ0lRVW1ZR0tqdzdmazI1Ylg3K29KZDIyakFOQmdrcWhraUc5dzBCQVFzRkFEQkYKTVNjd0pRWURWUVFMRXg1V1pXNWhabWtnVDNCbGNtRjBhVzl1WVd3Z1EyVnlkR2xtYVdOaGRHVXhHakFZQmdOVgpCQU1URVdoaExYUndjREV1YzNGc2FHRXVZMjl0TUI0WERURTVNRFl4TnpJeE1UVXhPRm9YRFRJd01EWXhOakl4Ck1UVXhPRm93UlRFbk1DVUdBMVVFQ3hNZVZtVnVZV1pwSUU5d1pYSmhkR2x2Ym1Gc0lFTmxjblJwWm1sallYUmwKTVJvd0dBWURWUVFERXhGb1lTMTBjSEF4TG5OeGJHaGhMbU52YlRDQ0FTSXdEUVlKS29aSWh2Y05BUUVCQlFBRApnZ0VQQURDQ0FRb0NnZ0VCQUxTYW5RQ0JFUEtXaG1KYzZ0T1Fod1oweExqN25xbm1KWGwrUjF0am9XN3RKUk5kCjljTzRyQzI0RjNFdFNOdnlmRldtSjBidUxEcWNmbkdKR2tWazFkOWtVZWI0elJKbXU0RlBOa1VzdjRRUkRoSGUKc2FydEowZU8wN2Rpek5nMXU4SG0rek5DcGk3TFZQRDhHRGJHeVN0WTVRblE1ZGU0ZllBMnpaV2NQNldRUjU4VApJblE0Q1NtejhiV01iRXdtQTgxdGlNVVR3YWMwTEFuL0hhYjVjOUVhaDlwc0NqSmMydFJiUjhpbmRRQWVmMmEzCkl3VEE1VUpzSHdpRjBGSHFRY2RDSG56NCtEdUVnVUlaaWZCcUNxSkhWdG53S0xya0YzZTNWZDdLemJBQXkzNlcKd2N0ZUhsdFk5UGlFUlRBSnp5WHRBNklscm5XT1lqNlRzNkVCYWJVQ0F3RUFBYU5wTUdjd0hRWURWUjBPQkJZRQpGRmxVc29uYVpwd25RTE9iTTFFNUYwdzNYamQrTUFrR0ExVWRFd1FDTUFBd0hBWURWUjBSQkJVd0U0SVJhR0V0CmRIQndNUzV6Y1d4b1lTNWpiMjB3SFFZRFZSMGxCQll3RkFZSUt3WUJCUVVIQXdFR0NDc0dBUVVGQndNQ01BMEcKQ1NxR1NJYjNEUUVCQ3dVQUE0SUJBUUJYTnorMEJ1YzFlL2o2bnJoUHlRb0g2RDM3N0ptUmplMjBDQW5TSDlwNwpWMW5FeHlOMS83dGtXL0JTOEJtSlF4Ty84dWhBVXNVQ3FWalpleVZVRnN5czc4VE5YeEVQQncrT3lLMlJLVWJDCmJsYTFPa1dTWkxVb1A3WThoTysyWU80R1BnU25ndDhXMWR3dHdjQ1gvMFZEaFNDUEoxU2N0RXUwMHlkSlZpMWEKYkhqb1I5VG0xYXNyeG53Z0ttcGpxQlpsbWxaUDBvZDZyMTRFVFlIZjJKelFxa24rTjY4UHN5Mm1VZlo0ZDBpRQptajdnU0RwUlpvNlk2NHd0WlBoZU9mWlZCaEg3SjhxRUdRcjk5dW5kc0FvSVlla2NVSkd1RjhBRStFZUVuQllWCmNKQWZtYUE2Zmx0R0puVnZlTUpod29xRDVBNzNrcWpzRlNFeUNvZ3VncTRCCi0tLS0tRU5EIENFUlRJRklDQVRFLS0tLS0K \
venafi-tests-stack-usuu1
```
##### ASCIINEMA video:
[![asciicast](https://asciinema.org/a/68jJnqif98QYI4Acn3ot323xt.svg)](https://asciinema.org/a/68jJnqif98QYI4Acn3ot323xt)

#### For Venafi Cloud:
```bash
openstack stack create -t venafi/resources/tests/fixtures/test_certificate.yml \
--parameter common_name="cloud-ag1ya.example.com" \
--parameter sans="DNS:www.venafi.example.com","DNS:m.venafi.example.com" \
--parameter api_key=${CLOUD_APIKEY} \
--parameter zone=Default
```

##### ASCIINEMA video:
[![asciicast](https://asciinema.org/a/l3WfHpViFBhyINI3wY0mEyZkC.svg)](https://asciinema.org/a/l3WfHpViFBhyINI3wY0mEyZkC)
Also see examples in [Makefile](Makefile)

## License

Copyright &copy; Venafi, Inc. All rights reserved.

This solution is licensed under the Apache License, Version 2.0. See `LICENSE` for the full license text.

Please direct questions/comments to opensource@venafi.com.
