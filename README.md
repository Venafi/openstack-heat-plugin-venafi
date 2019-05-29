##### Test instructions:
1. Contribute into plugin https://github.com/Venafi/venafi-openstack-heat-plugin
1. Update the plugin on  host:   
```
 ssh stack@devstack-manager 
 cd /usr/lib/heat/venafi-openstack-heat-plugin
 git pull
 ```
1. Install necessary dependencies:   
`pip install -f /usr/lib/heat/venafi-openstack-heat-plugin/requirements.txt`
1.  Restart heat engine service: `sudo systemctl restart devstack@h-eng`
1. Try to create  a stack: `openstack stack create --template   ~/devstack/venafi_certificate.yaml venafi_cert_test`
1. Look into logs: `journalctl -u devstack@h-api.service --since "5 minutes ago"`