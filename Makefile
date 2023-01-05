# Domain used on Venafi Platform demo resources
TPP_DOMAIN := venqa.venafi.com
# Domain used in Venafi Cloud demo resources
CLOUD_DOMAIN := venafi.example.com
# Domain used in fake demo resources
FAKE_DOMAIN := fake.example.com
#Random site name for demo resources
RANDOM_SITE_EXP := $$(head /dev/urandom | tr -dc a-z0-9 | head -c 5 ; echo '')
STACK_NAME=venafi-tests-stack
#STACK_TEMPLATE=venafi/resources/tests/fixtures/test_certificate.yml
STACK_TEMPLATE=venafi/resources/tests/fixtures/test_certificate_output_only.yml

default: install test

install:
	fab install -r openstack-heat-plugin-venafi/resources/tests/install_venafi_certificate_plugin.py

test:
	pytest -W ignore openstack-heat-plugin-venafi/resources/tests/

e2e_fake_create:
	$(eval RANDOM_SITE := $(shell echo $(RANDOM_SITE_EXP)))
	openstack stack create -t $(STACK_TEMPLATE) \
	--parameter common_name="tpp-$(RANDOM_SITE).example.com" \
	--parameter sans="IP:192.168.1.1","DNS:www.venafi.example.com","DNS:m.venafi.example.com","email:test@venafi.com","IP Address:192.168.2.2" \
	--parameter fake='true' \
	$(STACK_NAME)-fake-$(RANDOM_SITE)
	@echo "To check stack run the command:"
	@echo openstack stack show $(STACK_NAME)-fake-$(RANDOM_SITE) -c outputs -f shell

e2e_tpp_create:
	$(eval RANDOM_SITE := $(shell echo $(RANDOM_SITE_EXP)))
	openstack stack create -t $(STACK_TEMPLATE) \
	--parameter common_name="tpp-$(RANDOM_SITE).venafi.example.com" \
	--parameter sans="IP:192.168.1.1","DNS:www.venafi.example.com","DNS:m.venafi.example.com","email:test@venafi.com","IP Address:192.168.2.2" \
	--parameter tpp_user=$(TPPUSER) \
	--parameter tpp_password=$(TPPPASSWORD) \
	--parameter venafi_url=$(TPPURL) \
	--parameter zone=$(TPPZONE) \
	--parameter trust_bundle=$(TRUST_BUNDLE) \
	$(STACK_NAME)-tpp-$(RANDOM_SITE)
	@echo "To check stack run the command:"
	@echo openstack stack show $(STACK_NAME)-tpp-$(RANDOM_SITE) -c outputs -f shell

e2e_cloud_create:
	$(eval RANDOM_SITE := $(shell echo $(RANDOM_SITE_EXP)))
	openstack stack create -t $(STACK_TEMPLATE) \
	--parameter common_name="cloud-$(RANDOM_SITE).example.com" \
	--parameter sans="DNS:www.venafi.example.com","DNS:m.venafi.example.com" \
	--parameter api_key=$(CLOUDAPIKEY) \
	--parameter venafi_url=$(CLOUDURL) \
	--parameter zone=$(CLOUDZONE) \
	$(STACK_NAME)-cloud-$(RANDOM_SITE)
	@echo "To check stack run the command:"
	@echo openstack stack show $(STACK_NAME)-cloud-$(RANDOM_SITE) -c outputs -f shell

e2e_show:
	openstack stack show $(STACK_NAME) -c parameters
	openstack stack show $(STACK_NAME) -c outputs -f shell
	openstack stack output show $(STACK_NAME)  venafi_certificate
	openstack stack output show $(STACK_NAME)  venafi_certificate -c output_value -f shell

publish:
	pip3 install twine setuptools wheel
	rm -rf dist/
	rm -rf openstack_heat_plugin_venafi.egg-info
	python3 setup.py sdist bdist_wheel
	twine upload dist/*
