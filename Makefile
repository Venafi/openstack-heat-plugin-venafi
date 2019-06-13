STACK_NAME=venafi-tests-stack
default: deploy test

deploy:
	python venafi/resources/tests/deploy_venafi_certificate_plugin.py
test:
	pytest -W ignore venafi/resources/tests/
e2e_create:
	openstack stack create -t venafi/resources/tests/fixtures/test_certificate.yml \
	--parameter common_name="tpp-cert.example.com" \
	--parameter tpp_user=${TPPUSER} \
	--parameter tpp_password=${TPPPASSWORD} \
	--parameter venafi_url=${TPPURL} \
	--parameter zone=${TPPZONE} \
	--parameter trust_bundle=${TRUST_BUNDLE} \
	$(STACK_NAME)
e2e_show:
	openstack stack show $(STACK_NAME) -c parameters
	openstack stack show $(STACK_NAME) -c outputs -f shell
	openstack stack output show $(STACK_NAME)  venafi_certificate
	openstack stack output show $(STACK_NAME)  venafi_certificate -c output_value -f shell