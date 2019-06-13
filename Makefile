default: deploy test

deploy:
	python venafi/resources/tests/deploy_venafi_certificate_plugin.py
test:
	pytest -W ignore venafi/resources/tests/
e2e:
	openstack stack create -t venafi/resources/tests/fixtures/test_certificate.yml \
	--parameter common_name="tpp-cert.example.com" \
	--parameter tpp_user=${TPPUSER} \
	--parameter tpp_password=${TPPPASSWORD} \
	--parameter venafi_url=${TPPURL} \
	--parameter zone=${TPPZONE} \
	--parameter trust_bundle=${TRUST_BUNDLE} \
	venafi-tests-stack
