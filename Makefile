default: deploy test

deploy:
	python venafi/resources/tests/deploy_venafi_certificate_plugin.py
test:
	pytest -W ignore venafi/resources/tests/