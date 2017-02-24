TEST_TARGETS=centos\:5 centos\:6 centos\:7

test: $(addprefix test-,$(TEST_TARGETS))
	flake8 --ignore E501

test-%:
	docker run -it --volume $(CURDIR):/app $* python /app/bootstrap.py --help
