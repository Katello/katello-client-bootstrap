TEST_TARGETS=centos\:5 centos\:6 centos\:7

test: $(addprefix test-,$(TEST_TARGETS))
	flake8 --ignore E501 ./bootstrap.py ./setup.py

test-%:
	docker run -it --volume $(CURDIR):/app --workdir=/app $* python bootstrap.py --help
	docker run -it --volume $(CURDIR):/app --workdir=/app $* python setup.py sdist
