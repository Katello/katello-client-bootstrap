DOCKER=docker
TEST_TARGETS=centos\:6 centos\:7
TEST3_TARGETS=centos\:stream8 centos\:stream9
USE_SELINUX=$(shell test -d /sys/fs/selinux && echo ":Z")

test: $(addprefix test-,$(TEST_TARGETS)) $(addprefix test3-,$(TEST3_TARGETS)) lint

test-%:
	$(DOCKER) run -i --volume $(CURDIR):/app$(USE_SELINUX) --workdir=/app quay.io/centos/$* python bootstrap.py --help
	$(DOCKER) run -i --volume $(CURDIR):/app$(USE_SELINUX) --workdir=/app quay.io/centos/$* python setup.py sdist

test3-%:
	$(DOCKER) run -i --volume $(CURDIR):/app$(USE_SELINUX) --workdir=/app quay.io/centos/$* /usr/libexec/platform-python bootstrap.py --help
	$(DOCKER) run -i --volume $(CURDIR):/app$(USE_SELINUX) --workdir=/app quay.io/centos/$* /usr/libexec/platform-python setup.py sdist

lint:
	python -m flake8 --ignore E501,W504 ./bootstrap.py ./setup.py
	python -m pylint --reports=n --disable=I --ignore-imports=y ./bootstrap.py ./setup.py
