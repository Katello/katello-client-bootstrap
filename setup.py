#!/usr/bin/env python

from distutils.core import setup

setup(name='katello-client-bootstrap',
      version='1.2.0',
      description='Bootstrap Script for migrating systems to Foreman & Katello',
      author='Rich Jerrido',
      author_email='rjerrido@outsidaz.org',
      url='https://github.com/Katello/katello-client-bootstrap',
      packages=['bootstrap'],
     )
