#!/usr/bin/env python

from distutils.core import setup

setup(name='katello-client-bootstrap',
      version='1.2.2',
      description='Bootstrap Script for migrating systems to Foreman & Katello',
      author='Rich Jerrido',
      author_email='rjerrido@outsidaz.org',
      license='GPL-2',
      url='https://github.com/Katello/katello-client-bootstrap',
      scripts=['bootstrap.py'],
      )
