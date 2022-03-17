#!/usr/bin/env python

"""setup script for katello-client-bootstrap"""

from distutils.core import setup  # pylint:disable=import-error,no-name-in-module
from bootstrap import VERSION

setup(
    name='katello-client-bootstrap',
    version=VERSION,
    description='Bootstrap Script for migrating systems to Foreman & Katello',
    author='Rich Jerrido',
    author_email='rjerrido@outsidaz.org',
    license='GPL-2',
    url='https://github.com/Katello/katello-client-bootstrap',
    scripts=['bootstrap.py'],
    classifiers=[
        'Development Status :: 5 - Production/Stable',
        'Intended Audience :: System Administrators',
        'Topic :: System :: Systems Administration',
        'License :: OSI Approved :: GNU General Public License v2 (GPLv2)',
        'Operating System :: POSIX :: Linux',
        'Programming Language :: Python :: 2',
        'Programming Language :: Python :: 2.6',
        'Programming Language :: Python :: 2.7',
        'Programming Language :: Python :: 3',
        'Programming Language :: Python :: 3.6',
        'Programming Language :: Python :: 3.8',
        'Programming Language :: Python :: 3.9',
    ],
)
