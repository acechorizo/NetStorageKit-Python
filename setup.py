# -*- coding: utf-8 -*-
from os.path import expanduser
from setuptools import setup

setup(
    name='NetStorageKit',
    version='1.0',
    description='Akamai\'s NetStorage API communication kit',
    author='Ernesto Mendoza Blanco',
    author_email='ernestom@mentanetwork.com',
    install_requires=[
        'requests',
        'responses',
        'pytest'
        'requests[security]'
    ],
    data_files=[(expanduser('~'), ['netstoragekit_test_credentials.json.dist'])]
)
