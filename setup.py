# -*- coding: utf-8 -*-
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
    ]
)
