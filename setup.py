# -*- coding: utf-8 -*-
from os.path import expanduser
from setuptools import setup

setup(
    name='NetStorageKit',
    version='1.0.3',
    description='Akamai\'s NetStorage API communication kit',
    author='Ernesto Mendoza Blanco',
    author_email='ernestom@mentanetwork.com',
    install_requires=[
        'requests',
        'responses',
        'pytest',
        'ntplib',
        'pytest-cov',
        'requests[security]'
    ],
    url='https://github.com/MentaNetwork/NetStorageKit-Python',
    download_url='https://github.com/MentaNetwork/NetStorageKit-Python',
    package_data={'': ['*.json.dist']},
    include_package_data=True,
    data_files=[(expanduser('~'), ['netstoragekit_test_credentials.json.dist'])],
    classifiers=[
        'Development Status :: 5 - Production/Stable',
        'Environment :: Console',
        'Intended Audience :: Developers',
        'Intended Audience :: System Administrators',
        'License :: OSI Approved :: MIT License',
        'Operating System :: MacOS :: MacOS X',
        'Operating System :: Microsoft :: Windows',
        'Operating System :: POSIX',
        'Programming Language :: Python']
)
