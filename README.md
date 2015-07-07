# NetStorage communication Kit [![PyPI](https://img.shields.io/pypi/status/Django.svg?style=flat-square)](https://pypi.python.org/pypi/NetStorageKit)

## Usage

The [tests](tests.py) describe the usage thoroughly, but consider this upload example.

```python
import netstoragekit as ns

# NetStorage connection information
# The host part is prepended to -nsu.akamaihd.net, i.e. mycdn-nsu.akamaihd.net
test = dict(key_name='abc', key='abcdefghijk1234'
            cpcode='12345', host='mycdn')

# Create a Request instance
request = ns.api.Request(test['key_name'], test['key'],
                         test['cpcode'], test['host'])

remote_path = 'media/images/products/123.jpg'
local_path = '/opt/data/products/123.jpg'

# Upload the local path to the remote one (always relative to the CPCode)
# The returned data is the XML returned by the API parsed as a python object
# The response is the object as returned by the requests package
data, response = request.upload(remote_path, local_path)
```

## Installation

### Development

```shell
pip install autoenv
pip install virtualenv
virtualenv -p /usr/bin/python2.7.9 env
source env/bin/activate
python setup.py install
# Run tests
py.test tests.py
```

### Production

```shell
pip install netstoragekit
```
