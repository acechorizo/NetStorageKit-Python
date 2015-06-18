## Installation

### Development

```
pip install autoenv
pip install virtualenv
virtualenv -p /usr/bin/python2.7.9 env
source env/bin/activate
python setup.py install
# Run tests
py.test tests.py
```

### Production

```
python setup.py install
```
