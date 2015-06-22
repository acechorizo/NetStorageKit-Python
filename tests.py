# -*- coding: utf-8 -*-
import sys
import os
import json
import time
import logging
import tempfile
import pytest
import ntplib
import netstoragekit as ns

# Configure the logging level and stream to stdout to see the logs.
logging.basicConfig(level=logging.DEBUG,
                    format="%(levelname)s[%(name)s.%(funcName)s:%(lineno)s] %(message)s",
                    stream=sys.stdout)


### Testing helpers

def get_test_credentials():
    # This file is installed in the home dir as a .json.dist file
    # that the user should update in order for these tests to run
    file = '~/netstoragekit_test_credentials.json'
    file = os.path.expanduser(file)
    if not os.path.exists(file):
        return None
    with open(file) as data:
        test_credentials = json.load(data)
    return test_credentials

test_credentials = get_test_credentials()


# Decorator that runs tests only if there are test credentials
real_netstorage_api_request = pytest.mark.skipif(test_credentials is None,
    reason='The test credentials .json file was not found in ~')


def get_sample_text():
    lorem = 'Lorem ipsum dolor sit amet.'
    return '\n'.join([lorem for t in range(100)])

def get_temp_file(contents=None):
    file = tempfile.NamedTemporaryFile(prefix=__name__, delete=False)
    if contents:
        open(file.name, 'wb').write(contents)
    return file

### Tests

def test_local_clock():
    # Local clock must be within one minute of the actual time
    # according to the docs, but in practice, ~50 seconds of difference
    # are enough to get a request rejected
    client = ntplib.NTPClient()
    response = client.request('time1.google.com')
    remote_time = (response.tx_time + response.offset)
    diff = abs(remote_time - time.time())
    assert diff < 50, 'Local clock must be updated'


def test_api_http_headers():
    key_name = 'key1'
    key = 'abcdefghij'
    host = 'key1'
    cpcode = 'dir1'
    path = '/dir2/file.html'

    # Test auth functions

    # The following 3 tests are based on the example provided by Akamai in
    # the documentation, but even though it effectively demonstrates the
    # algorithm to generate the headers, it does not include key variables
    # that the API treat as mandatory, namely
    # * the CPCode in the path and
    # * the format=xml action parameter.
    # The tests reflect and execute that flawed example along with full,
    # complete examples that use real data.

    # Test 1: The action parameters should be assembled in alphabetical order
    # but this first test uses an example from the documentation as is

    example_action = 'version=1&action=upload&md5=0123456789abcdef0123456789abcdef&mtime=1260000000'
    example_data = '5, 0.0.0.0, 0.0.0.0, 1280000000, 382644692, key1'
    example_sign = 'vuCWPzdEW5OUlH1rLfHokWAZAWSdaGTM8yX3bgIDWtA='
    example_sign_string = ('5, 0.0.0.0, 0.0.0.0, 1280000000, 382644692, key1/dir1/dir2/file.html\n'
                            'x-akamai-acs-action:%s\n' % example_action)

    data = ns.auth.get_data(key_name, timestamp=1280000000, unique_id=382644692)
    sign = ns.auth.get_sign(key, cpcode, path, example_data, example_action)
    sign_string = ns.auth.get_sign_string(cpcode, path, example_data, example_action)

    assert data == example_data
    assert sign_string == example_sign_string
    assert sign == example_sign


    # Test 2: Action parameters in alphabetical order

    expected_action = 'action=upload&md5=0123456789abcdef0123456789abcdef&mtime=1260000000&version=1'
    expected_data = '5, 0.0.0.0, 0.0.0.0, 1280000000, 382644692, key1'
    expected_sign = '6s1fEWwrzlOXbd35A4e1u0Lc145Sh78vP0ZIP44OaEs='
    expected_sign_string = ('5, 0.0.0.0, 0.0.0.0, 1280000000, 382644692, key1/dir1/dir2/file.html\n'
                            'x-akamai-acs-action:%s\n' % expected_action)

    # Should accept numeric, string or unicode parameters
    data = ns.auth.get_data(unicode(key_name), timestamp=1280000000, unique_id=382644692)
    sign = ns.auth.get_sign(unicode(key), cpcode, path, expected_data, expected_action)
    sign_string = ns.auth.get_sign_string(cpcode, path, expected_data, expected_action)
    sign_string.replace('&format=xml', '')

    assert data == expected_data
    assert sign == expected_sign
    assert sign_string == expected_sign_string

    # Test 3: auth function calls inside the Request class

    request = ns.api.Request(key_name, key, cpcode, host,
                             timestamp=1280000000, unique_id=382644692,
                             testing=True)
    parameters = {'md5': '0123456789abcdef0123456789abcdef', 'mtime': '1260000000'}
    _, r = request.mock(path=path, action='upload', **parameters)

    # API headers
    assert r.request.headers['X-Akamai-ACS-Action'].replace('&format=xml', '') == expected_action
    assert r.request.headers['X-Akamai-ACS-Auth-Data'] == expected_data
    # The Request class includes the mandatory format parameter in the action
    # before it is used to build the hashed sign, and thus we can't remove it
    # like we did we the data header
    # This assertion will always fail for the above example
    #assert r.request.headers['X-Akamai-ACS-Auth-Sign'] == expected_sign


def test_parameters():

    def response_callback(response, *args, **kwargs):
        assert 'verify' in kwargs
        assert response.status_code == 200

    parameters_for_requests_lib = {
        'headers': {'X-Test-Header': 'OK'},
        'hooks': {'response': response_callback}
    }
    request = ns.api.Request('test-key', '123', '12345', 'host', testing=True,
                             **parameters_for_requests_lib)

    parameters_for_akamai_action = {'param1': 'test1'}
    _, r = request.mock(**parameters_for_akamai_action)

    # Test `requests.request` parameters such as headers and hooks
    assert r.request.headers['X-Test-Header'] == 'OK'
    # Test parameters send to the API as part of the action header
    assert r.request.headers['X-Akamai-ACS-Action'].find('param1=test1') > 0


def test_http_parameters():

    request = ns.api.Request('test-key', '123', '12345', 'host', testing=True)
    # Parameters should be properly escaped as part of the action header
    parameters = {'p1': 'Simple text', 'p2': 'mamá', 'p3': u's\xe9',
                  'size': 0, 'foo': None}
    _, r = request.mock(**parameters)
    expected_quoted_params = 'p1=Simple+text&p2=mam%C3%A1&p3=s%C3%A9'
    assert r.request.headers['X-Akamai-ACS-Action'].find(expected_quoted_params) > 0


def test_mock_http_responses():

    # Secure Hostname
    request = ns.api.Request('test-key', '123', '12345', 'host', secure=True, testing=True)
    _, r = request.mock()
    assert r.url == 'https://host-nsu.akamaihd.net/12345/mock'

    # Insecure Hostname
    request = ns.api.Request('test-key', '123', '12345', 'host', secure=False, testing=True)
    _, r = request.mock()
    assert r.url == 'http://host-nsu.akamaihd.net/12345/mock'

    # Valid request
    mock_response = {'status': 200, 'content_type': 'text/html'}
    request = ns.api.Request('test-key', '123', '12345', 'host', testing=mock_response)
    _, r = request.mock()
    assert r.status_code == 200
    assert r.headers['Content-Type'] == 'text/html'

    # Invalid request
    mock_response = {'status': 404, 'body': 'Not Found'}
    request = ns.api.Request('test-key', '123', '12345', 'host', testing=mock_response)
    _, e = request.mock()
    assert e.response.status_code == 404
    assert 'Not Found' in str(e.response.text)


@real_netstorage_api_request
def test_real_http_failed_responses():
    test = test_credentials

    # Service unavailable
    request = ns.api.Request('invalid_key_name', 'invalid_key',
                             'invalid_cpcode', 'invalid_host')
    data, e = request.du('/')
    assert data is None
    assert e.response.status_code == 503

    # Forbidden
    request = ns.api.Request(test['key_name'], 'INVALID_KEY',
                             test['cpcode'], test['host'])
    data, e = request.du('/')
    assert data is None
    assert e.response.status_code == 403

    # Test HTTP 403 Forbidden

    # The time of the client must be within one minute of the actual time
    delayed_timestamp = time.time() - 65
    request = ns.api.Request(test['key_name'], test['key'],
                             test['cpcode'], test['host'],
                             timestamp=delayed_timestamp)
    data, e = request.du('/')
    assert data is None
    assert e.response.status_code == 403

    # Test HTTP 404 Not Found

    request = ns.api.Request(test['key_name'], test['key'],
                             test['cpcode'], test['host'])
    data, e = request.du('/does-not-exist-%s' % time.time())
    assert data is None
    assert e.response.status_code == 404


def test_http_timedout_responses():
    test = test_credentials
    # Test timeout

    # Empty cpcode to request /delay/3 to httpbin.org
    request = ns.api.Request('key', 'key_name', '', 'host', **{'timeout': .5})
    request.host = 'httpbin.org'

    # Timeout

    # Timeout yields an empty response
    data, e = request.du('/delay/4')
    assert data is None
    assert isinstance(e, Exception)
    assert e.response is None
    assert 'Read timed out' in str(e)

    # OK
    request.parameters['timeout'] = 5
    data, r = request.du('/delay/1')
    assert data is not None
    assert r.status_code == 200


@real_netstorage_api_request
def test_real_http_successful_responses():
    test = test_credentials

    # An empty path means everything inside the CPCode
    path = ''

    # Sample timestamp and unique_id to test
    # expected responses against the aactual ones using the same data
    timestamp = int(time.time())
    unique_id = int(timestamp * 2.5)

    # These are all the expected results, minus the auth sign,
    # that is always computed with the new timestamp and unique_id from above
    expected_action = 'action=du&format=xml&version=1'
    expected_data = '5, 0.0.0.0, 0.0.0.0, %s, %s, %s' % (timestamp, unique_id, test['key_name'])
    expected_sign_string = (
        '5, 0.0.0.0, 0.0.0.0, %s, %s, %s/%s%s\nx-akamai-acs-action:%s\n' %
        (timestamp, unique_id, test['key_name'], test['cpcode'], path, expected_action))

    # Test HTTP 200 OK

    request = ns.api.Request(test['key_name'], test['key'],
                             test['cpcode'], test['host'],
                             timestamp=timestamp, unique_id=unique_id)
    data, r = request.du(path)
    # Test the auth function calls inside the Request class
    assert ns.auth.get_sign_string(test['cpcode'], path, expected_data, expected_action) == expected_sign_string
    assert r.request.headers['X-Akamai-ACS-Action'] == expected_action
    assert r.request.headers['X-Akamai-ACS-Auth-Data'] == expected_data
    assert r.request.headers['X-Akamai-ACS-Auth-Sign'] == ns.auth.get_sign(test['key'], test['cpcode'], path, expected_data, expected_action)
    # Test the actual method result
    assert data != None


def test_mock_du_response():
    # Valid response
    valid_mock_response_body = """
    <?xml version="1.0" encoding="ISO-8859-1"?>
    <du directory="/du/foo">
        <du-info files="12399999" bytes="383838383838"/>
    </du>
    """
    mock_response = {'status': 200, 'body': valid_mock_response_body}
    request = ns.api.Request('test-key', '123', '12345', 'host', testing=mock_response)
    data, r = request.du('/du/foo')
    assert r.status_code == 200
    assert data.du.directory == '/du/foo'
    assert data.du['du-info'].files == '12399999'
    assert data.du['du-info'].bytes == '383838383838'

    # Invalid response (unclosed tag)
    invalid_mock_response_body = """
    <?xml version="1.0" encoding="ISO-8859-1"?>
    <du directory="/du/foo">
        <du-info files="12399999" bytes="383838383838">
    </du>
    """
    mock_response = {'status': 200, 'body': invalid_mock_response_body}
    with pytest.raises(ns.exceptions.NetStorageKitError) as e:
        request = ns.api.Request('test-key', '123', '12345', 'host', testing=mock_response)
        data, r = request.du('/du/foo')
    assert r.status_code == 200
    assert 'ParseError' in str(e.value)

    # Unexpected response
    mock_response = {'status': 200, 'body': '<totally-invalid-xml>'}
    with pytest.raises(ns.exceptions.NetStorageKitError) as e:
        request = ns.api.Request('test-key', '123', '12345', 'host', testing=mock_response)
        _ = request.du('/')
    assert 'ParseError' in str(e.value)

    # Incomplete response
    mock_response = {'status': 200, 'body': '<du/>'}
    request = ns.api.Request('test-key', '123', '12345', 'host', testing=mock_response)
    data, r = request.du('/')
    assert data.du is None


@real_netstorage_api_request
def test_real_du_response():
    test = test_credentials

    # Valid response
    request = ns.api.Request(test['key_name'], test['key'],
                             test['cpcode'], test['host'])
    data, r = request.du('/')
    assert data.du.directory.strip('/') == test['cpcode']
    assert data.du['du-info'].files
    assert data.du['du-info'].bytes

    # Invalid response
    request = ns.api.Request(test['key_name'], test['key'],
                             test['cpcode'], test['host'])
    data, e = request.du('/does-not-exist')
    assert data is None
    assert e.response.status_code == 404


def test_mock_dir_response():
    # Valid response
    valid_mock_response_body = """
    <?xml version="1.0" encoding="ISO-8859-1"?>
    <stat directory="/dir/foo">
        <file type="file" name="a.jpg" mtime="1395977462" size="123" md5="d41d8cd98f00b204e9800998ecf8427e"/>
        <file type="file" name="b.png" mtime="1395977461" size="123" md5="d41d8cd98f00b204e9800998ecf8427e"/>
        <file type="dir" name="test2" mtime="1395977462"/>
    </stat>
    """
    mock_response = {'status': 200, 'body': valid_mock_response_body}
    request = ns.api.Request('test-key', '123', '12345', 'host', testing=mock_response)
    data, r = request.dir('/dir/foo')
    assert r.status_code == 200
    assert data.stat.directory == '/dir/foo'
    assert data.stat.file[0].name == 'a.jpg'
    assert data.stat.file[1].name == 'b.png'
    assert data.stat.file[2].name == 'test2'
    assert data.stat.file[2].type == 'dir'

    # Invalid response (unclosed tag)
    invalid_mock_response_body = """
    <?xml version="1.0" encoding="ISO-8859-1"?>
    <stat directory="/dir/foo">
        <file type="dir" name="test2" mtime="1395977462">
    </stat>
    """
    mock_response = {'status': 200, 'body': invalid_mock_response_body}
    with pytest.raises(ns.exceptions.NetStorageKitError) as e:
        request = ns.api.Request('test-key', '123', '12345', 'host', testing=mock_response)
        data, r = request.du('/dir/foo')
    assert r.status_code == 200
    assert 'ParseError' in str(e.value)

    # Unexpected response
    mock_response = {'status': 200, 'body': '<totally-invalid-xml>'}
    with pytest.raises(ns.exceptions.NetStorageKitError) as e:
        request = ns.api.Request('test-key', '123', '12345', 'host', testing=mock_response)
        _ = request.dir('/')
    assert 'ParseError' in str(e.value)

    # Incomplete response
    mock_response = {'status': 200, 'body': '<stat/>'}
    request = ns.api.Request('test-key', '123', '12345', 'host', testing=mock_response)
    data, r = request.dir('/')
    assert data.stat is None


@real_netstorage_api_request
def test_real_dir_response():
    test = test_credentials

    # Valid response
    request = ns.api.Request(test['key_name'], test['key'],
                             test['cpcode'], test['host'])
    data, r = request.dir('/')
    assert data.stat.directory.strip('/') == test['cpcode']

    # Invalid response
    request = ns.api.Request(test['key_name'], test['key'],
                             test['cpcode'], test['host'])
    data, e = request.dir('/does-not-exist')
    assert data is None
    assert e.response.status_code == 404


def test_mock_download_response():
    # Mock response
    response_body = get_sample_text()

    destination = get_temp_file()

    mock_response = {'status': 200, 'content_type': 'text/plain', 'body': response_body}
    request = ns.api.Request('test-key', '123', '12345', 'host', testing=mock_response)
    data, r = request.download('/dir/file.txt', destination.name)
    assert data is None
    assert r.status_code == 200
    #assert r.headers['Content-Length'] == len(response_body)
    assert len(destination.read()) == len(response_body)

    mock_response = {'status': 404, 'content_type': 'text/plain', 'body': 'Not Found'}
    request = ns.api.Request('test-key', '123', '12345', 'host', testing=mock_response)
    data, e = request.download('/dir/file.txt', destination.name)
    assert data is None
    assert e.response.status_code == 404

    mock_response = {'status': 200, 'content_type': 'text/plain', 'body': response_body}
    request = ns.api.Request('test-key', '123', '12345', 'host', testing=mock_response)
    with pytest.raises(ns.exceptions.NetStorageKitError) as e:
        data, e = request.download('/dir/file.txt', '/does/not/exist/dest')
    assert 'No such file' in str(e)

    os.unlink(destination.name)


def test_mock_upload_response():
    # Mock response

    source = get_temp_file()
    confirmation = '<HTML>Request Processed</HTML>'

    mock_response = {'status': 200, 'content_type': 'text/plain',
                     'body': confirmation}
    request = ns.api.Request('test-key', '123', '12345', 'host', testing=mock_response)
    data, r = request.upload('/dir/file.txt', source.name)

    assert data is None
    assert r.status_code == 200
    assert r.text == confirmation


def test_mock_delete_response():

    confirmation = '<HTML>Request Processed</HTML>'

    # Upload a file first
    response_body = get_sample_text()
    sample_text = get_sample_text()
    upload_file = get_temp_file(sample_text)

    mock_response = {'status': 200, 'content_type': 'text/plain',
                     'body': confirmation}
    request = ns.api.Request('test-key', '123', '12345', 'host', testing=mock_response)
    _, r = request.upload('/dir/file.txt', upload_file.name)
    assert r.text == confirmation

    # Delete the file
    mock_response = {'status': 200, 'content_type': 'text/plain',
                     'body': confirmation}
    request = ns.api.Request('test-key', '123', '12345', 'host', testing=mock_response)
    data, r = request.delete('/dir/file.txt')
    assert data is None
    assert r.status_code == 200
    assert r.text == confirmation

    # The file no longer exist
    mock_response = {'status': 404, 'content_type': 'text/plain', 'body': 'Not Found'}
    request = ns.api.Request('test-key', '123', '12345', 'host', testing=mock_response)
    data, e = request.download('/dir/file.txt', upload_file.name)
    assert data is None
    assert e.response.status_code == 404
    assert r.text == confirmation

    os.unlink(upload_file.name)


@real_netstorage_api_request
def test_real_upload_download_delete_response():
    test = test_credentials

    confirmation = '<HTML>Request Processed</HTML>\n'
    path = 'netstoragekit_test_file.txt'

    sample_text = get_sample_text()
    # The file to upload
    upload_file = get_temp_file(sample_text)
    # The destination file
    download_file = get_temp_file()


    # Upload a file first
    request = ns.api.Request(test['key_name'], test['key'],
                             test['cpcode'], test['host'])
    data, r = request.upload(path, upload_file.name)
    assert data is None
    assert r.status_code == 200
    assert r.text == confirmation
    time.sleep(1.5)
    # Then download it back and compare the contents
    request = ns.api.Request(test['key_name'], test['key'],
                             test['cpcode'], test['host'])
    data, r = request.download(path, download_file.name)
    assert data is None
    assert r.status_code == 200
    assert r.text == sample_text
    assert download_file.read() == sample_text
    time.sleep(1.5)
    # Then delete the file
    request = ns.api.Request(test['key_name'], test['key'],
                             test['cpcode'], test['host'])
    data, r = request.delete(path)
    assert data is None
    assert r.status_code == 200
    assert r.text == confirmation
    time.sleep(1.5)
    # Make sure the file is no longer online
    request = ns.api.Request(test['key_name'], test['key'],
                             test['cpcode'], test['host'])
    data, e = request.download(path, '/dev/null')
    assert data is None
    assert e.response.status_code == 404
    
    os.unlink(upload_file.name)
    os.unlink(download_file.name)
