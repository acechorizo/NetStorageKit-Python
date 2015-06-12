# -*- coding: utf-8 -*-
import sys
import logging
import pytest
import netstoragekit as ns


# Configure the logging level and stream to stdout to see the logs.
logging.basicConfig(level=logging.DEBUG, stream=sys.stdout)


def test_http_headers():
    key_name = 'key1'
    key = 'abcdefghij'
    cpcode = '12345'
    path = '/dir1/dir2/file.html'
    action = 'version=1&action=upload&md5=0123456789abcdef0123456789abcdef&mtime=1260000000'

    expected_data = '5, 0.0.0.0, 0.0.0.0, 1280000000, 382644692, %s' % key_name
    expected_sign = 'vuCWPzdEW5OUlH1rLfHokWAZAWSdaGTM8yX3bgIDWtA='

    data = ns.auth.get_data(key_name, timestamp=1280000000, unique_id=382644692)
    sign = ns.auth.get_sign(key, path, expected_data, action)

    assert data == expected_data
    assert sign == expected_sign

    request = ns.api.Request(key_name, key, cpcode,
                             timestamp='1280000000', unique_id='382644692',
                             testing=True)
    _, r = request.mock(path=path, action='upload')
    assert r.request.headers['X-Akamai-ACS-Action'] == action
    assert r.request.headers['X-Akamai-ACS-Auth-Data'] == data
    assert r.request.headers['X-Akamai-ACS-Auth-Sign'] == sign

def test_http_responses():

    def make_callback(code):
        def callback(response, *args, **kwargs):
            assert response.status_code == code
        return callback

    # Secure Hostname
    request = ns.api.Request('test-key', '123', '12345', secure=True, testing=True)
    _, response = request.mock()
    assert response.url == 'https://test-key-nsu.akamaihd.net/12345/mock'

    # Insecure Hostname
    request = ns.api.Request('test-key', '123', '12345', secure=False, testing=True)
    _, response = request.mock()
    assert response.url == 'http://test-key-nsu.akamaihd.net/12345/mock'

    # Valid request
    mock_response = {'status': 200, 'content_type': 'text/html'}
    request = ns.api.Request('test-key', '123', '12345', testing=mock_response)
    _, response = request.mock()
    assert response.status_code == 200
    assert response.headers['Content-Type'] == 'text/html'

    # Invalid request
    mock_response = {'status': 404, 'body': 'Not Found'}
    request = ns.api.Request('test-key', '123', '12345', testing=mock_response)
    _, response = request.mock()
    assert response.status_code == 404
    assert 'Not Found' in str(response.text)


def test_api_du():
    # Valid response
    valid_mock_response_body = """
    <du directory="/du/foo">
        <du-info files="12399999" bytes="383838383838"/>
    </du>
    """
    mock_response = {'status': 200, 'body': valid_mock_response_body}
    request = ns.api.Request('test-key', '123', '12345', testing=mock_response)
    data, response = request.du('/du/foo')
    assert response.status_code == 200

    # Invalid response (unclosed tag)
    invalid_mock_response_body = """
    <du directory="/du/foo">
        <du-info files="12399999" bytes="383838383838">
    </du>
    """
    mock_response = {'status': 200, 'body': invalid_mock_response_body}
    with pytest.raises(ns.exceptions.NetStorageKitError):
        request = ns.api.Request('test-key', '123', '12345', testing=mock_response)
        data, response = request.du('/du/foo')
    assert response.status_code == 200

    # Unexpected response
    mock_response = {'status': 200, 'body': '<totally-invalid-xml>'}
    with pytest.raises(ns.exceptions.NetStorageKitError) as e:
        request = ns.api.Request('test-key', '123', '12345', testing=mock_response)
        _ = request.du('/')
    assert 'ParseError' in str(e.value)

    # Incomplete response
    mock_response = {'status': 200, 'body': '<du/>'}
    with pytest.raises(ns.exceptions.NetStorageKitError) as e:
        request = ns.api.Request('test-key', '123', '12345', testing=mock_response)
        _ = request.du('/')
    assert 'AttributeError' in str(e.value)
