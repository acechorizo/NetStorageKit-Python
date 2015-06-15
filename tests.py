# -*- coding: utf-8 -*-
import sys
import logging
import pytest
import netstoragekit as ns


# Configure the logging level and stream to stdout to see the logs.
logging.basicConfig(level=logging.DEBUG, stream=sys.stdout)


def test_http_headers():
    key_name = 'test-key'
    key = '123'
    cpcode = '12345'
    path = '/dir1/dir2/file.html'

    # the action parameters should be assembled in alphabetical order
    expected_action = 'action=upload&md5=0123456789abcdef0123456789abcdef&mtime=1260000000&version=1'
    expected_data = '5, 0.0.0.0, 0.0.0.0, 1280000000, 382644692, %s' % key_name
    expected_sign = '8XSSLmZqQz8FDHBqvswtQIVu4JYwxO5E6sJwGXMtY6o='

    # Test auth functions

    # Should accept numeric, string or unicode parameters
    data = ns.auth.get_data(unicode(key_name), timestamp=1280000000, unique_id=382644692)
    sign = ns.auth.get_sign(unicode(key), path, expected_data, expected_action)

    assert data == expected_data
    assert sign == expected_sign

    # Test auth function calls inside Request

    request = ns.api.Request(key_name, key, cpcode, 'host',
                             timestamp='1280000000', unique_id='382644692',
                             testing=True)
    parameters = {'md5': '0123456789abcdef0123456789abcdef', 'mtime': '1260000000'}
    _, r = request.mock(path=path, action='upload', **parameters)

    assert r.request.headers['X-Akamai-ACS-Action'] == expected_action
    assert r.request.headers['X-Akamai-ACS-Auth-Data'] == expected_data
    assert r.request.headers['X-Akamai-ACS-Auth-Sign'] == expected_sign


def test_http_responses():

    def make_callback(code):
        def callback(response, *args, **kwargs):
            assert response.status_code == code
        return callback

    # Secure Hostname
    request = ns.api.Request('test-key', '123', '12345', 'host', secure=True, testing=True)
    _, response = request.mock()
    assert response.url == 'https://host-nsu.akamaihd.net/12345/mock'

    # Insecure Hostname
    request = ns.api.Request('test-key', '123', '12345', 'host', secure=False, testing=True)
    _, response = request.mock()
    assert response.url == 'http://host-nsu.akamaihd.net/12345/mock'

    # Valid request
    mock_response = {'status': 200, 'content_type': 'text/html'}
    request = ns.api.Request('test-key', '123', '12345', 'host', testing=mock_response)
    _, response = request.mock()
    assert response.status_code == 200
    assert response.headers['Content-Type'] == 'text/html'

    # Invalid request
    mock_response = {'status': 404, 'body': 'Not Found'}
    request = ns.api.Request('test-key', '123', '12345', 'host', testing=mock_response)
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
    request = ns.api.Request('test-key', '123', '12345', 'host', testing=mock_response)
    data, response = request.du('/du/foo')
    assert response.status_code == 200
    assert data['files'] == '12399999'
    assert data['bytes'] == '383838383838'

    # Invalid response (unclosed tag)
    invalid_mock_response_body = """
    <du directory="/du/foo">
        <du-info files="12399999" bytes="383838383838">
    </du>
    """
    mock_response = {'status': 200, 'body': invalid_mock_response_body}
    with pytest.raises(ns.exceptions.NetStorageKitError):
        request = ns.api.Request('test-key', '123', '12345', 'host', testing=mock_response)
        data, response = request.du('/du/foo')
    assert response.status_code == 200

    # Unexpected response
    mock_response = {'status': 200, 'body': '<totally-invalid-xml>'}
    with pytest.raises(ns.exceptions.NetStorageKitError) as e:
        request = ns.api.Request('test-key', '123', '12345', 'host', testing=mock_response)
        _ = request.du('/')
    assert 'ParseError' in str(e.value)

    # Incomplete response
    mock_response = {'status': 200, 'body': '<du/>'}
    with pytest.raises(ns.exceptions.NetStorageKitError) as e:
        request = ns.api.Request('test-key', '123', '12345', 'host', testing=mock_response)
        _ = request.du('/')
    assert 'AttributeError' in str(e.value)
