# -*- coding: utf-8 -*-
import sys
import logging
from urllib import urlencode
import requests
import responses
from .exceptions import NetStorageKitError
from .auth import get_data, get_sign
try:
    import xml.etree.cElementTree as et
except ImportError:
    import xml.etree.ElementTree as et


log = logging.getLogger(__name__)


def reraise_exception(exception):
    type_, value, traceback = sys.exc_info()
    raise NetStorageKitError, '%s(%s)' % (type_.__name__, value), traceback


class Request(object):

    def __init__(self, key_name, key, cpcode,
                 secure=True, host=None,
                 timestamp=None, unique_id=None,
                 testing=None):
        self.key_name = key_name
        self.key = key
        self.cpcode = cpcode
        self.secure = secure
        self.host = host or (self.key_name + '-nsu.akamaihd.net')

        self.timestamp = timestamp
        self.unique_id = unique_id

        self.testing = {} if testing is True else testing
        if self.testing:
            log.debug('Testing mode activated: %s' % self.testing)

    def get_action_header(self, action, **parameters):
        value = {'version': 1, 'action': action}
        value.update(parameters)
        value = urlencode(value)
        return {'X-Akamai-ACS-Action': value}

    def get_data_header(self):
        value = get_data(self.key_name,
                         timestamp=self.timestamp, unique_id=self.unique_id)
        return {'X-Akamai-ACS-Auth-Data': value}

    def get_sign_header(self, path, data, action):
        value = get_sign(self.key, path, data, action)
        return {'X-Akamai-ACS-Auth-Sign': value}

    def get_headers(self, path, action, **parameters):
        action_header = self.get_action_header(action, **parameters)
        action_value = action_header.values()[0]
        data_header = self.get_data_header()
        data_value = action_header.values()[0]
        sign_header = self.get_sign_header(path, data_value, action_value)
        headers = {
            'User-Agent': 'NetStorageKit-Python/1.0'
        }
        headers.update(action_header)
        headers.update(data_header)
        headers.update(sign_header)
        return headers

    def _send(self, method, path, action, callback=None, **parameters):
        """Sends an API request.

        HTTP Errors are catched and logged to let the caller handle the
        faulty response.

        Args:
            method: The HTTP method in uppercase.
            path: The remote path, without cpcode.
            action: The API action name, e.g. "du".
            callback: Optional callback to process the response.
            **parameters: Additional parameters to the given action, e.g.
                'mtime=1260000000' for the 'mtime' action.

        Returns:
            response: The response object as returned by the underlaying request.

        Raises:
            NetStorageKitError: A wrapper for any exception thrown before
                making the actual request, e.g. an error on the headers construction.

        """
        try:
            full_remote_path = '%s/%s' % (self.cpcode, path.strip('/'))
            protocol = 'https' if self.secure else 'http'
            url = '%s://%s/%s' % (protocol, self.host, full_remote_path)
            headers = self.get_headers(path, action, **parameters)
            hooks = {'response': callback} if callback else None

            # For testing purposes, mock the responses according to the
            # testing dict
            if self.testing:
                with responses.RequestsMock() as r:
                    r.add(method, url,
                          status=self.testing.get('status', 200),
                          content_type=self.testing.get('content_type', 'text/xml'),
                          body=self.testing.get('body', ''))
                    response = requests.request(method, url, headers=headers, hooks=hooks)
            else:
                response = requests.request(method, url, headers=headers, hooks=hooks)

            log.debug('Request: %s %s %s' % (action, url, parameters))
        except Exception, e:
            log.critical('[100] Failed to send request: ' + e.message)
            # Any exception catched here should be handled.
            # Re-raise the exception with our own type for API consumers.
            reraise_exception(e)
        try:
            response.raise_for_status()
        except requests.exceptions.HTTPError, e:
            error = '[%s] Failed to %s on %s' % (response.status_code, action, url)
            log.error(error)
        return response

    def mock(self, method='GET', path='/mock', action='mock', callback=None,
             **parameters):
        response = self._send('GET', path, 'mock', callback=callback, **parameters)
        return None, response
