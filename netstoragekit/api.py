# -*- coding: utf-8 -*-
import sys
import logging
from urllib import quote_plus
import requests
import responses
from .exceptions import NetStorageKitError
from .auth import get_data, get_sign
from .utils import format_response, reraise_exception, get_remote_path
try:
    import xml.etree.cElementTree as et
except ImportError:
    import xml.etree.ElementTree as et


log = logging.getLogger(__name__)


class Request(object):
    """An authenticated request to the NetStorage API."""

    def __init__(self, key_name, key, cpcode, host, secure=True,
                 timestamp=None, unique_id=None, testing=None):
        """Request initializer.

        Args:
            key_name: The NS Upload Account key_name as configured in Luna.
            key: The NS Upload Account key as configured in Luna.
            cpcode: The CPCode.
            host: Hostname preffix, e.g. "media" in "media-nsu.akamaihd.net".
            secure: Whether or not to use a secured connection (SSL).
            timestamp: Optional timestamp (for testing purposes).
            unique_id: Optional unique identifier (for testing purposes).
            testing: Dictionary to mock the responses. Available items include:
                - status: The mock HTTP status code.
                - content_type: The mock content_type response header.
                - body: The mock response body.

        """
        self.key_name = key_name
        self.key = key
        self.cpcode = cpcode
        self.host = '%s-nsu.akamaihd.net' % host
        self.secure = secure

        self.timestamp = timestamp
        self.unique_id = unique_id

        # Internal flag that mocks the request when set to true
        self._testing_mode = False
        if testing:
            self.testing = {} if testing is True else testing
            self._testing_mode = True
            log.debug('Testing mode activated: %s' % self.testing)

    def _get_action_header(self, action, **parameters):
        """Gets the X-Akamai-ACS-Action header.

        Args:
            action: The action name to perform, e.g. "upload".
            **parameters: Parameters for the action, e.g. "md5=abcdef12345678abcdef"

        Returns:
            The action header as a dict.
        """
        values = {'version': 1, 'action': action, 'format': 'xml'}
        values.update(parameters)
        # The query string parameters must be sorted alphabetically
        # for testing purposes
        value = '&'.join(['%s=%s' % (k, values[k]) for k in sorted(values)])
        return {'X-Akamai-ACS-Action': value}

    def _get_data_header(self):
        """Gets the X-Akamai-ACS-Auth-Data header.

        Returns:
            The data header as a dict.
        """
        value = get_data(self.key_name,
                         timestamp=self.timestamp, unique_id=self.unique_id)
        return {'X-Akamai-ACS-Auth-Data': value}

    def _get_sign_header(self, path, data, action):
        """Gets the X-Akamai-ACS-Auth-Sign header.

        Args:
            path: The remote path, without CPCode.
            data: The data header value.
            action: The action header value.

        Returns:
            The sign header as a dict.
        """
        value = get_sign(self.key, self.cpcode, path, data, action)
        return {'X-Akamai-ACS-Auth-Sign': value}

    def get_headers(self, path, action, **parameters):
        """Gets all the headers needed to perform an authenticated request.
            Currently: user-agent, action, data and sign headers.

        Args:
            path: The remote path, without CPCode.
            action: The API action name, e.g. "du".
            **parameters: Additional parameters to the given action.

        Returns:
            A dict of headers.
        """
        action_header = self._get_action_header(action, **parameters)
        action_value = action_header.values()[0]
        data_header = self._get_data_header()
        data_value = data_header.values()[0]
        sign_header = self._get_sign_header(path, data_value, action_value)
        headers = {
            'Host': self.host,
            'User-Agent': 'NetStorageKit-Python/1.0',
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
            path: The remote path, without CPCode, with/without leading/trailing slash.
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
            remote_path = get_remote_path(self.cpcode, path)
            protocol = 'https' if self.secure else 'http'
            url = '%s://%s%s' % (protocol, self.host, remote_path)
            headers = self.get_headers(path, action, **parameters)
            hooks = {'response': callback} if callback else None

            # For testing purposes, mock the responses according to the
            # testing dict
            if self._testing_mode:
                with responses.RequestsMock() as r:
                    log.debug('Added mock response %s %s' % (method, url))
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
            error = '[%s] Failed %s call:\n%s'
            error %= (response.status_code, action, format_response(response))
            log.critical(error)
        return response

    # API calls
    # All paths should be relative to the CPCode directory

    def mock(self, method='GET', path='/mock', action='mock', callback=None,
             **parameters):
        """Mock API call, using the responses package.

        This method doesn't make any HTTP connections.

        Args:
            method: The mock HTTP method in uppercase.
            path: The mock remote path, without CPCode.
            action: The mock API action name.
            callback: Optional callback to process the mock response.
            **parameters: Additional parameters to the given mock action, e.g.
                'mtime=1260000000' for the 'mtime' action.

        Returns:
            A tuple consisting of:
            1. The relevant data as a dict, currently just None.
            2. The mock response as returned by requests.
        """
        response = self._send('GET', path, action, callback=callback, **parameters)
        return None, response

    def du(self, path, callback=None):
        """Disk Usage.

        Gets the number of files and total bytes inside the provided path.

        Example response:
            <du directory="/dir1/dir2">
                <du-info files="12399999" bytes="383838383838"/>
            </du>

        Args:
            path: The remote path, without CPCode.
            callback: Optional callback to process the response further.

        Returns:
            A tuple consisting of:
            1. The relevant data (parsed xml) as a dict.
            2. The response as returned by requests.

        Raises:
            NetStorageKitError: A wrapper of any XML parsing error.
        """
        data = None
        response = self._send('GET', path, 'du', callback=callback)

        if response.status_code != 200:
            return data, response

        try:
            xml = et.fromstring(response.text)
            data = xml.find('du-info').attrib
        except (et.ParseError, AttributeError), e:
            log.critical('[101] Failed to parse response: ' + e.message)
            reraise_exception(e)
        return data, response
