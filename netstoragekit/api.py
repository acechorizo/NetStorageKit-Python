# -*- coding: utf-8 -*-
import logging
from hashlib import sha256
import requests
import responses
from .exceptions import NetStorageKitError
from .auth import get_data, get_sign
from .utils import (
    escape,
    format_exception,
    format_response,
    get_remote_path,
    reraise_exception,
    xml_to_data)
try:
    import xml.etree.cElementTree as et
except ImportError:
    import xml.etree.ElementTree as et


log = logging.getLogger(__name__)


class Request(object):
    """An authenticated request to the NetStorage API."""

    def __init__(self, key_name, key, cpcode, host, secure=True,
                 timestamp=None, unique_id=None, testing=None, **parameters):
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
            **parameters: Extra request parameters, e.g. headers, hooks, timeout.
        """
        self.key_name = key_name
        self.key = key
        self.cpcode = cpcode
        self.host = '%s-nsu.akamaihd.net' % host
        self.secure = secure

        self.timestamp = timestamp
        self.unique_id = unique_id

        self.parameters = parameters

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
        # Escape the parameters
        values = {'version': 1, 'action': action, 'format': 'xml'}
        values.update({k: escape(v) for k, v in parameters.items()})
        # The query string parameters must sorted alphabetically
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

    def _send(self, method, path, action, data=None, **parameters):
        """Sends an API request.

        HTTP Errors are catched and logged to let the caller handle the
        faulty response.

        Args:
            method: The HTTP method in uppercase.
            path: The remote path, without CPCode, with/without leading/trailing slash.
            action: The API action name, e.g. "du".
            **parameters: Additional parameters to the given action, e.g.
                'mtime=1260000000' for the 'mtime' action.

        Returns:
            A `requests.Response` object in case of success, or
            a `requests.exceptions.RequestException` object otherwise.
            The original failed response is available as a `response`
            attribute in the exception object.

        """
        headers = self.parameters.get('headers', {})
        hooks = self.parameters.get('hooks', {})
        timeout = self.parameters.get('timeout', 15)
        response = None
        try:
            remote_path = get_remote_path(self.cpcode, path)
            protocol = 'https' if self.secure else 'http'
            url = '%s://%s%s' % (protocol, self.host, remote_path)
            headers.update(self.get_headers(path, action, **parameters))

            # For testing purposes, mock the responses according to the
            # testing dict
            if self._testing_mode:
                with responses.RequestsMock() as r:
                    log.debug('Added mock response %s %s' % (method, url))
                    r.add(method, url,
                          status=self.testing.get('status', 200),
                          content_type=self.testing.get('content_type', 'text/xml'),
                          body=self.testing.get('body', ''))
                    response = requests.request(method, url, data=data,
                                                headers=headers,
                                                hooks=hooks,
                                                timeout=timeout)
            else:
                response = requests.request(method, url, data=data,
                                            headers=headers,
                                            hooks=hooks,
                                            timeout=timeout)

            success = '[%s] Succeeded to call %s: %s %s'
            success %= (response.status_code, action, url, parameters)
            log.debug(success)
            response.raise_for_status()
        except Exception, e:
            error = '[%s] Failed to call %s: %s %s %s'
            tb = format_exception()
            if response:
                error %= (response.status_code, action,
                          str(e), format_response(response), tb)
            else:
                error %= (100, action, str(e), '<empty response>', tb)
                # The response becomes an exception that has a response attr
                response = e
            log.critical(error)
        return response

    def _send_read_action(self, path, action, **parameters):
        """Sends a read-only API request and parses its response.

        See _send.

        Returns:
            A Tuple (data, response|exception).
            Data is a Data (dictionary with attribute-like access too) object
            with the response text, or the translated response xml content if
            the content type is text/xml.
            Response is either the object as returned by requests,
            or an exception also returned by requests, with a response attribute.

            If self.parameters['stream'] is True, Data will be None because
            the actual response should be processed by this method's caller.
        """
        data = None
        response = self._send('GET', path, action, **parameters)

        if isinstance(response, Exception) or response.status_code != 200:
            return data, response

        try:
            if self.parameters.get('stream') == True:
                data = None
            else:
                data = response.text.strip()
                if data and response.headers['Content-Type'].startswith('text/xml'):
                    xml = et.fromstring(data)
                    data = xml_to_data(xml)
        except (et.ParseError, AttributeError), e:
            log.critical('[101] Failed to get response: ' + e.message)
            reraise_exception(e)
        return data, response

    def _send_write_action(self, path, action, data, **parameters):
        """Sends a write API request and parses its response.

        See _send.

        These responses return the following body:
            <HTML>Request Processed</HTML>

        TODO: Support form uploads.

        Returns:
            A Tuple (data, response|exception) where data is a Data (dictionary with
            attribute-like access too) object with the translated response xml
            content, and response is either the object as returned by requests,
            or an exception also returned by requests, with a response attribute.
        """
        if data:
            self.parameters.setdefault('headers', {})
            self.parameters['headers']['Content-Length'] = len(data)
        response = self._send('POST', path, action, data, **parameters)

        # Response data
        data = None

        if isinstance(response, Exception) or response.status_code != 200:
            return data, response
        
        try:
            body = response.text.strip()
            if data and response.headers['Content-Type'].startswith('text/xml'):
                xml = et.fromstring(data)
                data = xml_to_data(xml)
        except (et.ParseError, AttributeError), e:
            log.critical('[102] Failed to parse response: ' + e.message)
            reraise_exception(e)
        return data, response


    # API calls
    # All paths should be relative to the CPCode directory

    def mock(self, method='GET', path='/mock', action='mock', data=None, **parameters):
        """Mock API call, using the responses package.

        This method doesn't make any HTTP connections.

        Args:
            method: The mock HTTP method in uppercase.
            path: The mock remote path, without CPCode.
            action: The mock API action name.
            **parameters: Additional parameters to the given mock action, e.g.
                'mtime=1260000000' for the 'mtime' action.

        Returns:
            A tuple consisting of:
            1. The relevant data as a dict, currently just None.
            2. The mock response as returned by requests.
        """
        if method == 'POST':
            return self._send_write_action(path, action, data=data, **parameters)
        return self._send_read_action(path, action, **parameters)

    def du(self, path):
        """Disk Usage.

        Gets the number of files and total bytes inside the provided path.

        Example response:
            <du directory="/dir1/dir2">
                <du-info files="12399999" bytes="383838383838"/>
            </du>

        Example parsed data returned:
            {'du': {'directory': '/dir1/dir2/',
                    'du-info': {'files': '12399999',
                                'bytes': '383838383838'}}}

        Args:
            path: The remote path, without CPCode.

        Returns:
            A tuple consisting of:
            1. The relevant data (parsed xml) as a dict.
            2. The response as returned by requests.

        Raises:
            NetStorageKitError: A wrapper of any XML parsing error.
        """
        return self._send_read_action(path, 'du')

    def dir(self, path):
        """Directory structure.

        Gets the directory structure of the provided path.

        Example response:
            <stat directory="/dir/foo">
                <file type="file" name="a.jpg" mtime="1395977462"
                      size="123" md5="d41d8cd98f00b204e9800998ecf8427e"/>
                <file type="file" name="b.png" mtime="1395977461"
                      size="123" md5="d41d8cd98f00b204e9800998ecf8427e"/>
                <file type="dir" name="test2" mtime="1395977462"/>
            </stat>

        Example parsed data returned:
            {'stat': {'directory': '/12345',
                      'file': [{'type': 'dir', 'name': 'dir_a', 'mtime': '1425652079'},
                               {'type': 'dir', 'name': 'dir_b', 'mtime': '1395977462'}]}}

        Args:
            path: The remote path, without CPCode.

        Returns:
            A tuple consisting of:
            1. The relevant data (parsed xml) as a dict.
            2. The response as returned by requests.

        Raises:
            NetStorageKitError: A wrapper of any XML parsing error.
        """
        return self._send_read_action(path, 'dir')

    def download(self, path, destination):
        """File download.

        Downloads the given path into the provided destination.

        Args:
            path: The remote path, without CPCode.
            destination: The local path.

        Returns:
            A tuple consisting of:
            1. None, for there is no success/failure confirmation other than
                the response's status code.
            2. The response as returned by requests.
        """
        self.parameters['stream'] = True
        _, response = self._send_read_action(path, 'download')

        if isinstance(response, Exception):
            return _, response

        try:
            with open(destination, 'wb') as f: # 100KB per write
                for chunk in response.iter_content(chunk_size=100000):
                    f.write(chunk)
                    f.flush()
        except Exception, e:
            log.critical('[103] Failed to write in %s: %s' % (destination, str(e)))
            reraise_exception(e)
        return None, response

    def upload(self, path, source):
        """File upload.

        Uploads the given path from the provided source.
        The sha256 checksum is computed automatically.

        Binary upload support only.

        Args:
            path: The remote path, without CPCode.
            destination: The local path.

        Returns:
            A tuple consisting of:
            1. None, for there is no success/failure confirmation other than
                the response's status code.
            2. The response as returned by requests.
        """
        try:
            data = None
            with open(source, 'r') as f: # 100KB per write
                data = f.read()
            sha256_sum = sha256(data).hexdigest()
            parameters = {
                'sha256': sha256_sum,
                'size': len(data),
                'upload-type': 'binary'}
            _, response = self._send_write_action(path, 'upload', data, **parameters)
        except Exception, e:
            log.critical('[104] Failed to read/upload %s: %s' % (source, str(e)))
            reraise_exception(e)
        return None, response

    def delete(self, path):
        """File or symlink deletion.

        Args:
            path: The remote path, without CPCode.

        Returns:
            A tuple consisting of:
            1. None, for there is no success/failure confirmation other than
                the response's status code.
            2. The response as returned by requests.
        """
        return self._send_write_action(path, 'delete', None)
