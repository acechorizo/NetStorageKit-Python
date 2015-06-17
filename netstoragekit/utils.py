# -*- coding: utf-8 -*-
from sys import exc_info
from .exceptions import NetStorageKitError


def reraise_exception(exception):
    """Reraises the given exception wrapped in our NetStorageKitError.
    The original exception information is preserved.
    """
    type_, value, traceback = exc_info()
    raise NetStorageKitError, '%s(%s)' % (type_.__name__, value), traceback


def get_remote_path(cpcode, path):
    """Returns the remote absolute path starting with the cpcode.
    Args:
        cpcode: The CPCode.
        path: The remote path without the CPCode.

    Returns:
        The full remote path without trailing slash, e.g. /<cpcode>/<path>.
    """
    components = [cpcode, path]
    remote_path = '/' + '/'.join([str(c).strip('/') for c in components])
    # No trailing slash
    return remote_path.rstrip('/')


def format_headers(headers, prefix=''):
    """Formats the given headers dict prefixing each with an optional prefix.
    For testing and debugging purposes.
    """
    return '\n'.join(['%s%s: %s' % (prefix, k, v)
                      for k, v in headers.items()])


def format_response(response):
    """Formats the given response similar to a `curl -v` call.
    For testing and debugging purposes.
    """
    raw_response = 'Request:\n%s %s\n%s\nResponse:\n%s\nBody:\n%s' % (
        response.request.method,
        response.url,
        format_headers(response.request.headers, '> '),
        format_headers(response.headers, '< '),
        response.text)
    return raw_response
