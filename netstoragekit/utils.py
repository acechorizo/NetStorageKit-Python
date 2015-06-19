# -*- coding: utf-8 -*-
from sys import exc_info
import traceback
from urllib import quote_plus
from collections import defaultdict
from .exceptions import NetStorageKitError


def reraise_exception(exception):
    """Reraises the given exception wrapped in our NetStorageKitError.
    The original exception information is preserved.
    """
    type_, value, traceback = exc_info()
    raise NetStorageKitError, '%s(%s)' % (type_.__name__, value), traceback


def format_exception():
    """Formats the last exception."""
    return traceback.format_exc()


def escape(value):
    """Escapes the value to use it as a query string parameter."""
    if value is None:
        return ''
    string = str(value.encode('utf-8') if type(value) is unicode else value)
    return quote_plus(string)


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


class Data(dict):
    """Hackish Dict with attribute-like access for the lazy.
    This should probably be improved later.
    """
    __getattr__ = dict.__getitem__
    __setattr__ = dict.__setitem__
    __delattr__ = dict.__delitem__


def xml_to_data(xml_etree):
    """Transforms an xml ETree into a dict.
    Slightly modified version of http://stackoverflow.com/a/10076823/642087
    """
    d = Data({xml_etree.tag: Data({}) if xml_etree.attrib else None})
    children = list(xml_etree)
    if children:
        dd = defaultdict(list)
        for dc in map(xml_to_data, children):
            for k, v in dc.iteritems():
                dd[k].append(v)
        dd = Data(dd)
        d = Data({xml_etree.tag: Data({k: v[0] if len(v) == 1
                                       else v for k, v in dd.iteritems()})})
    if xml_etree.attrib:
        d[xml_etree.tag].update(Data((k, v) for k, v in xml_etree.attrib.iteritems()))
    if xml_etree.text:
        text = xml_etree.text.strip()
        if children or xml_etree.attrib:
            if text:
              d[xml_etree.tag]['text'] = text
        else:
            d[xml_etree.tag] = text
    return d
