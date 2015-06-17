# -*- coding: utf-8 -*-
import hmac
import hashlib
import logging
from time import time
from random import getrandbits
from .utils import get_remote_path


log = logging.getLogger(__name__)


# Akamai Version 5 Authentication:
# HMAC-SHA256([key], [data] + [sign-string])

def get_data(key_name, timestamp=None, unique_id=None):
    """Gets the X-Akamai-ACS-Auth-Data header value.

    Args:
        key_name: The NS Upload Account key_name as configured in Luna.
        timestamp: Optional timestamp (mainly for testing purposes).
        unique_id: Optional unique identifier (mainly for testing purposes).

    Returns:
        The header value.
    """
    values = [
        # Authentication encryption format
        '5',
        # Hardcoded, reserved
        '0.0.0.0',
        '0.0.0.0',
        # Current epoch time
        str(timestamp or int(time())),
        # Guarantee uniqueness for headers generated at the same time
        str(unique_id or getrandbits(64)),
        key_name]
    data = str(', '.join(values))
    log.debug(data)
    return data


def get_sign_string(cpcode, path, data, action):
    """Gets the X-Akamai-ACS-Auth-Sign sign string.

    Args:
        cpcode: The CPCode.
        path: The remote path, without cpcode.
        data: The data header value.
        action: The action header value.

    Returns:
        The sign string.
    """
    values = [
        data,
        get_remote_path(cpcode, path) + '\n',
        'x-akamai-acs-action:' + action + '\n']
    sign_string = str(''.join(values))
    log.debug(sign_string.replace('\n', '\\n'))
    return sign_string


def get_sign(key, cpcode, path, data, action):
    """Gets the X-Akamai-ACS-Auth-Sign header value.

    Args:
        key: The NS Upload Account key as configured in Luna.
        cpcode: The CPCode.
        path: The remote path, without cpcode.
        data: The data header value.
        action: The action header value.

    Returns:
        The base 64 encoded header value.
    """
    msg = get_sign_string(cpcode, path, data, action)
    digest = hmac.new(str(key), msg=msg, digestmod=hashlib.sha256).digest()
    sign = digest.encode('base64').strip()
    log.debug(sign)
    return sign
