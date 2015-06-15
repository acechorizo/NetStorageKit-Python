# -*- coding: utf-8 -*-
import hmac
import hashlib
from time import time
from random import getrandbits


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
        str(timestamp or time()),
        # Guarantee uniqueness for headers generated at the same time
        str(unique_id or getrandbits(64)),
        key_name]
    return str(', '.join(values))


def get_sign(key, path, data, action):
    """Gets the X-Akamai-ACS-Auth-Sign header value.

    Args:
        key: The NS Upload Account key as configured in Luna.
        path: The remote path, without cpcode.
        data: The data header value.
        action: The action header value.

    Returns:
        The base 64 encoded header value.
    """
    values = [
        data,
        path + '\n',
        'x-akamai-acs-action:' + action + '\n']
    msg = str(''.join(values))
    digest = hmac.new(str(key), msg=msg, digestmod=hashlib.sha256).digest()
    return digest.encode('base64').strip()
