# -*- coding: utf-8 -*-
import hmac
import hashlib
from time import time
from random import getrandbits


# Akamai Version 5 Authentication:
# HMAC-SHA256([key], [data] + [sign-string])

def get_data(key_name, timestamp=None, unique_id=None):
    values = [
        '5', # Authentication version
        '0.0.0.0', # hardcoded, reserved
        '0.0.0.0', # hardcoded, reserved
        str(timestamp or time()),
        str(unique_id or getrandbits(64)),
        key_name]
    return ', '.join(values)


def get_sign(key, path, data, action):
    values = [
        data,
        path + '\n',
        'x-akamai-acs-action:' + action + '\n']
    msg = ''.join(values)
    digest = hmac.new(key, msg=msg, digestmod=hashlib.sha256).digest()
    return digest.encode('base64').strip()
