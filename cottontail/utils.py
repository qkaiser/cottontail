#!/usr/bin/env python
"""
A set of utility functions to mess with RabbitMQ.

Author: Quentin Kaiser <kaiserquentin@gmail.com>
"""
import base64
import hashlib

def crack(hashed, candidate, method="rabbit_password_hashing_md5"):
    """
    You can dump password hashes if you have administrator privileges. This
    is a simple attempt at writing a cracking function :)

    Documentation on rabbitmq hashes https://www.rabbitmq.com/passwords.html

    Args:
        hashed (str): password hash
        candidate (str): plaintext to compare hash to
        method (str): rabbitmq hashing method

    Returns:
        boolean. True if valid candidate, False otherwise.
    """
    decoded = base64.b64decode(hashed).encode('hex')
    hex_salt = decoded[0:8]
    hex_hash = decoded[8:]
    if method == "rabbit_password_hashing_md5":
        hex_hash_candidate = hashlib.md5(
            hex_salt.decode('hex') + candidate
        ).hexdigest()
    elif method == "rabbit_password_hashing_sha256":
        hex_hash_candidate = hashlib.sha256(
            hex_salt.decode('hex') + candidate
        ).hexdigest()
    elif method == "rabbit_password_hashing_sha512":
        hex_hash_candidate = hashlib.sha512(
            hex_salt.decode('hex') + candidate
        ).hexdigest()
    else:
        raise Exception("Hashing method '{}' not supported".format(method))
    return hex_hash == hex_hash_candidate

