"""
This is a basic authenticator which allows you to predefine a list
of users and hashed passwords for JupyterHub. 

To generate a password hash:

  python -m minimal_authenticator

or

  python minimal_authenticator.py

"""

import binascii
import hashlib
import getpass
import os

import toml

from tornado import gen
from jupyterhub.auth import Authenticator

def hash_password(password):
    """Hash a password for storing."""
    salt = hashlib.sha256(os.urandom(60)).hexdigest().encode('ascii')
    pwdhash = hashlib.pbkdf2_hmac('sha512', password.encode('utf-8'), 
                                salt, 100000)
    pwdhash = binascii.hexlify(pwdhash)
    return (salt + pwdhash).decode('ascii')


def verify_password(stored_password, provided_password):
    """Verify a stored password against one provided by user"""
    salt = stored_password[:64]
    stored_password = stored_password[64:]
    pwdhash = hashlib.pbkdf2_hmac('sha512', 
                                  provided_password.encode('utf-8'), 
                                  salt.encode('ascii'), 
                                  100000)
    pwdhash = binascii.hexlify(pwdhash).decode('ascii')
    return pwdhash == stored_password


class MinimalAuthenticator(Authenticator):

    @gen.coroutine
    def authenticate(self, handler, data):

        with open('/srv/jupyterhub/logins.toml') as f:
          logins = toml.loads(f.read())

        if verify_password(logins.get(data['username']),data['password']):
            return data['username']

if __name__ == '__main__':
   pword = getpass.getpass('Password:')
   print(hash_password(pword))