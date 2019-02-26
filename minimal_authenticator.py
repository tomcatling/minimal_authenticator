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

from tornado import gen
from jupyterhub.auth import Authenticator

LOGINS = {
    'admin': 'a19a489885c1b94cde75644e24937b84db532e7a2d6e74a91b55021c8974d3ccc72d144fd04e01ca18223c29909b0e378362a094354a6099c6fe1313431c1334191f14b7eb09b484a5663327fa8ac5c0130fb83ffb22f3023c38465d7c9bdc21',
    'user' : '51b12c34b72d36f5f894076f644b56f6666f8854faebabd2394731544876200e247931ba9da23c51753ca9d28456a878fee2143eccc84fae5588fbeb324561d1ecf6d5412ca27f459346157c7159a710de4b5d18569266315e90a3b1b5d707b6'
}

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
        if verify_password(LOGINS.get(data['username']),data['password']):
            return data['username']

if __name__ == '__main__':
   pword = getpass.getpass('Password:')
   print(hash_password(pword))