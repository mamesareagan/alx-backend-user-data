#!/usr/bin/env python3
""" Module of Index views
"""

from typing import List, TypeVar
from models.user import User
from .auth import Auth
import re
import base64
import binascii


class BasicAuth(Auth):
    """ baisc auth class
    """

    def extract_base64_authorization_header(self,
                                            authorization_header: str) -> str:
        """ returns the Base64 part of the Authorization header
        """
        if type(authorization_header) == str:
            pattern = r'Basic (?P<token>.+)'
            match = re.fullmatch(pattern, authorization_header.strip())
            if match:
                return match.group('token')
        return None

    def decode_base64_authorization_header(self,
                                           base64_authorization_header: str
                                           ) -> str:
        """ returns the decoded value of a Base64 string
        """
        if type(base64_authorization_header) == str:
            try:
                res = base64.b64decode(
                    base64_authorization_header, validate=True)
                return res.decode('utf-8')
            except (binascii.Error, UnicodeDecodeError):
                return None

    def extract_user_credentials(self,
                                 decoded_base64_authorization_header: str
                                 ) -> tuple[str, str]:
        """ returns the user email and password from the Base64 decoded value
        """
        if type(decoded_base64_authorization_header) == str:
            pattern = r'(?P<email>.+?):(?P<password>.+)'
            match = re.fullmatch(
                pattern, decoded_base64_authorization_header.strip())
            if match:
                return (match.group('email'), match.group('password'))
        return (None, None)

    def user_object_from_credentials(self,
                                     user_email: str, user_pwd: str
                                     ) -> TypeVar('User'):
        """ returns the User instance based on his email and password
        """
        if type(user_email) == str and type(user_pwd) == str:
            try:
                users = User.search({'email': user_email})
            except Exception:
                return None
            if len(users) <= 0:
                return None
            if users[0].is_valid_password(user_pwd):
                return users[0]
        return None

    def current_user(self, request=None) -> TypeVar('User'):
        """ overloads Auth and retrieves the User instance for a request
        """
        Auth_header = self.authorization_header(request)
        b64_Auth_header = self.extract_base64_authorization_header(Auth_header)
        decoded_b64_Auth_header = self.decode_base64_authorization_header(
            b64_Auth_header)
        user_credentials = self.extract_user_credentials(
            decoded_b64_Auth_header)
        user = self.user_object_from_credentials(
            user_credentials[0], user_credentials[1])
        return user
