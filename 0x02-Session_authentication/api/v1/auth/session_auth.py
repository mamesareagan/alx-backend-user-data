#!/usr/bin/env python3
"""Session authentication module.
"""
from typing import TypeVar
from api.v1.auth.auth import Auth
from flask import request
from flask_cors import (CORS, cross_origin)
import os
import uuid

from models.user import User


class SessionAuth(Auth):
    """ SessionAuth class to manage API authentication."""
    user_id_by_session_id = {}

    def create_session(self, user_id: str = None) -> str:
        """ Creates a Session ID for a user_id."""
        if user_id is None or type(user_id) != str:
            return None
        session_id = str(uuid.uuid4())
        self.user_id_by_session_id[session_id] = user_id
        return session_id

    def user_id_for_session_id(self, session_id: str = None) -> str:
        """ Returns a User ID based on a Session ID."""
        if session_id is None or type(session_id) != str:
            return None
        return self.user_id_by_session_id.get(session_id)

    def current_user(self, request=None) -> TypeVar('User'):
        """ Returns a User instance based on a cookie value."""
        if request is None:
            return None
        session_cookie = self.session_cookie(request)
        if session_cookie:
            user_id = self.user_id_for_session_id(session_cookie)
            if user_id:
                return User.get(user_id)
        return None
