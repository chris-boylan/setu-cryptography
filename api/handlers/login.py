import base64
from datetime import datetime, timedelta, timezone
import hashlib
from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerifyMismatchError
from tornado.escape import json_decode
from uuid import uuid4
from .base import BaseHandler

# Initialize Argon2 hasher (same config as registration)
_ph = PasswordHasher(memory_cost=65536, time_cost=3, parallelism=4)


def verify_password(password: str, stored_password: str) -> bool:
    """Verify password against Argon2 hash using constant-time comparison."""
    if not isinstance(stored_password, str):
        return False

    try:
        _ph.verify(stored_password, password)
        return True
    except (VerifyMismatchError, InvalidHashError):
        return False


def hash_token(token: str) -> str:
    return hashlib.sha256(token.encode('utf-8')).hexdigest()

class LoginHandler(BaseHandler):
    async def generate_token(self, email):
        token_uuid = uuid4().hex
        token_hash = hash_token(token_uuid)
        expires_in = (datetime.now(timezone.utc) + timedelta(hours=2)).timestamp()

        await self.db.users.update_one({
            'email': email
        }, {
            '$set': {
                'tokenHash': token_hash,
                'expiresIn': expires_in,
            }
        })

        return {
            'token': token_uuid,
            'expiresIn': expires_in,
        }


    async def post(self):
        try:
            body = json_decode(self.request.body)
            email = body['email'].lower().strip()
            password = body['password']
        except Exception:
            self.send_error(400, message='You must provide an email address and password!')
            return

        if not email:
            self.send_error(400, message='The email address is invalid!')
            return

        if not password:
            self.send_error(400, message='The password is invalid!')
            return

        if not isinstance(password, str):
            self.send_error(400, message='The password is invalid!')
            return

        user = await self.db.users.find_one({
          'email': email
        }, {
          'password': 1
        })

        if user is None:
            self.send_error(403, message='The email address and password are invalid!')
            return

        if not verify_password(password, user.get('password')):
            self.send_error(403, message='The email address and password are invalid!')
            return

        token = await self.generate_token(email)

        self.set_status(200)
        self.response['token'] = token['token']
        self.response['expiresIn'] = token['expiresIn']

        self.write_json()
