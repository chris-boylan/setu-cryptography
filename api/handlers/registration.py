import base64
import hashlib
import os

from tornado.escape import json_decode
from .base import BaseHandler

# Helper function to hash passwords using PBKDF2 with SHA-256, 600,000 iterations and a random salt
def hash_password(password: str) -> str:
    iterations = 600000
    salt = os.urandom(16)
    derived_key = hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), salt, iterations, dklen=32)

    salt_b64 = base64.b64encode(salt).decode('ascii')
    hash_b64 = base64.b64encode(derived_key).decode('ascii')
    return f'pbkdf2_sha256${iterations}${salt_b64}${hash_b64}'

class RegistrationHandler(BaseHandler):
    async def post(self):
        try:
            body = json_decode(self.request.body)
            email = body['email'].lower().strip()
            password = body['password']
            display_name = body.get('displayName')
            if display_name is None:
                display_name = email
            if not isinstance(display_name, str):
                raise Exception('Display name must be a string')

        except Exception:
            self.send_error(400, message='You must provide an email address, password and display name!')
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

        if not display_name:
            self.send_error(400, message='The display name is invalid!')
            return

        user = await self.db.users.find_one({
          'email': email
        })

        if user is not None:
            self.send_error(409, message='A user with the given email address already exists!')
            return

        password_hash = hash_password(password)

        await self.db.users.insert_one({
            'email': email,
            'password': password_hash,
            'displayName': display_name
        })

        self.set_status(200)
        self.response['email'] = email
        self.response['displayName'] = display_name

        self.write_json()
