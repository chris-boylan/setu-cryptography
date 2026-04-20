import base64
from datetime import datetime, timedelta, timezone
import hashlib
import hmac
from tornado.escape import json_decode
from uuid import uuid4
from .base import BaseHandler


def verify_password(password: str, stored_password: str) -> bool:
    if not isinstance(stored_password, str):
        return False

    parts = stored_password.split('$')
    if len(parts) == 4 and parts[0] == 'pbkdf2_sha256':
        try:
            iterations = int(parts[1])
            salt = base64.b64decode(parts[2])
            expected_hash = base64.b64decode(parts[3])
            derived_hash = hashlib.pbkdf2_hmac(
                'sha256', password.encode('utf-8'), salt, iterations, dklen=len(expected_hash)
            )
            return hmac.compare_digest(derived_hash, expected_hash)
        except Exception:
            return False

    # Keep legacy plaintext comparison for existing fixtures/data.
    return hmac.compare_digest(stored_password, password)

class LoginHandler(BaseHandler):
    async def generate_token(self, email):
        token_uuid = uuid4().hex
        expires_in = (datetime.now(timezone.utc) + timedelta(hours=2)).timestamp()

        token = {
            'token': token_uuid,
            'expiresIn': expires_in,
        }

        await self.db.users.update_one({
            'email': email
        }, {
            '$set': token
        })

        return token

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
