import json

from tornado.escape import json_decode
from tornado.httputil import HTTPHeaders
from tornado.ioloop import IOLoop
from tornado.web import Application

from api.handlers.user import UserHandler
from api.handlers.login import hash_token

from .base import BaseTest


class UserHandlerTest(BaseTest):

    @classmethod
    def setUpClass(self):
        self.my_app = Application([(r'/user', UserHandler)])
        super().setUpClass()

    async def register(self):
        await self.get_app().db.users.insert_one({
            'email': self.email,
            'password': self.password,
            'displayName': self.display_name,
        })

    async def login(self):
        await self.get_app().db.users.update_one({
            'email': self.email,
        }, {
            '$set': {'tokenHash': hash_token(self.token), 'expiresIn': 2147483647},
        })

    def setUp(self):
        super().setUp()

        self.email = 'test@test.com'
        self.password = 'testPassword'
        self.display_name = 'testDisplayName'
        self.token = 'testToken'

        IOLoop.current().run_sync(self.register)
        IOLoop.current().run_sync(self.login)

    # ------------------------------------------------------------------ GET --

    def test_user(self):
        headers = HTTPHeaders({'X-Token': self.token})

        response = self.fetch('/user', headers=headers)
        self.assertEqual(200, response.code)

        body = json_decode(response.body)
        self.assertEqual(self.email, body['email'])
        self.assertEqual(self.display_name, body['displayName'])

    def test_user_without_token(self):
        response = self.fetch('/user')
        self.assertEqual(400, response.code)

    def test_user_wrong_token(self):
        headers = HTTPHeaders({'X-Token': 'wrongToken'})

        response = self.fetch('/user', headers=headers)
        self.assertEqual(403, response.code)

    # ------------------------------------------------------------------ PUT --

    def test_put_personal_details(self):
        """PUT with all valid personal fields should return 200."""
        headers = HTTPHeaders({'X-Token': self.token})
        payload = {
            'full_name': 'Alice Smith',
            'address': '1 Main St, Dublin',
            'date_of_birth': '2000-01-15',
            'phone_number': '+353 1 234 5678',
            'disabilities': ['Dyslexia', 'ADHD'],
        }

        response = self.fetch(
            '/user',
            method='PUT',
            headers=headers,
            body=json.dumps(payload),
        )
        self.assertEqual(200, response.code)

    def test_put_personal_details_then_get_returns_decrypted(self):
        """After a PUT the GET should return decrypted personal details."""
        headers = HTTPHeaders({'X-Token': self.token})
        payload = {
            'full_name': 'Alice Smith',
            'address': '1 Main St, Dublin',
            'date_of_birth': '2000-01-15',
            'phone_number': '+353 1 234 5678',
            'disabilities': ['Dyslexia'],
        }

        put_resp = self.fetch(
            '/user',
            method='PUT',
            headers=headers,
            body=json.dumps(payload),
        )
        self.assertEqual(200, put_resp.code)

        get_resp = self.fetch('/user', headers=headers)
        self.assertEqual(200, get_resp.code)

        body = json_decode(get_resp.body)
        self.assertEqual('Alice Smith', body['fullName'])
        self.assertEqual('1 Main St, Dublin', body['address'])
        self.assertEqual('2000-01-15', body['dateOfBirth'])
        self.assertEqual('+353 1 234 5678', body['phoneNumber'])
        self.assertEqual(['Dyslexia'], body['disabilities'])

    def test_put_invalid_date_of_birth(self):
        """PUT with a badly formatted date should return 400."""
        headers = HTTPHeaders({'X-Token': self.token})
        payload = {'date_of_birth': 'not-a-date'}

        response = self.fetch(
            '/user',
            method='PUT',
            headers=headers,
            body=json.dumps(payload),
        )
        self.assertEqual(400, response.code)

    def test_put_no_fields(self):
        """PUT with an empty body should return 400."""
        headers = HTTPHeaders({'X-Token': self.token})

        response = self.fetch(
            '/user',
            method='PUT',
            headers=headers,
            body=json.dumps({}),
        )
        self.assertEqual(400, response.code)

    def test_put_without_token(self):
        """PUT without a token should return 400."""
        payload = {'full_name': 'Alice Smith'}

        response = self.fetch(
            '/user',
            method='PUT',
            body=json.dumps(payload),
        )
        self.assertEqual(400, response.code)
