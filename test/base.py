from concurrent.futures import ThreadPoolExecutor
from mongomock_motor import AsyncMongoMockClient
from tornado.ioloop import IOLoop
from tornado.testing import AsyncHTTPTestCase

from .conf import MONGODB_DBNAME, WORKERS

class BaseTest(AsyncHTTPTestCase):

    @classmethod
    def setUpClass(self):
        self.my_app.db = AsyncMongoMockClient()[MONGODB_DBNAME]

        self.my_app.executor = ThreadPoolExecutor(WORKERS)

    def get_app(self):
        return self.my_app

    def setUp(self):
        super().setUp()
        IOLoop.current().run_sync(self.get_app().db.users.drop)

    def tearDown(self):
        super().tearDown()
        IOLoop.current().run_sync(self.get_app().db.users.drop)
