from tornado.web import authenticated

from .auth import AuthHandler

class LogoutHandler(AuthHandler):

    @authenticated
    async def post(self):
        await self.db.users.update_one({
            'email': self.current_user['email'],
        }, {
            '$set': {
                'token': None
            }
        })

        self.current_user = None

        self.set_status(200)
        self.write_json()
