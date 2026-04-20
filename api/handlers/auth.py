from datetime import datetime, timezone
from .base import BaseHandler

class AuthHandler(BaseHandler):
    async def prepare(self):
        super(AuthHandler, self).prepare()

        if self.request.method == 'OPTIONS':
            return

        try:
            token = self.request.headers.get('X-Token')
            if not token:
              raise Exception()
        except Exception:
            self.current_user = None
            self.send_error(400, message='You must provide a token!')
            return

        user = await self.db.users.find_one({
            'token': token
        }, {
            'email': 1,
            'displayName': 1,
            'expiresIn': 1
        })

        if user is None:
            self.current_user = None
            self.send_error(403, message='Your token is invalid!')
            return

        current_time = datetime.now(timezone.utc).timestamp()
        if current_time > user['expiresIn']:
            self.current_user = None
            self.send_error(403, message='Your token has expired!')
            return

        self.current_user = {
            'email': user['email'],
            'display_name': user['displayName']
        }
