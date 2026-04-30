from tornado.escape import json_decode
from tornado.web import authenticated

from .auth import AuthHandler
from api.security.encryption import (
    encrypt_field, decrypt_field,
    validate_text_field, validate_date_field, validate_text_list_field,
    ValidationError, PHONE_PATTERN,
)


def _get_first_present(body, *keys):
    """Return the first key found in body; otherwise None."""
    for key in keys:
        if key in body:
            return body[key]
    return None


class UserHandler(AuthHandler):

    @authenticated
    async def get(self):
        # Fetch the full user record so we can return personal details
        user = await self.db.users.find_one({'email': self.current_user['email']})

        self.set_status(200)
        self.response['email'] = self.current_user['email']
        self.response['displayName'] = self.current_user['display_name']

        # Decrypt and return personal fields using camelCase API names
        field_map = {
            'full_name': 'fullName',
            'address': 'address',
            'date_of_birth': 'dateOfBirth',
            'phone_number': 'phoneNumber',
        }
        for db_field, api_field in field_map.items():
            if user.get(db_field):
                try:
                    self.response[api_field] = decrypt_field(user[db_field])
                except Exception:
                    pass

        if user.get('disabilities'):
            try:
                self.response['disabilities'] = [decrypt_field(item) for item in user['disabilities']]
            except Exception:
                pass

        self.write_json()

    @authenticated
    async def put(self):
        try:
            body = json_decode(self.request.body)
        except Exception:
            self.send_error(400, message='Invalid JSON body!')
            return

        updates = {}
        errors = []

        full_name = _get_first_present(body, 'full_name', 'fullName')
        if full_name is not None:
            try:
                val = validate_text_field(full_name, 'Full name', 200)
                updates['full_name'] = encrypt_field(val)
            except ValidationError as e:
                errors.append(str(e))

        address = _get_first_present(body, 'address')
        if address is not None:
            try:
                val = validate_text_field(address, 'Address', 500)
                updates['address'] = encrypt_field(val)
            except ValidationError as e:
                errors.append(str(e))

        date_of_birth = _get_first_present(body, 'date_of_birth', 'dateOfBirth')
        if date_of_birth is not None:
            try:
                val = validate_date_field(date_of_birth, 'Date of birth')
                updates['date_of_birth'] = encrypt_field(val)
            except ValidationError as e:
                errors.append(str(e))

        phone_number = _get_first_present(body, 'phone_number', 'phoneNumber', 'phoneNubmer')
        if phone_number is not None:
            try:
                val = validate_text_field(
                    phone_number, 'Phone number', 30,
                    PHONE_PATTERN, 'Phone number contains invalid characters',
                )
                updates['phone_number'] = encrypt_field(val)
            except ValidationError as e:
                errors.append(str(e))

        disabilities = _get_first_present(body, 'disabilities')
        if disabilities is not None:
            try:
                vals = validate_text_list_field(disabilities, 'Disabilities', 'disability', 200)
                updates['disabilities'] = [encrypt_field(v) for v in vals]
            except ValidationError as e:
                errors.append(str(e))

        if errors:
            self.send_error(400, message='; '.join(errors))
            return

        if not updates:
            self.send_error(400, message='No valid personal-detail fields provided!')
            return

        await self.db.users.update_one(
            {'email': self.current_user['email']},
            {'$set': updates},
        )

        self.set_status(200)
        self.write_json()
