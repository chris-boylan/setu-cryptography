import asyncio
import click
from json import loads
from motor.motor_tornado import MotorClient

from api.conf import MONGODB_HOST, MONGODB_DBNAME

async def get_users(db):
  cur = db.users.find({}, {
    'email': 1,
    'password': 1,
    'displayName': 1,
    'token': 1,
    'expiresIn': 1,
  })
  docs = await cur.to_list(length=None)
  print('There are ' + str(len(docs)) + ' registered users:')
  for doc in docs:
    click.echo(doc)

@click.group()
def cli():
    pass

@cli.command()
def list():
    db = MotorClient(**MONGODB_HOST)[MONGODB_DBNAME]
    asyncio.run(get_users(db))

if __name__ == '__main__':
    cli()
