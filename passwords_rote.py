#!/usr/bin/env python3
import os.path
import click
from passlib.hash import bcrypt

from sqlalchemy import Column, String
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

STORAGE_FOLDER = os.path.join(os.path.expanduser("~"),
                              "local/share/passwords_rote")
STORAGE_FILE = os.path.join(STORAGE_FOLDER, "rote.sqlite")

Base = declarative_base()


class Hash(Base):
    __tablename__ = "hashes"
    name = Column(String, primary_key=True)
    hash_ = Column(String)


class HashDB(object):
    def __init__(self, db_file_name):
        """Args:
        db_file_name: str, file name for the sqlite database
        """
        engine = create_engine(r'sqlite:///%s' % db_file_name, echo=False)
        Base.metadata.create_all(engine)
        self.create_session = sessionmaker(bind=engine)


@click.command()
@click.option('--store')
def main(store):
    if store:
        store_password(store)
    else:
        rote()


def store_password(name):
    """Prompts the user for a password and stores its hash in
    the database.
    Args:
      name - str, name under which store the password"""
    if not os.path.exists(STORAGE_FOLDER):
        os.makedirs(STORAGE_FOLDER)

    hash_db = HashDB(STORAGE_FILE)
    session = hash_db.create_session()
    if session.query(Hash).filter(Hash.name == name).first():
        if not click.confirm("Overwrite %s?" % name):
            return
    password = click.prompt(
        "Please enter the password", hide_input=True, confirmation_prompt=True)
    new_hash = Hash(name=name, hash_=bcrypt.encrypt(
        password, rounds=14, salt_size=22))
    session.merge(new_hash)
    session.commit()


def rote():
    """Prompts the user for all the stored passwords, checks them using hash,
    repeatedly asks in case of a mistake."""
    hash_db = HashDB(STORAGE_FILE)
    session = hash_db.create_session()
    stored_hashes = session.query(Hash)
    for hash_ in stored_hashes:
        correct = False
        while not correct:
            user_input = click.prompt("Please enter the password for %s" %
                                      hash_.name, hide_input=True)
            correct = bcrypt.verify(user_input, hash_.hash_)


if __name__ == '__main__':
    main()
