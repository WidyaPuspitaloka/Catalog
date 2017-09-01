import os
import sys
from sqlalchemy import Column, ForeignKey, Integer, String
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import relationship
from sqlalchemy import create_engine

Base = declarative_base()

class User(Base):
    __tablename__ = 'user'

    id = Column(Integer, primary_key=True)
    name = Column(String(250), nullable=False)
    email = Column(String(250), nullable=False)
    picture = Column(String(250))

class Album(Base):
    __tablename__ = 'album'

    id = Column(Integer, primary_key=True)
    name = Column(String(250), nullable=False)
    user_id = Column(Integer, ForeignKey('user.id'))
    user = relationship(User)

    @property
    def serialize(self):
        """Return object data in easily serializeable format"""
        return {
            'name': self.name,
            'id': self.user_id,
        }

class SongItem(Base):
    __tablename__ = 'song_item'

    name =Column(String(80), nullable = False)
    id = Column(Integer, primary_key = True)
    year = Column(String(8))
    length = Column(String(8))
    genre = Column(String(250))
    album_id = Column(Integer,ForeignKey('album.id'))
    album = relationship(Album)
    user_id = Column(Integer, ForeignKey('user.id'))
    user = relationship(User)

# We added this serialize function to be able to send JSON objects in a
# serializable format
    @property
    def serialize(self):

        return {
            'name': self.name,
            'year': self.year,
            'id': self.id,
            'length': self.length,
            'genre': self.genre,
        }

engine = create_engine('sqlite:///coldplaydiscographywithuser.db')
Base.metadata.create_all(engine)