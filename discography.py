from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from database_setup import Album, Base, songItem, User

engine = create_engine('sqlite:///coldplaydiscography.db')
# Bind the engine to the metadata of the Base class so that the
# declaratives can be accessed through a DBSession instance
Base.metadata.bind = engine

DBSession = sessionmaker(bind=engine)
# A DBSession() instance establishes all conversations with the database
# and represents a "staging zone" for all the objects loaded into the
# database session object. Any change made against the objects in the
# session won't be persisted into the database until you call
# session.commit(). If you're not happy about the changes, you can
# revert all of them back to the last commit by calling
# session.rollback()
session = DBSession()

# create users
User1 = User(name="Widya", email="widyapuspitaloka@gmail.com")
session.add(User1)
session.commit()


User2 = User(name="Robo Barista", email="tinnyTim@udacity.com",
             picture='https://pbs.twimg.com/profile_images/2671170543/18debd694829ed78203a5a36dd364160_400x400.png')
session.add(User2)
session.commit()


#Songs for Parachutes album
album1 = Album(name = "Parachutes")

session.add(album1)
session.commit()


songItem1 = songItem(name = "Don't Panic", year = "2001", length = "2:17", genre = "alternative rock, soft rock", album = album1, album_id = 1)

session.add(songItem1)
session.commit()

songItem2 = songItem(name = "Shiver", year = "2000", length = "5:00", genre = "alternative rock, post-Britpop", album = album1, album_id = 1)

session.add(songItem2)
session.commit()

songItem3 = songItem(name = "Yellow", year = "2000", length = "4:29", genre = "alternative rock", album = album1, album_id = 1)

session.add(songItem3)
session.commit()

songItem4 = songItem(name = "Trouble", year = "2000", length = "4:31", genre = "piano rock", album = album1, album_id = 1)

session.add(songItem4)
session.commit()


#Songs for A Rush of Blood to the Head
album2 = Album(name = "A Rush of Blood to the Head")

session.add(album2)
session.commit()


songItem1 = songItem(name = "In My Place", year = "2002", length = "3:48", genre = "alternative rock, soft rock", album = album2, album_id = 2)

session.add(songItem1)
session.commit()

songItem2 = songItem(name = "God Put a Smile upon Your Face", year = "2003", length = "4:58", genre = "alternative rock, folk rock", album = album2, album_id = 2)

session.add(songItem2)
session.commit()

songItem3 = songItem(name = "The Scientis", year = "2002", length = "5:09", genre = "alternative rock, soft rock, piano rock", album = album2, album_id = 2)

session.add(songItem3)
session.commit()

songItem4 = songItem(name = "Clocks", year = "2002", length = "5:07", genre = "alternative rock, soft rock", album = album2, album_id = 2)

session.add(songItem4)
session.commit()


#Songs for X & Y album
album3 = Album(name = "X & Y")

session.add(album3)
session.commit()


songItem1 = songItem(name = "White Shadows", year = "2007", length = "5:28", genre = "alternative rock", album = album3, album_id = 3)

session.add(songItem1)
session.commit()

songItem2 = songItem(name = "Fix You", year = "2005", length = "4:54", genre = "alternative rock, post-Brtipop", album = album3, album_id = 3)

session.add(songItem2)
session.commit()

songItem3 = songItem(name = "Speed Sound", year = "2005", length = "4:49", genre = "alternative rock, post-Brtipop", album = album3, album_id = 3)

session.add(songItem3)
session.commit()

songItem4 = songItem(name = "The Hardest Part", year = "2006", length = "4:25", genre = "alternative rock", album = album3, album_id = 3)

session.add(songItem4)
session.commit()


#Songs for Viva la Vida Album
album4 = Albbum(name = "Viva la Vida or Death and All His Friends")

session.add(album4)
session.commit()


songItem1 = songItem(name = "Cemeteries of London", year = "2007-2008", length = "3:21", genre = "alternative rock", album = album4, album_id = 4)

session.add(songItem1)
session.commit()

songItem2 = songItem(name = "Viva la Vida", year = "2008", length = "4:01", genre = "Baroque Pop", album = album4, album_id = 4)

session.add(songItem2)
session.commit()

songItem3 = songItem(name = "Violet Hill", year = "2008", length = "3:49", genre = "alternative rock", album = album4, album_id = 4)

session.add(songItem3)
session.commit()

songItem4 = songItem(name = "Strawberry Swing", year = "2009", length = "4:11", genre="alternative rock, folk pop", album = album4, album_id = 4)

session.add(songItem4)
session.commit()


#Songs for Mylo Xyloto Album
album5 = Album(name = "Mylo Xyloto")

session.add(album5)
session.commit()


songItem1 = songItem(name = "Paradise", year = "2011", length = "4:39", genre = "pop rock, R&B", album = album5, album_id = 5)

session.add(songItem1)
session.commit()

songItem2 = songItem(name = "Charlie Brown", year = "2012", length = "4:45", genre = "alternative rock, pop rock, power pop", album = album5, album_id = 5)

session.add(songItem2)
session.commit()

songItem3 = songItem(name = "Every Teardrop is a Waterfall", year = "2011", length = "4:03", genre = "alternative rock, pop rock, electronic rock", album = album5, album_id = 5)

session.add(songItem3)
session.commit()

songItem4 = songItem(name = "Major Minus", year = "2011", length = "3:30", genre = "alternative rock", album = album5, album_id = 5)

session.add(songItem4)
session.commit()

print "added song items!"

