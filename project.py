from flask import Flask, render_template, request, redirect, jsonify, url_for, flash
from sqlalchemy import create_engine, asc
from sqlalchemy.orm import sessionmaker
from database_setup import Album, Base, songItem, User

# Import Login session
from flask import session as login_session
import random
import string

# imports for gconnect
from oauth2client.client import flow_from_clientsecrets
from oauth2client.client import FlowExchangeError
import httplib2
import json
from flask import make_response
import requests

# import login decorator
from functools import wraps

app = Flask(__name__)

CLIENT_ID = json.loads(open('client_secrets.json', 'r').read())['web']['client_id']
APPLICATION_NAME = "Coldplay Discography Application"

# Connect to Database and create database session
engine = create_engine('sqlite:///coldplaydiscography.db')
Base.metadata.bind = engine

DBsession = sessionmaker(bind = engine)
session = DBsession()

# create a state token to request forgery.
# store it in the session for later validation

def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_name' not in login_session:
            return redirect('/login')
        return f(*args, **kwargs)
    return decorated_function

@app.route('/login')
def showlogin():
    state = ''.join(random.choice(string.ascii_uppercase + string.digits)
                   for x in xrange(32))
    login_session['state'] = state
    return render_template('login.html', STATE = state)

@app.route('/gconnect', methods = ['POST'])
def gconnect():
    # validate state token
    if request.args.get('state')!= login_session['state']:
        response = make_response(json.dumps('Invalid state parameter.'), 401)
        response.headers['Content-Type']= 'application-json'
        return response
    # Obtain authorization code
    code = request.data

    try:
        # upgrade the authorization code in credentials object
        oauth_flow = flow_from_clientsecrets('client_secrets.json', scope='')
        oauth_flow.redirect_uri = 'postmessage'
        credentials = oauth_flow.step2_exchange(code)
    except FlowExchangeError:
        response = make_response(json.dumps('Failed to upgrade the authorization code'), 401)
        response.headers['Content-Type']= 'application-json'
        return response

    # Check that the access token is valid.
    access_token = credentials.access_token
    url = ('https://www.googleapis.com/oauth2/v1/tokeninfo?access_token=%s'
           % access_token)
    h = httplib2.Http()
    result = json.loads(h.request(url, 'GET')[1].decode("utf-8"))
    # If there was an error in the access token info, abort.
    if result.get('error') is not None:
        response = make_response(json.dumps(result.get('error')), 500)
        response.headers['Content-Type'] = 'application/json'
        return response

    # Verify that the access token is used for the intended user.
    gplus_id = credentials.id_token['sub']
    if result['user_id'] != gplus_id:
        response = make_response(
            json.dumps("Token's user ID doesn't match given user ID."), 401)
        response.headers['Content-Type'] = 'application/json'
        return response

    # Verify that the access token is valid for this app.
    if result['issued_to'] != CLIENT_ID:
        response = make_response(
            json.dumps("Token's client ID does not match app's."), 401)
        print "Token's client ID does not match app's."
        response.headers['Content-Type'] = 'application/json'
        return response
    # Access token within the app
    stored_credentials = login_session.get('credentials')
    stored_gplus_id = login_session.get('gplus_id')
    if stored_credentials is not None and gplus_id == stored_gplus_id:
        response = make_response(json.dumps('Current user is already connected.'),
                                 200)
        response.headers['Content-Type'] = 'application/json'
        return response

    # Store the access token in the session for later use.
    login_session['access_token'] = credentials.access_token
    login_session['gplus_id'] = gplus_id
    response = make_response(json.dumps('Succesfully connected users', 200))

    # Get user info
    userinfo_url = "https://www.googleapis.com/oauth2/v1/userinfo"
    params = {'access_token': credentials.access_token, 'alt': 'json'}
    answer = requests.get(userinfo_url, params=params)

    data = answer.json()
    login_session['provider'] = 'google'
    login_session['username'] = data['name']
    login_session['picture'] = data['picture']
    login_session['email'] = data['email']

    # See if user exists or if it doesn't make a new one
    print 'User email is' +str(login_session['email'])
    user_id = getUserID(login_session['email'])
    if user_id:
        print 'Existing user#' +str(user_id) +'matches this email'
    else:
      user_id = createUser(login_session)
      print 'New user_id#' +str(user_id)+ 'created'
    login_session['user_id'] = user_id
    print 'Login session is tied to :id#' +str(login_session['user_id'])

    output = ''
    output += '<h1>Welcome, '
    output += login_session['username']
    output += '!</h1>'
    output += '<img src="'
    output += login_session['picture']
    output += ' " style = "width: 300px; height: 300px;border-radius:150px;- \
      webkit-border-radius:150px;-moz-border-radius: 150px;">'
    flash("you are now logged in as %s" % login_session['username'])
    print "done!"
    return output

# Helper Functions
def createUser(login_session):
    newUser = User(name=login_session['username'], email=login_session['email'],
                   picture=login_session['picture'])
    session.add(newUser)
    session.commit()
    user = session.query(User).filter_by(email=login_session['email']).first()
    return user.id

def getUserInfo(user_id):
    user = session.query(User).filter_by(id=user_id).first()
    return user

def getUserID(email):
    try:
       user = session.query(User).filter_by(email=email).first()
       return user.id
    except:
       return None


# DISCONNECT - Revoke a current user's token and reset their login_session.
@app.route('/gdisconnect')
def gdisconnect():
    # only disconnect a connected User
    access_token = login_session.get('access_token')
    print 'In gdisconnect access token is %s', access_token
    print 'User name is: '
    print login_session['username']
    if access_token is None:
 	print'Access Token is None'
    	response=make_response(json.dumps('Current user not connected'), 401)
    	response.headers['Content-Type']='application/json'
    	return response
    url = 'https://accounts.google.com/o/oauth2/revoke?token=%s' % login_session['access_token']
    h = httplib2.Http()
    result = h.request(url, 'GET')[0]
    print 'result is'
    print result
    if result['status'] == '200':
        response = make_response(json.dumps('Successfully disconnected.'), 200)
    	response.headers['Content-Type'] = 'application/json'
    	return response
    else:

    	response = make_response(json.dumps('Failed to revoke token for given user.', 400))
    	response.headers['Content-Type'] = 'application/json'
    	return response

@app.route('/logout')
def logout():
    if 'provider' in login_session:
        if login_session['provider'] == 'google':
          gdisconnect()
          del login_session['gplus_id']
          del login_session['access_token']
        del login_session['username']
        del login_session['email']
        del login_session['picture']
        del login_session['user_id']
        del login_session['provider']
        flash("you have succesfully been logout")
        return redirect(url_for('showAlbums'))
    else:
        flash("you were not logged in")
        return redirect(url_for('showAlbums'))


# JSON APIs to view Coldplay Discography
@app.route('/album/<int:album_id>/song/JSON')
def albumSongJSON(album_id):
    album = session.query(Album).filter_by(id = album_id).one()
    items = session.query(songItem).filter_by(album_id = album_id).all()
    return jsonify(songItems=[i.serialize for i in items])


@app.route('/album/<int:album_id>/song/<int:song_id>/JSON')
def songItemJSON(album_id, song_id):
    song_item = session.query(songItem).filter_by(id = song_id).one()
    return jsonify(song_item = song_item.serialize)

@app.route('/album/JSON')
def albumJSON():
    albums = session.query(Album).all()
    return jsonify(albums= [r.serialize for r in albums])

#Show all albums
@app.route('/')
@app.route('/album/')
def showAlbums():
    albums = session.query(Album).order_by(asc(Album.name))
    if 'username' not in login_session:
       return render_template('publicAlbums.html', albums = albums)
    else:
       return render_template('albums.html', albums = albums)


#Create a new album
@app.route('/album/new/', methods=['GET','POST'])
def newAlbum():
    if request.method == 'POST':
        newAlbum = Album(name = request.form['name'], user_id = login_session['user_id'])
        session.add(newAlbum)
        flash('New Album %s Successfully Created' % newAlbum.name)
        session.commit()
        return redirect(url_for('showAlbums'))
    else:
        return render_template('newAlbum.html')

#Edit an album
@app.route('/album/<int:album_id>/edit/', methods = ['GET', 'POST'])
def editAlbum(album_id):
  editedAlbum = session.query(Album).filter_by(id = album_id).first()
  if editedAlbum.user_id != login_session['user_id']:
     return "<script>function myFunction(){alert('You are not authorized to edit \
       this album. please create your own album in order to edit.');} \
       </script><body onload='myFunction()''>"
  if request.method == 'POST':
      if request.form['name']:
        editedAlbum.name = request.form['name']
        flash('Album Successfully Edited %s' % editedAlbum.name)
        return redirect(url_for('showAlbums'))
      else:
       return render_template('editAlbum.html', album = editedAlbum)


#Delete an album
@app.route('/album/<int:album_id>/delete/', methods = ['GET','POST'])
def deleteAlbum(album_id):
    albumToDelete = session.query(Album).filter_by(id = album_id).first()
    if albumToDelete.user_id != login_session['user_id']:
       return "<script>function myFunction() {alert('you are not authorized to \
         delete this album.please create your own album to delete');}\
         </script><body onLoad = 'myFunction()''>"
    if request.method == 'POST':
      session.delete(albumToDelete)
      flash('%s Successfully Deleted' % albumToDelete.name)
      session.commit()
      return redirect(url_for('showAlbums', album_id = album_id))
    else:
      return render_template('deleteAlbum.html',album = albumToDelete)

#Show songs from album
@app.route('/album/<int:album_id>/')
@app.route('/album/<int:album_id>/song/')
def showSong(album_id):
    album = session.query(Album).filter_by(id = album_id).first()
    creator = getUserInfo(album.user_id)
    items = session.query(songItem).filter_by(album_id = album_id).all()

    if 'username' not in login_session:
       return render_template('publicSongs.html', songs = songs, album = album, creator = creator)
    else:
       return render_template('songs.html', songs=songs, album=album, creator=creator)


#Create a new song
@app.route('/album/<int:album_id>/song/new/',methods=['GET','POST'])
def newSong(album_id):
  album = session.query(Album).filter_by(id = album_id).one()
  if request.method == 'POST':
     newItem = SongItem(name = request.form['name'], year = request.form['year'],
                        length = request.form['length'], genre = request.form['genre'],
                        album_id = album_id, user_id = album.user_id)
     session.add(songItem)
     session.commit()
     flash('New Song %s Item Successfully Created' % (newSong.name))
     return redirect(url_for('showSong', album_id = album_id))
  else:
      return render_template('newSong.html', album_id = album_id)

#Edit a song
@app.route('/album/<int:album_id>/song/<int:song_id>/edit', methods=['GET','POST'])
def editSong(album_id, song_id):
    editedItem = session.query(songItem).filter_by(id = song_id).one()
    album = session.query(Album).filter_by(id = album_id).one()
    if login_session['user_id'] != album.user_id:
        return "<script>function myFunction() {alert('You are not authorized to \
          edit songs to this album.Please create your own album in \
          order to edit songs.');}</script><body onload='myFunction()''>"

    if request.method == 'POST':
        if request.form['name']:
            editedItem.name = request.form['name']
        if request.form['year']:
            editedItem.year = request.form['year']
        if request.form['length']:
            editedItem.length = request.form['length']
        if request.form['genre']:
            editedItem.genre = request.form['genre']
        session.add(editedItem)
        session.commit()
        flash('Song Successfully Edited')
        return redirect(url_for('showSong', album_id = album_id))
    else:
        return render_template('editSong.html', album_id = album_id,
                                song_id = song_id, item = editedItem)


#Delete a song
@app.route('/album/<int:album_id>/song/<int:song_id>/delete', methods = ['GET','POST'])

def deleteSong(album_id,song_id):
    album = session.query(Album).filter_by(id = album_id).one()
    songToDelete = session.query(songItem).filter_by(id = song_id).one()
    if login_session['user_id'] != album.user_id:
       return "<script>function myFunction() {alert ('you are not authorized to \
         delete song to this album.please create your own album \
         in order to delete songs');}</script><body onload='myFunction()''>"
    if request.method == 'POST':
        session.delete(songToDelete)
        session.commit()
        flash('Song Successfully Deleted')
        return redirect(url_for('showSong', album_id = album_id))
    else:
        return render_template('deleteSong.html', item = itemToDelete)


if __name__ == '__main__':
   app.secret_key = 'super_secret_key'
   app.debug = True
   app.run(host = '0.0.0.0', port = 5000)
