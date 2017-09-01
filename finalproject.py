#!/usr/bin/env python
######################################################
# Project 4: Make a catalog
# Date Created: 08/31/2017
# Submitted by: Widya Puspitaloka
# Description: This file is a source code for an
#              application that provides
#              a list of items within a variety of
#              categories as well as provide a user
#              registration and authentication system
######################################################

from flask import Flask, render_template
from flask import request, redirect, url_for, flash, jsonify
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from database_setup import Base, Album, SongItem, User
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

app = Flask(__name__)

CLIENT_ID = json.loads(open('client_secrets.json', 'r')
                       .read())['web']['client_id']
APPLICATION_NAME = "Coldplay Discography Application"

engine = create_engine('sqlite:///coldplaydiscographywithuser.db')
Base.metadata.bind = engine

DBSession = sessionmaker(bind=engine)
session = DBSession()

# Create a state token to request forgery.
# Store it in the session for later validation


@app.route('/login')
def showLogin():
    state = ''.join(random.choice(string.ascii_uppercase + string.digits)
                    for x in xrange(32))
    login_session['state'] = state
    # return "The current session state is %s" % login_session['state']
    return render_template('login.html', STATE=state)


@app.route('/gconnect', methods=['POST'])
def gconnect():
    # Validate state token
    if request.args.get('state') != login_session['state']:
        response = make_response(json.dumps('Invalid state parameter.'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response
    # Obtain authorization code
    code = request.data

    try:
        # Upgrade the authorization code into a credentials object
        oauth_flow = flow_from_clientsecrets('client_secrets.json', scope='')
        oauth_flow.redirect_uri = 'postmessage'
        credentials = oauth_flow.step2_exchange(code)
    except FlowExchangeError:
        response = make_response(
            json.dumps('Failed to upgrade the authorization code.'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response

    # Check that the access token is valid.
    access_token = credentials.access_token
    url = ('https://www.googleapis.com/oauth2/v1/tokeninfo?access_token=%s'
           % access_token)
    h = httplib2.Http()
    result = json.loads(h.request(url, 'GET')[1])
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

    stored_access_token = login_session.get('access_token')
    stored_gplus_id = login_session.get('gplus_id')
    if stored_access_token is not None and gplus_id == stored_gplus_id:
        response = make_response(json.dumps
                                 ('Current user is already connected.'),
                                 200)
        response.headers['Content-Type'] = 'application/json'
        return response

    # Store the access token in the session for later use.
    login_session['access_token'] = credentials.access_token
    login_session['gplus_id'] = gplus_id

    # Get user info
    userinfo_url = "https://www.googleapis.com/oauth2/v1/userinfo"
    params = {'access_token': credentials.access_token, 'alt': 'json'}
    answer = requests.get(userinfo_url, params=params)

    data = answer.json()

    login_session['username'] = data['name']
    login_session['picture'] = data['picture']
    login_session['email'] = data['email']

    # See if a user exists, if it doesn't make a new one
    user_id = getUserID(login_session['email'])
    if not user_id:
        user_id = createUser(login_session)
    login_session['user_id'] = user_id

    output = ''
    output += '<h1>Welcome, '
    output += login_session['username']
    output += '!</h1>'
    output += '<img src="'
    output += login_session['picture']
    output += ' " style = "width: 300px; height: 300px;border-radius: \
                150px;-webkit-border-radius: \
                150px;-moz-border-radius: 150px;"> '
    flash("you are now logged in as %s" % login_session['username'])
    print "done!"
    return output


# User Helper Functions
def createUser(login_session):
    newUser = User(name=login_session['username'], email=login_session[
                   'email'], picture=login_session['picture'])
    session.add(newUser)
    session.commit()
    user = session.query(User).filter_by(email=login_session['email']).one()
    return user.id


def getUserInfo(user_id):
    user = session.query(User).filter_by(id=user_id).first()
    return user


def getUserID(email):
    try:
        user = session.query(User).filter_by(email=email).one()
        return user.id
    except:
        return None


# DISCONNECT - Revoke a current user's token and reset their login_session
@app.route('/gdisconnect')
def gdisconnect():
    access_token = login_session.get('access_token')
    if access_token is None:
        print 'Access Token is None'
        response = make_response(json.dumps
                                 ('Current user not connected.'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response
    print 'In gdisconnect access token is %s', access_token
    print 'User name is: '
    print login_session['username']
    url = 'https://accounts.google.com/o/oauth2/revoke?token=%s' \
          % login_session['access_token']
    h = httplib2.Http()
    result = h.request(url, 'GET')[0]
    print 'result is '
    print result
    if result['status'] == '200':
        # Read the user's session
        del login_session['access_token']
        del login_session['gplus_id']
        del login_session['username']
        del login_session['email']
        del login_session['picture']
        response = make_response(json.dumps('Successfully disconnected.'), 200)
        response.headers['Content-Type'] = 'application/json'
        return response
    else:
        response = make_response(json.dumps
                                 ('Failed to revoke token \
                                  for given user.', 400))
        response.headers['Content-Type'] = 'application/json'
        return response
    print login_session


# Making an API endpoint (GET request)
@app.route('/albums/JSON')
def albumsJSON():
    albums = session.query(Album).all()
    return jsonify(Albums=[i.serialize for i in albums])


@app.route('/albums/songs/JSON')
def songJSON():
    songs = session.query(SongItem).all()
    return jsonify(All_Songs=[i.serialize for i in songs])


@app.route('/album/<int:album_id>/song/JSON')
def albumSongJSON(album_id):
    album = session.query(Album).filter_by(id=album_id).first()
    songs = session.query(SongItem).filter_by(album_id=album.id).all()
    return jsonify(SongItems=[i.serialize for i in songs])


@app.route('/album/<int:album_id>/song/<int:song_id>/JSON')
def songItemJSON(album_id, song_id):
    song_item = session.query(SongItem).filter_by(id=song_id).one()
    return jsonify(SongItem=song_item.serialize)


# Show all albums
@app.route('/')
@app.route('/albums/')
def showAlbums():
    albums = session.query(Album).all()
    if 'username' not in login_session:
        return render_template('publicAlbums.html', albums=albums)
    else:
        return render_template('albums.html', albums=albums)


# Create new album
@app.route('/album/new/', methods=['GET', 'POST'])
def newAlbum():
    if 'username' not in login_session:
        return redirect('/login')
    if request.method == 'POST':
        newAlbum = Album(
            name=request.form['name'], user_id=login_session['user_id'])
        session.add(newAlbum)
        session.commit()
        flash("New album has been added!")
        return redirect(url_for('showAlbums'))
    else:
        return render_template('newAlbum.html')


# Edit album
@app.route('/album/<int:album_id>/edit/', methods=['GET', 'POST'])
def editAlbum(album_id):
    editedAlbum = session.query(Album).filter_by(id=album_id).first()
    if 'username' not in login_session:
        return redirect('/login')
    if editedAlbum.user_id != login_session['user_id']:
        return "<script>function myFunction() {alert('You are not authorized\
        to edit this album. Please create your own \
        album in order to edit.');}</script><body onload='myFunction()''>"

    if request.method == 'POST':
        if request.form['name']:
            editedAlbum.name = request.form['name']
        session.add(editedAlbum)
        session.commit()
        flash("Album has been edited!")
        return redirect(url_for('showAlbums', album_id=album_id))
    else:
        # USE THE RENDER_TEMPLATE FUNCTION BELOW TO
        # SEE THE VARIABLES YOU SHOULD USE IN YOUR EDITMENUITEM TEMPLATE
        return render_template('editAlbum.html',
                               album_id=album_id, i=editedAlbum)


# Delete an album
@app.route('/album/<int:album_id>/delete/', methods=['GET', 'POST'])
def deleteAlbum(album_id):
    albumToDelete = session.query(Album).filter_by(id=album_id).one()
    if 'username' not in login_session:
        return redirect('/login')
    if albumToDelete.user_id != login_session['user_id']:
        return "<script>function myFunction() {alert('You are not authorized \
        to edit this album. Please create your own album in\
        order to delete.');}</script><body onload='myFunction()''>"

    if request.method == 'POST':
        session.delete(albumToDelete)
        session.commit()
        flash("Album has been deleted!")
        return redirect(url_for('showAlbums', album_id=album_id))
    else:
        return render_template('deleteAlbum.html', i=albumToDelete)


# Show all songs
@app.route('/')
@app.route('/albums/songs')
def showAllSongs():
    songs = session.query(SongItem).all()
    return render_template('allsongs.html', songs=songs)


# Show songs from album
@app.route('/album/<int:album_id>/')
@app.route('/album/<int:album_id>/song/')
def showSong(album_id):
    album = session.query(Album).filter_by(id=album_id).first()
    creator = getUserInfo(album.user_id)
    songs = session.query(SongItem).filter_by(album_id=album_id).all()
    if 'username' not in login_session:
        return render_template('publicSongs.html',
                               songs=songs, album=album, creator=creator)
    else:
        return render_template('songs.html',
                               songs=songs, album=album, creator=creator)


# Create new song
@app.route('/album/<int:album_id>/song/new/', methods=['GET', 'POST'])
def newSongItem(album_id):
    if 'username' not in login_session:
        return redirect('/login')
    album = session.query(Album).filter_by(id=album_id).one()
    if login_session['user_id'] != album.user_id:
        return "<script>function myFunction() {alert('You are not \
        authorized to add song to this album. Please create your own \
        album in order to add songs.');}</script><body onload='myFunction()''>"
    if request.method == 'POST':
        newItem = SongItem(
            name=request.form['name'], year=request.form['year'],
            length=request.form['length'], genre=request.form['genre'],
            album_id=album_id, user_id=album.user_id)
        session.add(newItem)
        session.commit()
        flash("New song has been added!")
        return redirect(url_for('showSong', album_id=album_id))
    else:
        return render_template('newSongitem.html', album_id=album_id)


# Edit a song
@app.route('/album/<int:album_id>/song/\
    <int:song_id>/edit/', methods=['GET', 'POST'])
def editSongItem(album_id, song_id):
    if 'username' not in login_session:
        return redirect('/login')
    editedItem = session.query(SongItem).filter_by(id=song_id).one()
    album = session.query(Album).filter_by(id=album_id).one()
    if login_session['user_id'] != album.user_id:
        return "<script>function myFunction() {alert('You are not authorized \
        to edit songs in this album.\
        Please create your own album in order to \
        edit songs.');}</script><body onload='myFunction()''>"
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
        flash("Song item has been edited!")
        return redirect(url_for('showSong', album_id=album_id))
    else:
        # USE THE RENDER_TEMPLATE FUNCTION BELOW TO SEE THE VARIABLES
        # YOU SHOULD USE IN YOUR EDITMENUITEM TEMPLATE
        return render_template('editSongItem.html',
                               album_id=album_id,
                               song_id=song_id, i=editedItem)


# Delete an album
@app.route('/album/<int:album_id>/song/ \
            <int:song_id>/delete/', methods=['GET', 'POST'])
def deleteSong(album_id, song_id):
    if 'username' not in login_session:
        return redirect('/login')
    itemToDelete = session.query(SongItem).filter_by(id=song_id).one()
    album = session.query(Album).filter_by(id=album_id).one()
    if login_session['user_id'] != album.user_id:
        return "<script>function myFunction() {alert('You are not authorized \
        to edit songs in this album. Please create your own album in order \
        to edit songs.');}</script><body onload='myFunction()''>"
    if request.method == 'POST':
        session.delete(itemToDelete)
        session.commit()
        flash("Song has been deleted!")
        return redirect(url_for('showSong', album_id=album_id))
    else:
        return render_template('deleteSongItem.html',
                               album_id=album_id,
                               song_id=song_id, i=itemToDelete)


if __name__ == '__main__':
    app.secret_key = 'super_secret_key'
    app.debug = True
    app.run(host='0.0.0.0', port=5000)
