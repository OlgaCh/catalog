import logging
import os
from datetime import datetime
from sqlalchemy import asc
from functools import wraps

from flask import Flask, render_template, request, redirect, url_for, flash, \
    jsonify
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import orm
from models import Category, PlaceItem, User

from flask import session as login_session
import random, string

from oauth2client.client import flow_from_clientsecrets
from oauth2client.client import FlowExchangeError
import httplib2
import json
from flask import make_response
import requests

app = Flask(__name__)

app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///places.db'
db = SQLAlchemy(app)
session = db.session

CLIENT_ID = json.loads(open('client_secrets.json', 'r').read())['web'][
    'client_id']


# Create anti-forgery state token
@app.route('/login')
def showLogin():
    """
    Initiate state for Google OAUTH login

    :return: login page
    """
    state = ''.join(random.choice(string.ascii_uppercase + string.digits)
                    for x in range(32))
    login_session['state'] = state
    return render_template('login.html', STATE=state)


# Code was derived from "Creating Google Sign in" course of
# Full Stack Nano Degree
# https://classroom.udacity.com/nanodegrees/nd004/parts/8d3e23e1-9ab6-47eb-b4f3
# -d5dc7ef27bf0/modules/348776022975461/lessons/3967218625/concepts/39518891880923
# It has only minor modifications on code style
@app.route('/gconnect', methods=['POST'])
def gconnect():
    """
    Connecting to Google app with Client ID
    """
    global CLIENT_ID
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
    url = (f'https://www.googleapis.com/oauth2/v1/tokeninfo?'
           f'access_token={access_token}')
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
        logging.warning("Token's client ID does not match app's.")
        response.headers['Content-Type'] = 'application/json'
        return response

    stored_access_token = login_session.get('access_token')
    stored_gplus_id = login_session.get('gplus_id')
    if stored_access_token is not None and gplus_id == stored_gplus_id:
        response = make_response(
            json.dumps('Current user is already connected.'), 200)
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

    # see if user exists, if it doesn't create new one
    user_id = getUserID(data['email'])
    if not user_id:
        user_id = createUser(login_session)
    login_session['user_id'] = user_id

    # Adding provider to login session.
    # May be useful if several oauth providers will be used.
    login_session['provider'] = 'Google'

    output = f'<h1 align="center">Welcome, {login_session["username"]}!<h1>' \
             f'<img src="{login_session["picture"]}" style = "width: 200px; ' \
             f'height: 200px;border-radius: 100px;-webkit-border-radius: 1050px;' \
             f'-moz-border-radius: 150px;" align="center">'
    flash("You are now logged in as ~ %s" % login_session['username'])
    return output


# User Helper Functions


def createUser(login_session):
    """
    Create new user.

    :param login_session: session with user details
    :return: user.id
    """
    newUser = User(name=login_session['username'], email=login_session['email'],
                   picture_url=login_session['picture'])
    session.add(newUser)
    session.commit()
    user = session.query(User).filter_by(email=login_session['email']).one()
    return user.id


def getUserInfo(user_id):
    """
    Get user info by id

    :param user_id: user unique key.
    :return: user object.
    """
    user = session.query(User).filter_by(id=user_id).one()
    return user


def getUserID(email):
    """
    Get user id by email. Useful when Google auth used.

    :param email: user email.
    :return: user.id
    """
    try:
        user = session.query(User).filter_by(email=email).one()
        return user.id
    except orm.exc.NoResultFound:
        return None

# Helper wrappers
def login_required(func):
    """
    To check if user logged in and request login if not.
    """
    @wraps(func)
    def wrapper(*args, **kwargs):
        if 'username' not in login_session:
            return redirect('login')
        else:
            return func(*args, **kwargs)
    return wrapper

def ownership_required(func):
    """
    To check if user owns an object he about to change/delete
    """
    @wraps(func)
    def wrapper(*args, **kwargs):
        category_id = kwargs.get('category_id', None)
        place_id = kwargs.get('place_id', None)
        if place_id:
            db_object = session.query(PlaceItem).filter_by(id=place_id).one()
        elif category_id:
            db_object = session.query(Category).filter_by(id=category_id).one()
        else:
            return "Some error occur"
        if db_object.user_id != login_session['user_id']:
            return """
                    <script>function myFunction() {alert('Sorry! You are not
                    authorized to perform this action! Please make sure that you\'re
                    the owner of this page!');
                    }</script>
                    <body onload='myFunction()'>
                    """
        else:
            return func(*args, **kwargs)
    return wrapper

def object_exists(func):
    """
    To check if object we about to change/delete exists in database.
    """
    @wraps(func)
    def wrapper(*args, **kwargs):
        category_id = kwargs.get('category_id', None)
        place_id = kwargs.get('place_id', None)
        db_object = None
        print(category_id, place_id)
        if place_id:
            db_object = session.query(PlaceItem).filter_by(id=place_id).one_or_none()
        elif category_id:
            db_object = session.query(Category).filter_by(id=category_id).one_or_none()
        if not db_object:
            response = make_response('Some error occur. Can\'t find record '
                                     'you about to change/delete', 404)
            return response
        else:
            return func(*args, **kwargs)
    return wrapper

@app.route('/gdisconnect')
def gdisconnect():
    """
    Disconnecting from Google.
    Required to clean up the session if account not used anymore.
    """
    access_token = login_session.get('access_token')
    if access_token is None:
        logging.warning('Access Token is None')
        response = make_response(json.dumps('Current user not connected.'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response
    logging.info(f'In gdisconnect access token is {access_token}')
    logging.info(f'User name is: {login_session["username"]}')
    url = f'https://accounts.google.com/o/oauth2/revoke?token=' \
          f'{login_session["access_token"]}'
    h = httplib2.Http()
    result = h.request(url, 'GET')[0]
    logging.info(f'result is \n{result}')
    if result['status'] == '200':
        for k in ['access_token', 'gplus_id', 'username', 'email', 'picture']:
            del login_session[k]
        response = make_response(json.dumps('Successfully disconnected.'), 200)
        response.headers['Content-Type'] = 'application/json'
        return response
    else:
        response = make_response(
            json.dumps('Failed to revoke token for given user.', 400))
        response.headers['Content-Type'] = 'application/json'
    return response

# JSON APIs to view Category Information
@app.route('/category/<int:category_id>/places/JSON')
def categoryPlaceJSON(category_id):
    """
    JSON representation of all places belonging to the category.

    :param category_id: unique key of the category
    :return: json
    """
    places = session.query(PlaceItem).filter_by(category_id=category_id).all()
    return jsonify(PlaceItems=[i.serialize for i in places])


@app.route('/category/<int:category_id>/places/<int:place_id>/JSON')
def placeItemJSON(category_id, place_id):
    """
    JSON representation of the specific place.

    :param category_id: unique key of the category place belongs too (not used
     in the query)
    :param place_id: unique place id
    :return: json
    """
    place_item = session.query(PlaceItem).filter_by(id=place_id).one_or_none()
    if not place_item:
        response = make_response('No Such Place!', 404)
        return response
    return jsonify(Place=place_item.serialize)


@app.route('/category/JSON')
def categoryJSON():
    """
    JSON representation of all categories

    :return: json
    """
    categories = session.query(Category).all()
    return jsonify(Categories=[r.serialize for r in categories])


# Show all categories
@app.route('/')
@app.route('/category/')
def showCategories():
    """
    Categories listing at the main page.

    :return: html
    """
    categories = session.query(Category).order_by(asc(Category.name))
    is_logged_in = False
    user = None
    if 'username' in login_session:
        is_logged_in = True
        user = getUserInfo(login_session['user_id'])
    return render_template('category/categories.html', categories=categories,
                           creator=user, is_logged_in=is_logged_in)


# Create a new category
@app.route('/category/new/', methods=['GET', 'POST'])
@login_required
def newCategory():
    """
    Page to add new category

    :return: html
    """
    if request.method == 'POST':
        newCategory = Category(name=request.form.get('name'),
                               user_id=login_session['user_id'])
        session.add(newCategory)
        flash(f'New Category ~ {newCategory.name} ~ Successfully Created')
        session.commit()
        return redirect(url_for('showCategories'))
    else:
        user = getUserInfo(login_session['user_id'])
        return render_template('category/new_category.html', creator=user)


# Edit a category
@app.route('/category/<int:category_id>/edit/', methods=['GET', 'POST'])
@object_exists
@login_required
@ownership_required
def editCategory(category_id):
    """
    Page to edit category

    :param category_id: unique key of the edited category
    :return: html
    """
    editedCategory = session.query(Category).filter_by(
        id=category_id).one()
    if request.method == 'POST':
        if 'name' in request.form:
            editedCategory.name = request.form.get('name')
            session.add(editedCategory)
            session.commit()
            flash(f'Category Successfully Edited ~ {editedCategory.name}')
        return redirect(url_for('showCategories'))
    else:
        user = getUserInfo(login_session['user_id'])
        return render_template('category/edit_category.html',
                               category=editedCategory, creator=user)


# Delete category
@app.route('/category/<int:category_id>/delete/', methods=['GET', 'POST'])
@object_exists
@login_required
@ownership_required
def deleteCategory(category_id):
    """
    Page to delete category

    :param category_id: unique key of the category to be deleted
    :return: html
    """
    categoryToDelete = session.query(Category).filter_by(
        id=category_id).one()
    if request.method == 'POST':
        session.delete(categoryToDelete)
        flash(f'{categoryToDelete.name} ~ Successfully Deleted')
        session.commit()
        return redirect(url_for('showCategories', category_id=category_id))
    else:
        user = getUserInfo(login_session['user_id'])
        return render_template('category/delete_category.html',
                               category=categoryToDelete, creator=user)


# Show places for category
@app.route('/category/<int:category_id>/')
@app.route('/category/<int:category_id>/places/')
def showPlaces(category_id):
    """
    Page to show all places per category

    :param category_id: unique key of the category
    :return: html
    """
    category = session.query(Category).filter_by(id=category_id).one()
    places = session.query(PlaceItem).filter_by(category_id=category_id).all()
    creator = getUserInfo(category.user_id)
    is_logged_in = True
    if 'username' not in login_session or creator.id != login_session['user_id']:
        is_logged_in = False
    return render_template('place/places.html', places=places, category=category,
                           creator=creator, is_logged_in=is_logged_in)


# Create a new place
@app.route('/category/<int:category_id>/places/new/', methods=['GET', 'POST'])
@login_required
def newPlace(category_id):
    """
    Page to create new place

    :param category_id: unique key of the category page should belong to
    :return: html
    """
    #category = session.query(Category).filter_by(id=category_id).one()
    if request.method == 'POST':
        newItem = PlaceItem(name=request.form['name'],
                            address=request.form.get('address'),
                            phone=request.form.get('phone'),
                            website=request.form.get('website'),
                            latitude=request.form.get('latitude') if
                            len(request.form.get('latitude')) else 0.0,
                            longitude=request.form.get('longitude') if
                            len(request.form.get('longitude')) else 0.0,
                            description=request.form.get('description'),
                            media_links=request.form.get('media_links'),
                            rating=request.form.get('rating') if
                            len(request.form.get('rating')) else 0.0,
                            date_created=datetime.utcnow(),
                            category_id=category_id,
                            user_id=login_session['user_id'])
        session.add(newItem)
        session.commit()
        flash(f'New Place ~ {newItem.name} ~ Successfully Created')
        return redirect(url_for('showPlaces', category_id=category_id))
    else:
        user = getUserInfo(login_session['user_id'])
        return render_template('place/new_place.html', category_id=category_id,
                               creator=user)


# Edit place
@app.route('/category/<int:category_id>/places/<int:place_id>/edit',
           methods=['GET', 'POST'])
@object_exists
@login_required
@ownership_required
def editPlace(category_id, place_id):
    """
    Page to edit place.

    :param category_id: unique category key
    :param place_id: unique place key
    :return: html
    """
    editedItem = session.query(PlaceItem).filter_by(id=place_id).one()
    if request.method == 'POST':
        if 'name' in request.form:
            editedItem.name = request.form.get('name')
        if 'address' in request.form:
            editedItem.address = request.form.get('address')
        if 'phone' in request.form:
            editedItem.phone = request.form.get('phone')
        if 'website' in request.form:
            editedItem.website = request.form.get('website')
        if 'latitude' in request.form:
            editedItem.latitude = request.form.get('latitude')
        if 'longitude' in request.form:
            editedItem.longitude = request.form.get('longitude')
        if 'description' in request.form:
            editedItem.description = request.form.get('description')
        if 'media_links' in request.form:
            editedItem.media_links = request.form.get('media_links')
        if 'rating' in request.form:
            editedItem.rating = request.form.get('rating')
        session.add(editedItem)
        session.commit()
        flash(f'Place ~ {editedItem.name} ~ Successfully Edited')
        return redirect(url_for('showPlaces', category_id=category_id))
    else:
        user = getUserInfo(login_session['user_id'])
        return render_template('place/edit_place.html', category_id=category_id,
                               place_id=place_id, item=editedItem,
                               creator=user)


# Delete place
@app.route('/category/<int:category_id>/places/<int:place_id>/delete',
           methods=['GET', 'POST'])
@object_exists
@login_required
@ownership_required
def deletePlace(category_id, place_id):
    """
    Page to delete place.

    :param category_id: unique key of the category place belongs to
    :param place_id: unique key of the place to be deleted
    :return: html
    """
    itemToDelete = session.query(PlaceItem).filter_by(id=place_id).one()
    if request.method == 'POST':
        session.delete(itemToDelete)
        session.commit()
        flash(f'Place ~ {itemToDelete.name} ~ Successfully Deleted')
        return redirect(url_for('showPlaces', category_id=category_id))
    else:
        user = getUserInfo(login_session['user_id'])
        return render_template('place/delete_place.html', place=itemToDelete,
                               creator=user)


# Disconnect from Google
@app.route('/disconnect')
def disconnect():
    """
    Page to disconnect from Google

    :return: html
    """
    gdisconnect()
    for f in ['gplus_id', 'access_token', 'username', 'email',
            'picture', 'user_id', 'provider']:
        if f in login_session:
            del login_session[f]
    flash("You have successfully been logged out.")
    return redirect(url_for('showCategories'))


if __name__ == '__main__':
    # In order to use OAUTH with Google a secret key should be provided at
    # each app's run. Key may be random and required to generate token.
    app.secret_key = 'some_secret_key'
    app.debug = True
    app.run(host='localhost', port=int(os.environ.get('PORT',5000)))
