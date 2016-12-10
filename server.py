
from flask import Flask, render_template, request, redirect, session, flash
import re
import md5
from flask_bcrypt import Bcrypt



EMAIL_REGEX = re.compile(r'^[a-zA-Z0-9.+_-]+@[a-zA-Z0-9._-]+\.[a-zA-Z]+$')
PASS_REGEX = re.compile(r'^(?=.*[A-Z])(?=.*[a-z])[a-zA-Z\d]+$')

app = Flask(__name__)
bcrypt = Bcrypt(app)

app.secret_key = 'i<3secrets'

from mysqlconnection import MySQLConnector
mysql = MySQLConnector (app, 'wall')


@app.route('/')
def index():
    return render_template('index.html')

@app.route('/register', methods =['POST'])
def create():
    message = False;
    if len(request.form["first_name"])< 2:
        flash("First Name cannot be empty and more than 2 characters")
        message = True;

    if len(request.form["last_name"])< 2:
        flash("Last Name cannot be empty and more than 2 characters")
        message = True;

    if not EMAIL_REGEX.match(request.form['email']):
        flash("Enter a valid email")
        message = True;

    if not len(request.form["password"])> 8:
        flash("Password should be longer than 8 characters")
        message = True;

    if not len(request.form["confirm_password"])> 8 :
        flash("Password should be longer than 8 characters")
        message = True;

    if not str(request.form["password"])== str(request.form["confirm_password"]):
        flash("Password do not match")
        message = True;

    if message == True:
        return redirect('/')
    else:
        query = 'INSERT INTO users(first_name,last_name,email, password, confirm_password) values(:first_name, :last_name, :email,:password, :confirm_password)'
        data = {
        'first_name': request.form["first_name"],
        'last_name' : request.form["last_name"],
        'email': request.form["email"],
        'password': bcrypt.generate_password_hash(request.form['password']),
        'confirm_password': md5.new(request.form['confirm_password']).hexdigest()
        }
        mysql.query_db(query, data)

        flash("Registration Successful")
        return redirect('/wall')

@app.route('/login', methods =['POST'])
def login():
    query = "SELECT * FROM users WHERE email = '" +request.form["email"]+ "';"
    info = mysql.query_db(query)


    if len(info)>0 and bcrypt.check_password_hash(info[0]['password'], request.form['password']):
        flash("Login Successful")
        session['id'] = info[0]['id']
        return redirect('/wall')
    else:
        flash("Invalid email/password")
        return redirect('/')

@app.route('/wall')
def wall():
    # session['id']
    query = 'SELECT * FROM users WHERE id = :id'
    data = {
        'id': session['id']
    }
    info = mysql.query_db(query, data)


    query_msg = 'SELECT first_name, last_name, messages.id, messages.created_at, message FROM users LEFT JOIN messages ON users.id = messages.user_id ORDER BY messages.created_at DESC;'
    msgs = mysql.query_db(query_msg)

    query_com = "SELECT first_name, last_name, comments.created_at, comment, message_id FROM comments LEFT JOIN users ON users.id = comments.user_id LEFT JOIN messages ON comments.message_id= messages.id ORDER BY comments.created_at DESC;"

    coms = mysql.query_db(query_com)

    return render_template('wall.html', info = info, msgs = msgs, coms = coms)





@app.route('/message', methods = ['POST'])
def msg():
    if not request.form['message']:
        flash("Enter something!")
        return redirect('/wall')

    query = 'INSERT INTO messages(message, created_at, updated_at, user_id) VALUES(:message, NOW(), NOW(), :id);'
    data={
    'message': request.form['message'],
    'id': session['id']
    }
    mysql.query_db(query, data)
    return redirect('/wall')

@app.route('/comment/<msg_id>',methods = ['POST'])
def com(msg_id):
    comment_query = 'INSERT INTO comments(comment, created_at, updated_at, user_id, message_id) VALUES(:comment, NOW(), NOW(),:id,:message_id)'
    comment_data = {
    'comment': request.form['comment'],
    'id': session['id'],
    'message_id': msg_id
    }
    mysql.query_db(comment_query, comment_data)
    return redirect('/wall')
# @app.route('/wall')
# def showAll():
#     query_msg = 'SELECT first_name, last_name, created_at, message FROM users LEFT JOIN messages ON users.id = messages.user_id;'
#     info = mysql.query_db(query_msg)
#     return redirect('/wall', info = info)



app.run(debug=True)
