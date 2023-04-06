from flask import Flask, request, jsonify, render_template, redirect, url_for, make_response, session, send_from_directory
import jwt
from datetime import datetime, timedelta
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
import pymysql.cursors
import pymysql
import os


# Set the allowed file extensions
ALLOWED_EXTENSIONS = {'txt', 'pdf', 'png', 'jpg', 'jpeg', 'gif'}

app = Flask(__name__)

# Configure JWT
app.config['SECRET_KEY'] = 'super-secret'  # Change this!

# Set the maximum allowed file size to 16 megabytes
app.config['MAX_FILE_SIZE'] = 16 * 1024 * 1024

# Set the path to the upload folder
app.config['UPLOAD_FOLDER'] = 'uploads'

# Set the allowed file extenstions
app.config['ALLOWED_EXTENSIONS'] = ALLOWED_EXTENSIONS


# Connect to the database
conn = pymysql.connect(
    host='localhost',
    user='root', 
    password = "Rico4321!",
    db='449_db',
)

# User model with username and password fields
class User:
    def __init__(self, username, password):
        self.username = username
        self.password = password

# Root route
@app.route('/')
def index():
    return render_template('index.html')

# Registration endpoint that creates a new user
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        # Check if the user already exists
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM users WHERE username=%s", (username,))
        if cursor.fetchone() is not None:
            return render_template('register.html', message='User already exists.')

        # Create a new user
        hashed_password = generate_password_hash(password)
        user = User(username, hashed_password)
        cursor.execute("INSERT INTO users (username, password) VALUES (%s, %s)", (user.username, user.password.encode('utf-8')))
        conn.commit()

        return render_template('register.html', message='User created successfully.')

    return render_template('register.html')

# Login endpoint that login users
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        # Check if the username and password are valid
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM users WHERE username=%s", (username,))
        user = cursor.fetchone()
        if user is None:
            return render_template('login.html', message='Invalid credentials.')

        hashed_password = user[2]

        # Check if the password matches for the user
        if check_password_hash(hashed_password, password):
            # Create a JWT token for the user
            payload = {
                'sub': user[1],
                'exp': datetime.utcnow() + timedelta(days=1)
            }
            access_token = jwt.encode(payload, app.config['SECRET_KEY'], algorithm='HS256')
            session['token'] = access_token
            return redirect(url_for('welcome', token=access_token))

        else:
            return render_template('login.html', message='Invalid credentials.')

    return render_template('login.html')

# Logout endpoint
@app.route('/logout')
def logout():
    # Clear the session cookie and token
    session.pop('token', None)
    session.clear()

    # Redirect the user to the login page
    return redirect(url_for('login'))

# Protected welcome endpoint for logged in users
@app.route('/welcome', methods=['GET'])
def welcome():
    token = session.get('token')
    if not token:
        return render_template('login.html', message='Token not found.'), 401
    try:
        payload = jwt.decode(token, app.config['SECRET_KEY'], algorithms=['HS256'])
        username = payload['sub']
    except jwt.ExpiredSignatureError:
        return jsonify({'error': 'Token has expired.'}), 401
    except jwt.InvalidTokenError:
        return jsonify({'error': 'Invalid token.'}), 401

    upload_url = url_for('upload', token=token)

    # Make sure token is not saved when logging out or when returning to the page 
    response = make_response(render_template('welcome.html', username=username,  upload_url=upload_url))
    response.headers['Cache-Control'] = 'no-cache, no-store, must-revalidate'
    response.headers['Pragma'] = 'no-cache'
    response.headers['Expires'] = '0'

    return response


# Protected upload endpoint for logged in users
@app.route('/upload', methods=['GET', 'POST'])
def upload():
    token = session.get('token')
    if not token:
        return render_template('login.html', message='Token not found.'), 401

    try:
        payload = jwt.decode(token, app.config['SECRET_KEY'], algorithms=['HS256'])
        username = payload['sub']
    except jwt.ExpiredSignatureError:
        return render_template('login.html', message='Token has expired.'), 401
    except jwt.InvalidTokenError:
        return render_template('login.html', message='Invalid token.'), 401

    # Saving the file to the folder within local machine
    if request.method == 'POST':
        file = request.files['file']
        if not file:
            return render_template('upload.html', message='No file selected.'), 400
        if file:
            filename = secure_filename(file.filename)
            if filename.split('.')[-1].lower() not in app.config['ALLOWED_EXTENSIONS']:
                return render_template('upload.html', message='Invalid file type. Allowed file types: ' + ', '.join(app.config['ALLOWED_EXTENSIONS'])), 400

            file_size = len(file.read())
            file.seek(0)
            if file_size > app.config['MAX_FILE_SIZE']:
                return render_template('upload.html', message='File size is too large. Maximum allowed file size: ' + str(app.config['MAX_FILE_SIZE']) + ' bytes'), 400

            file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))

            # insert the username and filename into the database
            cur = conn.cursor()
            cur.execute("INSERT INTO uploads (username, filename) VALUES (%s, %s)", (username, filename))
            conn.commit()
            cur.close()

            # Make sure token is not saved when logging out or when returning to the page 
            response = make_response(render_template('upload.html', message='File uploaded successfully.'))
            response.headers['Cache-Control'] = 'no-cache, no-store, must-revalidate'
            response.headers['Pragma'] = 'no-cache'
            response.headers['Expires'] = '0'

            return response

    return render_template('upload.html')

# Public endpoint for showing public information
@app.route('/public')
def public():
    # Get all unique usernames from the database
    cur = conn.cursor()
    cur.execute("SELECT DISTINCT username FROM uploads")
    usernames = [row[0] for row in cur.fetchall()]

    # Create a dictionary to store the uploads for each user
    uploads = {}
    for username in usernames:
        cur.execute("SELECT filename FROM uploads WHERE username = %s", (username,))
        filenames = [row[0] for row in cur.fetchall()]
        uploads[username] = filenames

    # Render the public profile page with all the uploads
    return render_template('public.html', uploads=uploads)


@app.route('/uploads/<filename>')
def uploaded_file(filename):
    return send_from_directory(app.config['UPLOAD_FOLDER'], filename)


if __name__ == '__main__':
    app.run(debug=True)
