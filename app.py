from flask import Flask, request, jsonify, render_template, redirect, url_for, make_response
import jwt
from datetime import datetime, timedelta
from werkzeug.security import generate_password_hash, check_password_hash
import pymysql.cursors
import pymysql
import os




# Set the allowed file extensions
ALLOWED_EXTENSIONS = {'txt', 'pdf', 'png', 'jpg', 'jpeg', 'gif'}

app = Flask(__name__)

# Configure JWT
app.config['SECRET_KEY'] = 'super-secret'  # Change this!

# Set the maximum allowed file size to 16 megabytes
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024

# Set the path to the upload folder
app.config['UPLOAD_FOLDER'] = 'uploads'

# Connect to the database
conn = pymysql.connect(
    host='localhost',
    user='root', 
    password = "Rico4321!",
    db='449_db',
)

# Create a user model with username and password fields
class User:
    def __init__(self, username, password):
        self.username = username
        self.password = password

@app.route('/')
def index():
    return render_template('index.html')

# Implement a registration endpoint that creates a new user
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

        return render_template('login.html', message='User created successfully.')

    return render_template('register.html')


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

        if check_password_hash(hashed_password, password):
            # Create a JWT token for the user
            payload = {
                'sub': user[1],
                'exp': datetime.utcnow() + timedelta(days=1)
            }
            access_token = jwt.encode(payload, app.config['SECRET_KEY'], algorithm='HS256')
            print(access_token)
            return redirect(url_for('welcome', token=access_token))

        else:
            return render_template('login.html', message='Invalid credentials.')

    return render_template('login.html')

@app.route('/welcome', methods=['GET'])
def welcome():
    token = request.args.get('token')
    print(token)
    if token:
        try:
            payload = jwt.decode(token, app.config['SECRET_KEY'], algorithms=['HS256'])
            username = payload['sub']
            return render_template('welcome.html', username=username)
        except jwt.ExpiredSignatureError:
            return jsonify({'error': 'Token has expired.'}), 401
        except jwt.InvalidTokenError:
            return jsonify({'error': 'Invalid token.'}), 401
    else:
        return render_template('login.html', message='Authorization header not found.'), 401

# Function to check if a file has an allowed extension
def allowed_file(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS


@app.route('/upload', methods=['GET', 'POST'])
def upload():
    auth_header = request.headers.get('Authorization')
    if not auth_header:
        return render_template('login.html', message='Authorization header not found.'), 401

    token = auth_header.split(' ')[1]
    try:
        payload = jwt.decode(token, app.config['SECRET_KEY'], algorithms=['HS256'])
        username = payload['sub']
    except jwt.ExpiredSignatureError:
        return render_template('login.html', message='Token has expired.'), 401
    except jwt.InvalidTokenError:
        return render_template('login.html', message='Invalid token.'), 401

    if request.method == 'POST':
        file = request.files['file']
        if file:
            filename = secure_filename(file.filename)
            if filename.split('.')[-1].lower() not in app.config['ALLOWED_EXTENSIONS']:
                return render_template('upload.html', message='Invalid file type. Allowed file types: ' + ', '.join(app.config['ALLOWED_EXTENSIONS'])), 400

            file_size = len(file.read())
            file.seek(0)
            if file_size > app.config['MAX_FILE_SIZE']:
                return render_template('upload.html', message='File size is too large. Maximum allowed file size: ' + str(app.config['MAX_FILE_SIZE']) + ' bytes'), 400

            file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
            return render_template('upload.html', message='File uploaded successfully.')

    return render_template('upload.html')


if __name__ == '__main__':
    app.run(debug=True)
