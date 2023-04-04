from flask import Flask, request, jsonify, render_template
from flask_jwt_extended import create_access_token, jwt_required, JWTManager
# from flask_uploads import UploadSet, configure_uploads, IMAGES
# from werkzeug.utils import secure_filename
# from flask_bcrypt import generate_password_hash, check_password_hash
from werkzeug.security import generate_password_hash, check_password_hash
import pymysql.cursors
import pymysql
import os


# Define the allowed file types
# ALLOWED_EXTENSIONS = {'txt', 'pdf', 'png', 'jpg', 'jpeg', 'gif'}

app = Flask(__name__)

# Configure JWT
app.config['JWT_SECRET_KEY'] = 'super-secret'  # Change this!

# Configure file uploads
# app.config['UPLOADED_FILES_DEST'] = 'uploads'
# app.config['UPLOADED_FILES_ALLOW'] = IMAGES
# app.config['UPLOADED_FILES_DENY'] = (['exe', 'py', 'sh', 'php', 'js'])
# app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16 MB
# files = UploadSet('files', ('txt', 'pdf', 'png', 'jpg', 'jpeg', 'gif'))
# configure_uploads(app, files)

jwt = JWTManager(app)

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


# Implement a login endpoint that authenticates the user and returns a JWT token
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
            access_token = create_access_token(identity=user[0])

            return jsonify({'access_token': access_token}), 200
        else:
            return render_template('login.html', message='Invalid credentials.')

    return render_template('login.html')


# Implement a welcome page after successful login
# @app.route('/welcome', methods=['GET'])
# @jwt_required()
# def welcome():
#     current_user = get_jwt_identity()
#     return render_template('welcome.html', username=current_user)

# # Implement an endpoint for file upload
# @app.route('/upload', methods=['GET', 'POST'])
# @jwt_required()
# def upload():
#     if request.method == 'POST':
#         # Get the uploaded file and validate its type and size
#         file = request.files.get('file')
#         if file and allowed_file(file.filename) and allowed_size(file):
#             # Save the uploaded file in a secure location
#             filename = secure_filename(file.filename)
#             file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))

#             return jsonify({'message': 'File uploaded successfully.'}), 200
#         else:
#             return jsonify({'message': 'Invalid file.'}), 400

#     return render_template('upload.html')

# # Function to check if a file is allowed
# def allowed_file(filename):
#     return '.' in filename and \
#            filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

# # Function to check if a file size is allowed
# def allowed_file_size(file):
#     return file.content_length <= app.config['MAX_CONTENT_LENGTH']

# Implement a protected endpoint that requires a valid JWT token to access
# @app.route('/protected', methods=['GET'])
# @jwt_required()
# def protected():
#     return jsonify({'message': 'You are authorized to access this endpoint.'}), 200


if __name__ == '__main__':
    app.run(debug=True)
