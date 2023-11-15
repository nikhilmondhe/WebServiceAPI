from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from flask_restful import Api
from flask_jwt_extended import JWTManager
from datetime import datetime
from sqlalchemy.ext.hybrid import hybrid_property
from flask_restful import Resource, reqparse
from flask_jwt_extended import create_access_token, jwt_required, get_jwt_identity

app = Flask(__name__)
api = Api(app)
bcrypt = Bcrypt(app)
app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql+pymysql://root:admin@localhost/mydatabase'
app.config['JWT_SECRET_KEY'] = 'Nikhil@23'
db = SQLAlchemy(app)
jwt = JWTManager(app)

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(80), nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    _password = db.Column('password', db.String(100), nullable=False)
    last_login = db.Column(db.DateTime, nullable=True)

    @hybrid_property
    def password(self):
        return self._password

    @password.setter
    def password(self, plaintext_password):
        self._password = bcrypt.generate_password_hash(plaintext_password).decode('utf-8')

parser = reqparse.RequestParser()
parser.add_argument('name', required=True, help='Name cannot be blank.')
parser.add_argument('email', required=True, help='Email cannot be blank.')
parser.add_argument('password', required=True, help='Password cannot be blank.')

class UserResource(Resource):
    def post(self):  # Create a new user
        data = parser.parse_args()
        if User.query.filter_by(email=data['email']).first():
            return {'message': 'User with that email already exists'}, 400
        user = User(name=data['name'], email=data['email'], password=data['password'])
        db.session.add(user)
        db.session.commit()
        return {'message': 'User created'}, 201

    @jwt_required()
    def get(self):  # Get a single user's details
        current_user = get_jwt_identity()
        user = User.query.get(current_user)
        if not user:
            return {'message': 'User not found'}, 404
        return {
            'name': user.name,
            'email': user.email,
            #'last_login': user.last_login
            'last_login': user.last_login.isoformat() if user.last_login else None
        }, 200

    @jwt_required()
    def put(self):  # Update a user's details 
        current_user = get_jwt_identity()
        user = User.query.get(current_user)
        if not user:
            return {'message': 'User not found'}, 404

        data = parser.parse_args()
        user.name = data['name']
        user.email = data['email']  # Be careful with changing email since it's a unique field.
        if data['password']:  # Only update the password if it's provided.
            user.password = data['password']
        db.session.commit()

        return {'message': 'User updated successfully'}, 200
    
    @jwt_required()
    def delete(self):  # Delete a user
        current_user = get_jwt_identity()
        user = User.query.get(current_user)
        if not user:
            return {'message': 'User not found'}, 404

        db.session.delete(user)
        db.session.commit()

        return {'message': 'User deleted successfully'}, 200


api.add_resource(UserResource, '/user')

class UserListResource(Resource):
    def get(self):  # List all users
        users = User.query.all()
        return [{
            'id': user.id,
            'name': user.name,
            'email': user.email,
            #'last_login': user.last_login
            'last_login': user.last_login.isoformat() if user.last_login else None
        } for user in users], 200

api.add_resource(UserListResource, '/users')

class UserLogin(Resource):
    def post(self):
        data = parser.parse_args()
        user = User.query.filter_by(email=data['email']).first()
        if user and bcrypt.check_password_hash(user.password, data['password']):
            user.last_login = datetime.utcnow()
            db.session.commit()
            access_token = create_access_token(identity=user.id)
            return {'access_token': access_token}, 200
        else:
            return {'message': 'Invalid credentials'}, 401

api.add_resource(UserLogin, '/login')

def setup_database(app):
    with app.app_context():
        db.create_all()  # This creates the tables

if __name__ == '__main__':
    setup_database(app)
    app.run(debug=True)
