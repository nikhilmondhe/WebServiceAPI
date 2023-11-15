
# Flask User Management API

## Introduction
This Flask application provides a basic backend for user management. It includes functionalities like user registration, authentication, profile updates, and deletion. The application uses Flask-SQLAlchemy for database interactions, Flask-Bcrypt for password hashing, and Flask-JWT-Extended for JWT handling.

## Features
- User registration and management.
- Secure password handling with bcrypt.
- JWT-based authentication.
- CRUD operations for user data.

## Requirements
- Flask
- Flask-SQLAlchemy
- Flask-Bcrypt
- Flask-Restful
- Flask-JWT-Extended
- PyMySQL

## Installation
1. Clone the repository to your local machine.
2. Install the required packages:
   ```bash
   pip install Flask Flask-SQLAlchemy Flask-Bcrypt Flask-Restful Flask-JWT-Extended PyMySQL
   ```
3. Configure your database settings in `app.config['SQLALCHEMY_DATABASE_URI']`.

## Database Setup
Run the `setup_database` function to initialize the database:
```python
setup_database(app)
```

## Running the Application
Execute the following command to start the application:
```bash
python [your-script-name].py
```

## Endpoints
- **/user**: User registration, details retrieval, updating, and deletion.
- **/users**: List all users.
- **/login**: User authentication and token generation.

## Usage
- **Register** a new user: POST to `/user` with `name`, `email`, and `password`.
- **Retrieve** user details: GET to `/user` with a valid JWT.
- **Update** user details: PUT to `/user` with updated fields and a valid JWT.
- **Delete** a user: DELETE to `/user` with a valid JWT.
- **List all users**: GET to `/users`.
- **User authentication**: POST to `/login` with `email` and `password`.

## Security
- Secure your database credentials.
- Validate and sanitize user inputs.

## License
[Your License Here]
