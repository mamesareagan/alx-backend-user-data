# 0x02. Session authentication

## Tasks

### 0. Et moi et moi et moi!

+ Copy all your work of the 0x06. Basic authentication project in this new folder.

### 1. Empty session

+ Create a class SessionAuth that inherits from Auth. For the moment this class will be empty. It’s the first step for creating a new authentication mechanism:

### 2. Create a session

+ Update SessionAuth class:

### 3. User ID for Session ID

+ Create an instance method def user_id_for_session_id(self, session_id: str = None) -> str: that returns a User ID based on a Session ID:

### 4. Session cookie

+ Update api/v1/auth/auth.py by adding the method def session_cookie(self, request=None): that returns a cookie value from a request:

### 5. Before request

+ Update the @app.before_request method in api/v1/app.py:

### 6. Use Session ID for identifying a User

+ Create an instance method def current_user(self, request=None): (overload) that returns a User instance based on a cookie value:

### 7. New view for Session Authentication

+ Create a new Flask view that handles all routes for the Session authentication.

### 8. Logout

+ Update the class SessionAuth by adding a new method def destroy_session(self, request=None): that deletes the user session / logout:

### 9. Expiration?

+ Create a class SessionExpAuth that inherits from SessionAuth in the file api/v1/auth/session_exp_auth.py:

### 10. Sessions in database

+ Create a new model UserSession in models/user_session.py that inherits from Base: