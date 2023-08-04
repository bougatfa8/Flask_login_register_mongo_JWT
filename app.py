import time

import db
import json
from flask import Flask, request, render_template, make_response, session, jsonify
import jwt


app = Flask(__name__)



app.config['SECRET_KEY'] = 'maya123'



@app.route('/', methods = ['GET', 'POST'])
def home():
    return render_template("signin.html")


@app.route('/signup', methods = ['GET', 'POST'])
def signup():
    return render_template("signup.html")



@app.route('/signin', methods = ['GET', 'POST'])
def signin():
    status, username = db.check_user()
    data = {
        "username": username,
        "status": status
    }

    if status == True:
        print(status)

        expiration_time = int(time.time()) + 1800  # 1800 seconds = 30 minutes

        # Create the payload with the 'exp' claim
        payload = {'username': username, 'exp': expiration_time}


        # Encode the payload to create the token
        token = jwt.encode(payload, app.config['SECRET_KEY'])

        print(token)

        # Store the token in the session cookie
        session['token'] = token

        return json.dumps(data)

    else:

        return json.dumps(data)



@app.route('/protected', methods=['GET'])
def protected():
    # Get the token from the session
    token = session.get('token')

    if not token:
        return jsonify(message='Missing token'), 401

    try:
        # Verify the token with the secret key to check if it's valid and not expired
        payload = jwt.decode(token, app.config['SECRET_KEY'], algorithms=['HS256'])

        # Check if the token is expired (by verifying the 'exp' claim)
        current_time = int(time.time())

        if 'exp' in payload and payload['exp'] < current_time:
            return jsonify(message='Expired token'), 401

        return jsonify(message='Valid token'), 200

    except jwt.ExpiredSignatureError:
        return jsonify(message='Expired token'), 401

    except jwt.InvalidTokenError:
        return jsonify(message='Invalid token'), 401


if __name__ == '__main__':
    app.run(debug = True)
