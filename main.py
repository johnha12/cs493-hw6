from flask import Flask, request, jsonify
from google.cloud import datastore

import requests
import json

from six.moves.urllib.request import urlopen
from jose import jwt
from authlib.integrations.flask_client import OAuth

#Username-Password-Authentication

BUSINESSES ='businesses'
ERROR_NOT_FOUND = {"Error": "No business with this business_id exists"}
REVIEWS = 'reviews'

app = Flask(__name__)
app.secret_key = 'SECRET_KEY'

client = datastore.Client(project='hajo-hw6')

LODGINGS = "lodgings"

# Update the values of the following 3 variables
CLIENT_ID = 'eYxghLk6pW4qDlHwzUhF8GP7CTMFPTKa'
CLIENT_SECRET = 'ijPq0gQ60SFv2hUWihBp9U0eHwkDFSIR-fdQooJuH_LFXBJDy674xODiUdS_XSJr'
DOMAIN = 'dev-hlfdspycgpeh642t.us.auth0.com'
# For example
# DOMAIN = '493-24-spring.us.auth0.com'
# Note: don't include the protocol in the value of the variable DOMAIN

ALGORITHMS = ["RS256"]

oauth = OAuth(app)

auth0 = oauth.register(
    'auth0',
    client_id=CLIENT_ID,
    client_secret=CLIENT_SECRET,
    api_base_url="https://" + DOMAIN,
    access_token_url="https://" + DOMAIN + "/oauth/token",
    authorize_url="https://" + DOMAIN + "/authorize",
    client_kwargs={
        'scope': 'openid profile email',
    },
)

# This code is adapted from https://auth0.com/docs/quickstart/backend/python/01-authorization?_ga=2.46956069.349333901.1589042886-466012638.1589042885#create-the-jwt-validation-decorator

class AuthError(Exception):
    def __init__(self, error, status_code):
        self.error = error
        self.status_code = status_code


@app.errorhandler(AuthError)
def handle_auth_error(ex):
    response = jsonify(ex.error)
    response.status_code = ex.status_code
    return response

# Verify the JWT in the request's Authorization header
def verify_jwt(request):
    if 'Authorization' in request.headers:
        auth_header = request.headers['Authorization'].split()
        token = auth_header[1]
    else:
        raise AuthError({"code": "no auth header",
                            "description":
                                "Authorization header is missing"}, 401)
    
    jsonurl = urlopen("https://"+ DOMAIN+"/.well-known/jwks.json")
    jwks = json.loads(jsonurl.read())
    try:
        unverified_header = jwt.get_unverified_header(token)
    except jwt.JWTError:
        raise AuthError({"code": "invalid_header",
                        "Error":
                            "Unauthorized"}, 401)
                            
    if unverified_header["alg"] == "HS256":
        raise AuthError({"code": "invalid_header",
                        "description":
                            "Unauthorized"}, 401)
    rsa_key = {}
    for key in jwks["keys"]:
        if key["kid"] == unverified_header["kid"]:
            rsa_key = {
                "kty": key["kty"],
                "kid": key["kid"],
                "use": key["use"],
                "n": key["n"],
                "e": key["e"]
            }
    if rsa_key:
        try:
            payload = jwt.decode(
                token,
                rsa_key,
                algorithms=ALGORITHMS,
                audience=CLIENT_ID,
                issuer="https://"+ DOMAIN+"/"
            )
        except jwt.ExpiredSignatureError:
            raise AuthError({"code": "token_expired",
                            "description": "token is expired"}, 401)
        except jwt.JWTClaimsError:
            raise AuthError({"code": "invalid_claims",
                            "description":
                                "incorrect claims,"
                                " please check the audience and issuer"}, 401)
        except Exception:
            raise AuthError({"code": "invalid_header",
                            "description":
                                "Unable to parse authentication"
                                " token."}, 401)

        return payload
    else:
        raise AuthError({"code": "no_rsa_key",
                            "description":
                                "No RSA key in JWKS"}, 401)


@app.route('/')
def index():
    return "Please navigate to /lodgings to use this API"\

# Create a lodging if the Authorization header contains a valid JWT
@app.route('/lodgings', methods=['POST'])
def lodgings_post():
    if request.method == 'POST':
        payload = verify_jwt(request)
        content = request.get_json()
        new_lodging = datastore.entity.Entity(key=client.key(LODGINGS))
        new_lodging.update({"name": content["name"], "description": content["description"],
          "price": content["price"]})
        client.put(new_lodging)
        return jsonify(id=new_lodging.key.id)
    else:
        return jsonify(error='Method not recogonized')

# Decode the JWT supplied in the Authorization header
@app.route('/decode', methods=['GET'])
def decode_jwt():
    payload = verify_jwt(request)
    return payload          
        

# Generate a JWT from the Auth0 domain and return it
# Request: JSON body with 2 properties with "username" and "password"
#       of a user registered with this Auth0 domain
# Response: JSON with the JWT as the value of the property id_token
@app.route('/users/login', methods=['POST'])
def login_user():
    content = request.get_json()
    
    # Validate request body
    if 'username' not in content or 'password' not in content:
        return jsonify({"Error": "The request body is invalid"}), 400

    username = content["username"]
    password = content["password"]
    
    # Create the body for Auth0 request
    body = {
        'grant_type': 'password',
        'username': username,
        'password': password,
        'client_id': CLIENT_ID,
        'client_secret': CLIENT_SECRET,
        'scope': 'openid'  # Ensure 'openid' scope to get id_token
    }
    headers = {'content-type': 'application/json'}
    url = f'https://{DOMAIN}/oauth/token'
    
    # Send request to Auth0
    r = requests.post(url, json=body, headers=headers)
    
    if r.status_code == 200:
        # Extract the id_token from the response
        token_response = r.json()
        id_token = token_response.get("id_token")

        if id_token:
            return jsonify({"token": id_token}), 200
        else:
            return jsonify({"Error": "No id_token in response"}), 500
    # elif r.status_code == 401:
    #     return jsonify({"Error": "Username and/or password is incorrect"}), 401
    else:
        return jsonify({"Error": "Unauthorized"}), 401

# Everything above this line can be reused for Assignment 6
@app.route('/users', methods=['GET'])
def get_users():
    payload = verify_jwt(request)
    # print(payload)

    # Need to check datastore with payload['sub']
    user_sub = payload.get('sub')
    
    if not user_sub:
        raise AuthError({"code": "invalid_payload", "Error": "Unauthorized"}, 401)

    # Query the datastore to fetch the user with the given 'sub'
    query = client.query(kind='users')
    query.add_filter('sub', '=', user_sub)
    user_results = list(query.fetch())

    # Check if the user exists and has the role of 'admin'
    if len(user_results) == 0 or user_results[0]['role'] != 'admin':
        raise AuthError({"code": "unauthorized", "Error": "You don't have permission on this resource"}, 403)
    

    users_query = client.query(kind='users')
    users = list(users_query.fetch())
    response = [{'id': user.key.id, 'role': user['role'], 'sub': user['sub']} for user in users]
    return jsonify(response), 200

@app.route("/" + BUSINESSES, methods=['POST'])
def post_businesses():
    content = request.get_json()

    # Check if all required fields are present
    required_fields = ['name', 'street_address', 'city', 'state', 'zip_code', 'inspection_score']
    missing_fields = [field for field in required_fields if field not in content] # Get any field that is missing
    if missing_fields:
        return ({"Error": "The request body is missing at least one of the required attributes"}), 400

    # Verify JWT
    payload = verify_jwt(request)

    new_key = client.key(BUSINESSES)
    new_business = datastore.Entity(key=new_key)
    new_business.update({
        "owner_id": payload['sub'],  # Getting owner_id from token
        "name": content['name'],
        "street_address": content['street_address'],
        "city": content['city'],
        "state": content['state'],
        "zip_code": int(content['zip_code']),
        "inspection_score": int(content['inspection_score'])
    })

    client.put(new_business)
    new_business['id'] = new_business.key.id
    # Add self root url
    new_business['self'] = request.url_root + BUSINESSES + '/' + str(new_business.key.id)

    return jsonify(new_business), 201

@app.route("/businesses/<business_id>", methods=['GET'])
def get_business(business_id):

    # Start by checking failures, wrong token, wrong person, exist or not
    try:
        payload = verify_jwt(request)  # Verify JWT and get payload
    except AuthError as e:
        return jsonify({"Error": "Invalid or missing JWT"}), 401

    # Retrieve the business from Datastore
    business_key = client.key(BUSINESSES, int(business_id))
    business = client.get(key=business_key)

    if business is None:
        return jsonify({"Error": "No business with this business_id exists"}), 403

    # Check if owner_id in business matches sub claim in the JWT
    if business['owner_id'] != payload['sub']:
        return jsonify({"Error": "No business with this business_id exists"}), 403
        # return jsonify({"Error": "The JWT does not belong to the owner of this business"}), 403

    # Add self link
    business['id'] = business.key.id
    business['self'] = request.url_root + 'businesses/' + str(business.key.id)

    return jsonify(business), 200

# List businesses, depend on validity of JWT
# Always array
# Valid JWT, then all businesses/properties of owner
# No JWT, then all businesses/properties return EXCEPT inspection_score property

@app.route("/businesses", methods=['GET'])
def get_businesses():
    # Set up array with verified JWT owner
    try:
        payload = verify_jwt(request)  # Verify JWT
        owner_id = payload['sub']   # Get payload
        query = client.query(kind=BUSINESSES)
        query.add_filter('owner_id', '=', owner_id)
        businesses = list(query.fetch())
    # If JWT is invalid or not provided, return all businesses without inspection_score
    except AuthError as e:
        query = client.query(kind=BUSINESSES)
        businesses = list(query.fetch())
        for business in businesses:
            business.pop('inspection_score', None)  # Remove inspection_score

    # Add self link to each business
    for business in businesses:
        business['id'] = business.key.id
        business['self'] = request.url_root + 'businesses/' + str(business.key.id)

    # return final array
    return jsonify(businesses), 200

@app.route("/businesses/<business_id>", methods=['DELETE'])
def delete_business(business_id):
    try:
        # Verify JWT and get payload
        payload = verify_jwt(request)
        owner_id = payload['sub']  # Get owner ID from payload sub

        # Retrieve the business entity from Datastore
        business_key = client.key(BUSINESSES, int(business_id))
        business = client.get(key=business_key)

        if not business:
            # No business exists with the given ID
            return jsonify({"Error": "No business with this business_id exists"}), 403

        if business['owner_id'] != owner_id:
            # JWT of another owner
            return jsonify({"Error": "You are not authorized to delete this business"}), 403

        # Finally ready to delete
        client.delete(business_key)
        return '', 204

    except AuthError as e:
        # If cannot verify JWT, will trigger regardless of incorrect business id
        return jsonify(e.error), e.status_code # status 401

    except Exception as e:
        # System error
        return jsonify({"Error": "An error occurred while attempting to delete the business"}), 500



if __name__ == '__main__':
    app.run(host='127.0.0.1', port=8080, debug=True)

