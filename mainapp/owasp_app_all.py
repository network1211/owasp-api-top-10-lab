from flask import Flask, request, jsonify, send_from_directory
import jwt
import datetime
import os
from jwt.exceptions import InvalidTokenError
from flask_swagger_ui import get_swaggerui_blueprint
from jwcrypto import jwk
import uuid

app = Flask(__name__)

# ========== Static Setup ==========
SWAGGER_URL = '/swagger'
API_URL = '/static/swagger.json'
swaggerui_blueprint = get_swaggerui_blueprint(
    SWAGGER_URL,
    API_URL,
    config={ 'app_name': "OWASP API Vulnerabilities Combined App" }
)
app.register_blueprint(swaggerui_blueprint, url_prefix=SWAGGER_URL)

# ========== JWT Key Setup ==========
with open('private.pem', 'r') as f:
    PRIVATE_KEY = f.read()

with open('public.pem', 'r') as f:
    PUBLIC_KEY = f.read()

USERS = {
    "user1": {"username": "user1", "group": "user"},
    "admin1": {"username": "admin1", "group": "admin"},
    "1083": {"username": "user1083", "email": "user1083@example.com", "group": "user"},
    "1376": {"username": "user1376", "email": "user1376@example.com", "group": "user"},
    "1399": {"username": "user1399", "email": "user1399@example.com", "group": "user"},
    "1174": {"username": "user1174", "email": "user1174@example.com", "group": "user"},
    "1122": {"username": "user1122", "email": "user1122@example.com", "group": "user"},
    "1297": {"username": "user1297", "email": "user1297@example.com", "group": "user"},
    "1417": {"username": "user1417", "email": "user1417@example.com", "group": "user"},
    "1730": {"username": "user1730", "email": "user1730@example.com", "group": "user"},
    "1098": {"username": "user1098", "email": "user1098@example.com", "group": "user"},
    "1742": {"username": "user1742", "email": "user1742@example.com", "group": "user"},
    "1784": {"username": "user1784", "email": "user1784@example.com", "group": "user"},
    "1009": {"username": "user1009", "email": "user1009@example.com", "group": "user"},
    "1833": {"username": "user1833", "email": "user1833@example.com", "group": "user"},
    "1448": {"username": "user1448", "email": "user1448@example.com", "group": "user"},
    "1171": {"username": "user1171", "email": "user1171@example.com", "group": "user"},
    "1276": {"username": "user1276", "email": "user1276@example.com", "group": "user"},
    "1657": {"username": "user1657", "email": "user1657@example.com", "group": "user"},
    "1754": {"username": "user1754", "email": "user1754@example.com", "group": "user"},
    "1877": {"username": "user1877", "email": "user1877@example.com", "group": "user"},
    "1381": {"username": "user1381", "email": "user1381@example.com", "group": "user"},
    "1459": {"username": "user1459", "email": "user1459@example.com", "group": "user"},
    "1923": {"username": "user1923", "email": "user1923@example.com", "group": "user"},
    "1134": {"username": "user1134", "email": "user1134@example.com", "group": "user"},
    "1543": {"username": "user1543", "email": "user1543@example.com", "group": "user"},
    "1331": {"username": "user1331", "email": "user1331@example.com", "group": "user"},
    "1885": {"username": "user1885", "email": "user1885@example.com", "group": "user"},
    "1018": {"username": "user1018", "email": "user1018@example.com", "group": "user"},
    "1034": {"username": "user1034", "email": "user1034@example.com", "group": "user"},
    "1192": {"username": "user1192", "email": "user1192@example.com", "group": "user"},
    "1961": {"username": "user1961", "email": "user1961@example.com", "group": "user"},
    "1703": {"username": "user1703", "email": "user1703@example.com", "group": "user"},
    "1227": {"username": "user1227", "email": "user1227@example.com", "group": "user"},
    "1312": {"username": "user1312", "email": "user1312@example.com", "group": "user"},
    "1346": {"username": "user1346", "email": "user1346@example.com", "group": "user"},
    "1955": {"username": "user1955", "email": "user1955@example.com", "group": "user"},
    "1596": {"username": "user1596", "email": "user1596@example.com", "group": "user"},
    "1869": {"username": "user1869", "email": "user1869@example.com", "group": "user"},
    "1235": {"username": "user1235", "email": "user1235@example.com", "group": "user"},
    "1810": {"username": "user1810", "email": "user1810@example.com", "group": "user"},
    "1471": {"username": "user1471", "email": "user1471@example.com", "group": "user"},
    "1365": {"username": "user1365", "email": "user1365@example.com", "group": "user"},
    "1243": {"username": "user1243", "email": "user1243@example.com", "group": "user"},
    "1934": {"username": "user1934", "email": "user1934@example.com", "group": "user"},
    "1765": {"username": "user1765", "email": "user1765@example.com", "group": "user"},
    "1679": {"username": "user1679", "email": "user1679@example.com", "group": "user"},
    "1858": {"username": "user1858", "email": "user1858@example.com", "group": "user"},
    "1519": {"username": "user1519", "email": "user1519@example.com", "group": "user"},
    "1602": {"username": "user1602", "email": "user1602@example.com", "group": "user"},
    "1047": {"username": "user1047", "email": "user1047@example.com", "group": "user"},
    "1555": {"username": "user1555", "email": "user1555@example.com", "group": "user"}
}

# ========== JWKS URL =========
@app.route('/.well-known/jwks.json', methods=['GET'])
def jwks():
    key = jwk.JWK.from_pem(PUBLIC_KEY.encode())
    return jsonify({
        "keys": [key.export(as_dict=True)]
    })

# ========== 1. BOLA ==========
@app.route('/api/v1/users/<user_id>', methods=['GET'])
def get_user(user_id):
    auth_header = request.headers.get('Authorization', '')
    if not auth_header.startswith('Bearer '):
        return jsonify({"error": "Missing Authorization header"}), 401

    token = auth_header.replace('Bearer ', '')

    try:
        jwt.decode(token, PUBLIC_KEY, algorithms=['RS256'])
    except InvalidTokenError:
        return jsonify({"error": "Invalid or expired token"}), 401
    except Exception:
        return jsonify({"error": "Malformed or missing token"}), 401

    user = USERS.get(user_id)
    if user:
        return jsonify(user)
    return jsonify({"error": "User not found"}), 404

# ========== 2. Broken Authentication ==========
@app.route('/api/v1/auth/data', methods=['GET'])
def api_key_auth():
    if request.args.get('apikey') and request.args.get('regToken'):
        return jsonify({"data": "Authenticated via API key and regToken"})
    return jsonify({"error": "Missing API key or token"}), 401

@app.route('/api/v1/jwt/data', methods=['GET'])
def broken_jwt():
    auth = request.headers.get('Authorization', '')
    if not auth.startswith('Bearer '):
        return jsonify({"error": "No Bearer token"}), 401
    token = auth.split()[1]
    try:
        decoded = jwt.decode(token, options={"verify_signature": False})
        return jsonify({"message": "JWT accepted", "token_data": decoded})
    except Exception as e:
        return jsonify({"error": str(e)}), 400

# ========== 3. BOPLA ==========
@app.route('/api/v1/pii', methods=['GET'])
def pii_exposure():
    return jsonify({"ssn": "123-45-6789", "dob": "1990-01-01"})

@app.route('/api/v1/users', methods=['POST'])
def mass_assignment():
    data = request.get_json()
    return jsonify({"user": data}), 201 

# ========== 4. Unrestricted Resource Consumption ==========
@app.route('/initiate_forgot_password', methods=['POST'])
def resource_consumption():
    user_number = request.get_json().get("user_number")
    return jsonify({
        "reset_sms": "POST /sms/send_reset_pass_code",
        "Host": "willyo.net",
        "phone_number": user_number,
        "cost_charge": "$0.05"
    })

# ========== 5. BFLA ==========
@app.route('/api/v1/data', methods=['GET', 'POST'])
def secured_data():
    auth_header = request.headers.get('Authorization', '')
    if not auth_header.startswith('Bearer '):
        return jsonify({"error": "Missing or invalid Authorization header"}), 401

    token = auth_header.replace('Bearer ', '')

    try:
        decoded = jwt.decode(token, PUBLIC_KEY, algorithms=['RS256'])
        # No role/group enforcement — intentionally vulnerable to BFLA
        return jsonify({
            "user": decoded['sub'],
            "group": decoded['group'],
            "method": request.method
        })

    except InvalidTokenError as e:
        return jsonify({"error": f"Invalid token: {str(e)}"}), 401
    except Exception as e:
        return jsonify({"error": "Malformed or missing JWT"}), 401

@app.route('/generate_token/<username>', methods=['GET'])
def generate_token(username):
    user = USERS.get(username)
    if not user:
        return jsonify({"error": "Invalid user"}), 404

    now = datetime.datetime.utcnow()
    expiration = now + datetime.timedelta(days=30)

    payload = {
        "sub": user["username"],
        "jti": str(uuid.uuid4()),                        # Generate unique token ID
        "iat": now,
        "exp": expiration,
        "nbf": now,
        "group": user.get("group", "user")               # Optional group claim
    }

    token = jwt.encode(payload, PRIVATE_KEY, algorithm='RS256')
    return jsonify({"token": token})

# ========== 6. Business Logic Abuse ==========
tickets_remaining = 100

@app.route('/api/v1/tickets/buy', methods=['POST'])
def ticket_buy():
    global tickets_remaining
    req = request.get_json()
    qty = int(req.get('quantity', 1))
    if tickets_remaining <= 0:
        return jsonify({"message": "All tickets are sold out"}), 403
    qty = min(qty, tickets_remaining)
    tickets_remaining -= qty
    return jsonify({"message": f"Bought {qty} tickets", "left": tickets_remaining})

@app.route('/api/v1/tickets/reset', methods=['POST'])
def reset_tickets():
    global tickets_remaining
    tickets_remaining = 100
    return jsonify({"message": "Tickets have been reset", "total": tickets_remaining}), 200

# ========== 7. SSRF ==========
@app.route('/api/v1/profile/picture', methods=['POST'])
def profile_picture():
    url = request.get_json().get('image_url')
    if url in ['/etc/passwd', 'file:///etc/passwd']:
        return jsonify({"content": "root:x:0:0:root:/root:/bin/bash\n..."})
    return jsonify({"message": "Image set", "url": url})

# ========== 8. Misconfig (CORS *) ==========
@app.route('/api/v1/config/sample', methods=['GET'])
def config_sample():
    resp = jsonify({"message": "Weak CORS"})
    resp.headers['Access-Control-Allow-Origin'] = '*'
    return resp

# ========== 9. Shadow API (NOT documented) ==========
@app.route('/internal/api/userdata', methods=['GET'])
def shadow_api():
    return jsonify({"credit_card": "4111 1111 1111 1111", "dob": "1991-01-01"})

# ========== 10. Unsafe Consumption ==========
@app.route('/api/v1/userinfo', methods=['GET'])
def unsafe_consume():
    if request.headers.get('X-UCA') == 'Malicious':
        return jsonify({"payload": "<script>alert('XSS')</script> OR 1=1"})
    return jsonify({"name": "John", "email": "john@example.com", "phone": "+1-555-123-4567"})

# ========== Static Swagger Download ==========
@app.route('/swagger/download', methods=['GET'])
def download_swagger():
    return send_from_directory('static', 'swagger.json', as_attachment=True)

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5003, debug=True)