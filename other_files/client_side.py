import requests
import random

BASE_URL = "{{Your Domain Name, ex> https://domain.f5xc.test"
HEADERS = {"Content-Type": "application/json"}

# Generate up to 50 fake public IPs
def generate_fake_ips(count=50):
    return [f"{random.randint(11, 223)}.{random.randint(0, 255)}.{random.randint(0, 255)}.{random.randint(1, 254)}"
            for _ in range(count)]

FAKE_IPS = generate_fake_ips()

# Add X-Forwarded-For with a random IP
def with_random_ip(headers=None):
    if headers is None:
        headers = {}
    headers = headers.copy()
    headers["xff"] = random.choice(FAKE_IPS)
    return headers

# Traffic functions
def test_pii():
    r = requests.get(f"{BASE_URL}/api/v1/pii", headers=with_random_ip())
    print("[/pii]", r.status_code)

def test_user_creation():
    data = {
        "username": f"user{random.randint(100,999)}",
        "email": f"user{random.randint(1000,9999)}@example.com"
    }
    r = requests.post(f"{BASE_URL}/api/v1/users", json=data, headers=with_random_ip(HEADERS))
    print("[/users POST]", r.status_code)

USER_IP_MAP = {
    "1083": "23.111.202.11",
    "1376": "45.63.22.89",
    "1399": "64.227.38.74",
    "1174": "103.86.49.32",
    "1122": "185.193.11.99",
    "1297": "107.172.87.61",
    "1417": "92.205.11.173",
    "1730": "152.228.168.215",
    "1098": "134.209.34.122",
    "1742": "51.159.15.113",
    "1784": "138.68.24.199",
    "1009": "185.121.177.177",
    "1833": "188.166.25.9",
    "1448": "143.244.190.65",
    "1171": "209.141.60.145",
    "1276": "38.91.100.201",
    "1657": "66.42.112.88",
    "1754": "104.248.32.251",
    "1877": "162.243.55.182",
    "1381": "170.64.133.145",
    "1459": "45.55.85.112",
    "1923": "161.35.101.84",
    "1134": "165.227.90.123",
    "1543": "149.28.63.210",
    "1331": "207.154.232.243",
    "1885": "64.225.13.195",
    "1018": "168.119.64.202",
    "1034": "144.76.28.66",
    "1192": "89.58.38.154",
    "1961": "140.82.9.64",
    "1703": "38.242.242.34",
    "1227": "116.202.92.246",
    "1312": "84.17.59.155",
    "1346": "152.67.222.104",
    "1955": "159.223.160.93",
    "1596": "91.134.166.243",
    "1869": "45.80.152.3",
    "1235": "167.99.85.240",
    "1810": "185.198.27.131",
    "1471": "157.245.195.50",
    "1365": "139.59.27.204",
    "1243": "104.248.26.18",
    "1934": "138.197.218.170",
    "1765": "80.240.28.202",
    "1679": "164.90.160.189",
    "1858": "159.89.205.70",
    "1519": "128.199.211.126",
    "1602": "95.216.154.58",
    "1047": "176.58.105.152",
    "1555": "217.160.52.176"
}

FIXED_USER_IDS = list(USER_IP_MAP.keys())

def with_fixed_ip(user_id, headers=None):
    if headers is None:
        headers = {}
    headers = headers.copy()
    headers["xff"] = USER_IP_MAP[user_id]  # no fallback
    return headers

def test_bola():
    print("=== BOLA Testing ===")

    # Unauthorized request
    random_unauth_id = random.choice(FIXED_USER_IDS)
    headers_no_token = with_random_ip()
    r_unauth = requests.get(f"{BASE_URL}/api/v1/users/{random_unauth_id}", headers=headers_no_token)
    print(f"[UNAUTHORIZED] /users/{random_unauth_id} → {r_unauth.status_code}")

    # Authorized requests
    for user_id in FIXED_USER_IDS:
        try:
            r = requests.get(f"{BASE_URL}/generate_token/{user_id}")
            token = r.json()["token"]
            headers_valid = with_fixed_ip(user_id, {"Authorization": f"Bearer {token}"})
            r_valid = requests.get(f"{BASE_URL}/api/v1/users/{user_id}", headers=headers_valid)
            print(f"[AUTHORIZED] /users/{user_id} → {r_valid.status_code}")
        except Exception as e:
            print(f"[ERROR] /users/{user_id} → {e}")

def test_forgot_password():
    data = {"step": 1, "user_number": "6501113434"}
    r = requests.post(f"{BASE_URL}/initiate_forgot_password", json=data, headers=with_random_ip(HEADERS))
    print("[/initiate_forgot_password]", r.status_code)

def test_data_all_cases():
    user_id = random.choice(FIXED_USER_IDS)
    try:
        r = requests.get(f"{BASE_URL}/generate_token/{user_id}")
        token = r.json()["token"]
    except Exception as e:
        print(f"[ERROR] Token gen failed for {user_id}: {e}")
        return

    # No token
    r1 = requests.get(f"{BASE_URL}/api/v1/data", headers=with_random_ip())
    print("[/data GET without token] →", r1.status_code)

    # Invalid token
    headers_invalid = with_random_ip({"Authorization": "Bearer invalidtoken"})
    r2 = requests.get(f"{BASE_URL}/api/v1/data", headers=headers_invalid)
    print("[/data GET with invalid token] →", r2.status_code)

    # Valid token
    headers_valid = with_random_ip({"Authorization": f"Bearer {token}"})
    r3 = requests.get(f"{BASE_URL}/api/v1/data", headers=headers_valid)
    print("[/data GET with valid token] →", r3.status_code)

def test_config_sample():
    r = requests.get(f"{BASE_URL}/api/v1/config/sample", headers=with_random_ip())
    print("[/config/sample]", r.status_code)

def test_userinfo():
    r = requests.get(f"{BASE_URL}/api/v1/userinfo", headers=with_random_ip())
    print("[/userinfo]", r.status_code)

def test_ticket_buy():
    data = {"ticket_type": "Standard", "quantity": random.randint(1, 5)}
    r = requests.post(f"{BASE_URL}/api/v1/tickets/buy", json=data, headers=with_random_ip(HEADERS))
    print("[/tickets/buy]", r.status_code)

    # Reset ticket counter after purchase
    r_reset = requests.post(f"{BASE_URL}/api/v1/tickets/reset", headers=with_random_ip(HEADERS))
    print("[/tickets/reset]", r_reset.status_code)

def test_broken_auth():
    # Valid request
    valid_params = {
        "apikey": "my-valid-api-key",
        "regToken": "my-valid-token"
    }
    r_valid = requests.get(f"{BASE_URL}/api/v1/auth/data", params=valid_params, headers=with_random_ip())
    print("[/auth/data] (valid params) →", r_valid.status_code)

    # Invalid request (missing one or both)
    broken_case = random.choice(["none", "apikey_only", "regtoken_only"])
    if broken_case == "none":
        broken_params = {}
    elif broken_case == "apikey_only":
        broken_params = {"apikey": "my-valid-api-key"}
    else:  # "regtoken_only"
        broken_params = {"regToken": "my-valid-token"}

    r_invalid = requests.get(f"{BASE_URL}/api/v1/auth/data", params=broken_params, headers=with_random_ip())
    print(f"[/auth/data] (missing params - {broken_case}) →", r_invalid.status_code)

def test_ssrf_normal():
    data = {
        "image_url": "https://www.imagetest.com/my/photo.jpg"
    }
    r = requests.post(f"{BASE_URL}/api/v1/profile/picture", json=data, headers=with_random_ip(HEADERS))
    print("[/profile/picture] (normal image URL) →", r.status_code)

def test_shadow_api():
    """Access the undocumented Shadow API endpoint."""
    url = f"{BASE_URL}/internal/api/userdata"
    r = requests.get(url, headers=with_random_ip())
    print("[/internal/api/userdata] (shadow API)", r.status_code)

# === Execute all tests once ===
if __name__ == "__main__":
    test_pii()
    test_user_creation()
    test_bola()
    test_forgot_password()
    test_data_all_cases()
    test_config_sample()
    test_userinfo()
    test_ticket_buy()
    test_broken_auth()
    test_ssrf_normal()
    test_shadow_api()
