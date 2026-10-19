import sys
import jwt
import requests
from jwt.exceptions import PyJWTError

def audit_jwt(token):
    print("\n[+] === JWT SECURITY AUDIT ===")
    
    # 1. Decode without verification to inspect headers and payload
    try:
        unverified_header = jwt.get_unverified_header(token)
        unverified_payload = jwt.decode(token, options={"verify_signature": False})
        
        print(f"    -> Algorithm Used: {unverified_header.get('alg')}")
        print(f"    -> Token Payload: {unverified_payload}")
    except Exception as e:
        print(f"[-] Error decoding token: {e}")
        return

    # VULN CHECK 1: 'alg: none' vulnerability
    alg = unverified_header.get("alg", "").lower()
    if alg == "none":
        print("[!] CRITICAL VULNERABILITY: Token uses 'alg: none'. Server may accept unsigned tokens!")
    elif alg in ["hs256", "hs384", "hs512"]:
        print("[*] Info: Symmetric signing algorithm detected (HMAC). Testing for weak secrets...")
        
        # VULN CHECK 2: Weak Secret Brute-Force (Common defaults)
        common_secrets = ["secret", "password", "123456", "admin", "jwt_secret", "supersecret"]
        cracked = False
        for secret in common_secrets:
            try:
                jwt.decode(token, secret, algorithms=[unverified_header.get('alg')])
                print(f"[!] HIGH VULNERABILITY: Weak secret found! Secret is: '{secret}'")
                cracked = True
                break
            except PyJWTError:
                continue
        if not cracked:
            print("[+] Secure: No common weak secrets matched.")

def audit_api_headers(url):
    print(f"\n[+] === API ENDPOINT SECURITY HEADERS: {url} ===")
    try:
        response = requests.get(url, timeout=5)
        headers = response.headers
        
        security_headers = {
            "Content-Security-Policy": "Missing CSP leaves app vulnerable to XSS.",
            "Strict-Transport-Security": "Missing HSTS allows protocol downgrade attacks.",
            "X-Content-Type-Options": "Missing nosniff header allows MIME-sniffing exploits.",
            "X-Frame-Options": "Missing framing protection allows Clickjacking."
        }
        
        for header, warning in security_headers.items():
            if header in headers:
                print(f"    [✔] {header}: Present")
            else:
                print(f"    [✘] {header}: ABSENT! -> {warning}")
                
    except requests.exceptions.RequestException as e:
        print(f"[-] Could not connect to target URL: {e}")

if __name__ == "__main__":
    print("[*] TokenAudit Engine Initialized.")
    
    # Example test JWT signed with 'secret' (HMAC-SHA256)
    # Payload: {"user": "admin", "role": "operator"}
    test_token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VyIjoiYWRtaW4iLCJyb2xlIjoib3BlcmF0b3IifQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
    
    audit_jwt(test_token)
    
    # Test an API endpoint (e.g., example.com)
    target_url = sys.argv[1] if len(sys.argv) > 1 else "https://example.com"
    audit_api_headers(target_url)
