#!/usr/bin/env python3
import sys
import json
import argparse
import jwt
import requests
from datetime import datetime
from jwt.exceptions import PyJWTError

def audit_jwt(token):
    report = {"algorithm": None, "payload": None, "vulnerabilities": []}
    print("\n[+] === JWT SECURITY AUDIT ===")
    
    try:
        unverified_header = jwt.get_unverified_header(token)
        unverified_payload = jwt.decode(token, options={"verify_signature": False})
        
        alg = unverified_header.get("alg")
        report["algorithm"] = alg
        report["payload"] = unverified_payload
        
        print(f"    -> Algorithm Used: {alg}")
        print(f"    -> Token Payload: {unverified_payload}")
        
        # Check Expiration Claim (exp)
        if "exp" in unverified_payload:
            exp_timestamp = unverified_payload["exp"]
            exp_date = datetime.fromtimestamp(exp_timestamp)
            current_date = datetime.now()
            if current_date > exp_date:
                print("    [!] WARNING: Token is EXPIRED!")
                report["vulnerabilities"].append("Token is expired but may still be accepted if server skips verification.")
            else:
                print(f"    [✔] Token expiration: Valid until {exp_date}")

    except Exception as e:
        print(f"[-] Error decoding token: {e}")
        return report

    # VULN CHECK 1: 'alg: none' vulnerability
    alg = unverified_header.get("alg", "").lower()
    if alg == "none":
        msg = "CRITICAL: Token uses 'alg: none'. Server may accept unsigned tokens!"
        print(f"[!] {msg}")
        report["vulnerabilities"].append(msg)
    elif alg in ["hs256", "hs384", "hs512"]:
        print("[*] Info: Symmetric signing algorithm detected (HMAC). Testing for weak secrets...")
        
        common_secrets = ["secret", "password", "123456", "admin", "jwt_secret", "supersecret", "key"]
        cracked = False
        for secret in common_secrets:
            try:
                jwt.decode(token, secret, algorithms=[unverified_header.get('alg')])
                msg = f"HIGH: Weak secret found! Secret is: '{secret}'"
                print(f"[!] {msg}")
                report["vulnerabilities"].append(msg)
                cracked = True
                break
            except PyJWTError:
                continue
        if not cracked:
            print("[+] Secure: No common weak secrets matched.")
            
    return report

def audit_api_headers(url):
    report = {"target_url": url, "headers_status": {}}
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
                report["headers_status"][header] = "Present"
            else:
                print(f"    [✘] {header}: ABSENT! -> {warning}")
                report["headers_status"][header] = "Absent"
                
    except requests.exceptions.RequestException as e:
        print(f"[-] Could not connect to target URL: {e}")
        report["error"] = str(e)
        
    return report

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="TokenAudit: Automated API & JWT Security Auditor")
    parser.add_argument("-u", "--url", help="Target API endpoint URL to check headers", default="https://example.com")
    parser.add_argument("-t", "--token", help="JWT token string to audit", default="eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VyIjoiYWRtaW4iLCJyb2xlIjoib3BlcmF0b3IifQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c")
    parser.add_argument("-o", "--output", help="Save report to a JSON file", default=None)
    
    args = parser.parse_args()
    
    print("[*] TokenAudit Engine v2.0 Initialized.")
    
    jwt_report = audit_jwt(args.token)
    api_report = audit_api_headers(args.url)
    
    if args.output:
        full_report = {"jwt_audit": jwt_report, "api_audit": api_report}
        with open(args.output, "w") as f:
            json.dump(full_report, f, indent=4)
        print(f"\n[+] Report successfully saved to {args.output}")
