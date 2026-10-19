# TokenAudit

**TokenAudit** is a lightweight, Python-based Application Security auditing tool designed to detect JSON Web Token (JWT) misconfigurations and evaluate API endpoint security headers.

# Example Output
This tool was ran towards the popular vulnerable bank application, vulnbank built by @commando_skipzz

<img width="1366" height="726" alt="VULNBANKAUDIT" src="https://github.com/user-attachments/assets/604e16fc-92ce-4b03-91a3-757702cf3e4b" />


## Features
- **JWT Signature Verification Checks**: Identifies insecure `alg: none` header settings.
- **Weak Secret Detection**: Brute-forces symmetric HMAC-SHA256 (`HS256`) signatures against common weak secrets.
- **API Security Header Analysis**: Scans target endpoints for critical missing headers (`CSP`, `HSTS`, `X-Frame-Options`, `X-Content-Type-Options`).

## Installation

1. **Clone the repository:**
   ```bash
   git clone [https://github.com/YOUR_USERNAME/tokenaudit.git]
   cd tokenaudit

   Set up a virtual environment:
    Bash

    python3 -m venv venv
    source venv/bin/activate

    Install dependencies:
    Bash

    pip install -r requirements.txt

Usage

Run the auditor against a target API endpoint:
Bash

python3 auditor.py [https://example.com](https://example.com)

Security Disclaimer

This tool is intended strictly for educational and authorized security auditing purposes.


---

### **3. Initialize and Push to GitHub**

Once your files are ready, run these commands in your terminal to initialize Git, commit everything, and push to GitHub:

```bash
# 1. Initialize Git repository
git init

# 2. Add all files (it will respect .gitignore and skip venv/)
git add .

# 3. Create your first commit
git commit -m "feat: initial commit for TokenAudit security scanner"

# 4. Rename default branch to main
git branch -M main

# 5. Link to your GitHub repo and push
# (Replace with your actual GitHub repo URL)
git remote add origin https://github.com/YOUR_USERNAME/tokenaudit.git
git push -u origin main
