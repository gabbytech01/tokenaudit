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

## Usage

TokenAudit v2.0 supports flexible command-line flags. You can pass target URLs, custom JWTs, and export reports directly to JSON files for documentation or pipeline integration.

### 1. Run an Audit & Export to JSON
```bash
python3 auditor.py -u [https://vulnbank.org](https://vulnbank.org) -o report.json

2. Audit a Custom JWT and Endpoint
Bash

python3 auditor.py -u [https://api.example.com](https://api.example.com) -t "eyJhbGciOi..."

3. View the Help Menu & Available Flags
Bash

python3 auditor.py --help
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
