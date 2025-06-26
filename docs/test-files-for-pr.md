# Test Files for DevSecOps Sentinel PR Testing

Create these files in your `sentinel-testbed` repository to trigger all security scanners:

## 1. Secret Scanner Test Files

### `config/database.py` - Contains hardcoded secrets
```python
import os
import psycopg2

# BAD: Hardcoded database credentials (will trigger secret scanner)
DATABASE_CONFIG = {
    'host': 'prod-db.company.com',
    'database': 'production',
    'user': 'admin',
    'password': 'SuperSecret123!@#',  # This will be detected
    'port': 5432
}

# BAD: AWS credentials hardcoded
AWS_ACCESS_KEY_ID = "AKIAIOSFODNN7EXAMPLE"
AWS_SECRET_ACCESS_KEY = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"

# BAD: API keys
STRIPE_SECRET_KEY = "sk_test_4eC39HqLyjWDarjtT1zdp7dc"
GITHUB_TOKEN = "ghp_1234567890abcdefghijklmnopqrstuvwxyz"

def connect_to_database():
    """Connect to PostgreSQL database with hardcoded credentials."""
    try:
        connection = psycopg2.connect(
            host=DATABASE_CONFIG['host'],
            database=DATABASE_CONFIG['database'],
            user=DATABASE_CONFIG['user'],
            password=DATABASE_CONFIG['password'],
            port=DATABASE_CONFIG['port']
        )
        return connection
    except Exception as e:
        print(f"Database connection failed: {e}")
        return None
```

### `.env.example` - More secrets to detect
```bash
# Database Configuration
DB_PASSWORD=another_secret_password_123
DB_CONNECTION_STRING=postgresql://user:secret123@localhost:5432/mydb

# API Keys
OPENAI_API_KEY=sk-1234567890abcdefghijklmnopqrstuvwxyz1234567890abcdef
SENDGRID_API_KEY=SG.1234567890abcdefghijklmnopqrstuvwxyz.1234567890abcdefghijklmnopqrstuvwxyz

# JWT Secret
JWT_SECRET=my_super_secret_jwt_key_that_should_not_be_hardcoded
```

## 2. Vulnerability Scanner Test Files

### `requirements.txt` - Vulnerable Python packages
```
Django==2.0.1
requests==2.18.4
Pillow==5.0.0
PyYAML==3.12
urllib3==1.24.1
Jinja2==2.8
Flask==0.12.2
SQLAlchemy==1.1.0
cryptography==2.1.4
paramiko==2.0.0
```

### `package.json` - Vulnerable Node.js packages
```json
{
  "name": "vulnerable-test-app",
  "version": "1.0.0",
  "description": "Test app with known vulnerabilities",
  "dependencies": {
    "lodash": "4.17.4",
    "moment": "2.19.3",
    "express": "4.15.2",
    "mongoose": "4.13.6",
    "axios": "0.18.0",
    "jquery": "3.3.1",
    "bootstrap": "3.3.7",
    "handlebars": "4.0.11",
    "marked": "0.3.6",
    "debug": "2.6.8"
  },
  "devDependencies": {
    "webpack": "3.8.1",
    "babel-core": "6.26.0"
  }
}
```

## 3. AI Code Review Test Files

### `src/user_auth.py` - Code with security issues for AI review
```python
import hashlib
import sqlite3
from flask import request, session

class UserAuth:
    def __init__(self):
        # BAD: Using MD5 for password hashing
        self.hash_algorithm = hashlib.md5
        
    def authenticate_user(self, username, password):
        """Authenticate user with multiple security issues."""
        
        # BAD: SQL Injection vulnerability
        query = f"SELECT * FROM users WHERE username = '{username}' AND password = '{self.hash_password(password)}'"
        
        conn = sqlite3.connect('users.db')
        cursor = conn.cursor()
        
        # Execute vulnerable query
        result = cursor.execute(query).fetchone()
        
        if result:
            # BAD: Storing sensitive data in session without encryption
            session['user_id'] = result[0]
            session['username'] = result[1]
            session['is_admin'] = result[3]  # Potential privilege escalation
            return True
        return False
    
    def hash_password(self, password):
        """Hash password using weak algorithm."""
        # BAD: MD5 is cryptographically broken
        return self.hash_algorithm(password.encode()).hexdigest()
    
    def reset_password(self):
        """Reset password functionality with issues."""
        email = request.form.get('email')
        
        # BAD: No input validation
        # BAD: Potential email injection
        query = f"SELECT username FROM users WHERE email = '{email}'"
        
        # BAD: No rate limiting on password reset
        # This could be abused for enumeration attacks
        
        return "Password reset email sent"
    
    def check_admin_access(self):
        """Check if user has admin access."""
        # BAD: Trusting client-side data
        if request.headers.get('X-Admin-Override') == 'true':
            return True
            
        # BAD: Weak authorization check
        return session.get('is_admin', False)
```

### `src/file_upload.py` - File upload with security issues
```python
import os
import shutil
from flask import request, send_file

class FileUploader:
    def __init__(self, upload_dir="/tmp/uploads"):
        self.upload_dir = upload_dir
        
    def upload_file(self):
        """Handle file upload with security vulnerabilities."""
        
        if 'file' not in request.files:
            return "No file provided"
            
        file = request.files['file']
        filename = file.filename
        
        # BAD: No file type validation
        # BAD: Path traversal vulnerability
        file_path = os.path.join(self.upload_dir, filename)
        
        # BAD: No file size limits
        file.save(file_path)
        
        # BAD: Executing uploaded files
        if filename.endswith('.py'):
            os.system(f"python {file_path}")  # Command injection risk
            
        return f"File {filename} uploaded successfully"
    
    def download_file(self, filename):
        """Download file with path traversal vulnerability."""
        
        # BAD: No path validation - allows ../../../etc/passwd
        file_path = os.path.join(self.upload_dir, filename)
        
        # BAD: No access control
        return send_file(file_path)
    
    def delete_file(self, filename):
        """Delete file with insufficient validation."""
        
        # BAD: No authorization check
        # BAD: Potential path traversal
        file_path = os.path.join(self.upload_dir, filename)
        
        if os.path.exists(file_path):
            os.remove(file_path)
            return "File deleted"
        return "File not found"
```

## 4. Additional Test Files

### `Dockerfile` - With security issues
```dockerfile
FROM ubuntu:16.04

# BAD: Running as root
USER root

# BAD: Not pinning package versions
RUN apt-get update && apt-get install -y \
    python3 \
    python3-pip \
    curl \
    wget

# BAD: Hardcoded secrets in Dockerfile
ENV API_KEY=sk_test_1234567890abcdef
ENV DB_PASSWORD=supersecret123

# BAD: Copying everything including sensitive files
COPY . /app

WORKDIR /app

# BAD: Installing packages as root
RUN pip3 install -r requirements.txt

# BAD: Exposing unnecessary ports
EXPOSE 22 3306 5432 6379

CMD ["python3", "app.py"]
```

## Instructions for Testing:

1. **Create a new branch** in your `sentinel-testbed` repo:
   ```bash
   git checkout -b test-security-scanners
   ```

2. **Add these files** to trigger different scanners:
   - Add `config/database.py` and `.env.example` for **secret detection**
   - Add `requirements.txt` and `package.json` for **vulnerability scanning**  
   - Add `src/user_auth.py` and `src/file_upload.py` for **AI code review**
   - Add `Dockerfile` for additional security issues

3. **Create a Pull Request** to trigger the webhook

4. **Expected Results:**
   - **Secret Scanner**: Will detect ~8-10 hardcoded secrets
   - **Vulnerability Scanner**: Will find multiple CVEs in old package versions
   - **AI Reviewer**: Will identify SQL injection, weak crypto, path traversal, etc.

This comprehensive test will demonstrate all three security scanning capabilities of your DevSecOps Sentinel!
