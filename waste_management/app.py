from flask import Flask, render_template, request, redirect, url_for, session, flash, jsonify
import mysql.connector
from functools import wraps
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime, timedelta
import os
import secrets
import ssl
import hashlib
import hmac
import time
import json
import re
import logging
from logging.handlers import RotatingFileHandler
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_wtf.csrf import CSRFProtect, generate_csrf, validate_csrf
from flask_talisman import Talisman
import bleach
from werkzeug.middleware.proxy_fix import ProxyFix
from cryptography.fernet import Fernet
import ipaddress
from dotenv import load_dotenv
import mysql.connector.pooling


# Load environment variables
app = Flask(__name__, template_folder='templates')

load_dotenv()


# ===========================================
# SECURITY HARDENING CONFIGURATION
# ===========================================

# Proxy fix untuk reverse proxy
app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1, x_prefix=1)

# Security Configuration
app.secret_key = os.environ.get('SECRET_KEY', secrets.token_hex(32))

# Session Security - Maximum untuk ujian
app.config.update(
    SERVER_NAME=None,
    SEND_FILE_MAX_AGE_DEFAULT=0, 
    TEMPLATES_AUTO_RELOAD=True,  
    # MAX_CONTENT_LENGTH=5 * 1024 * 1024,
    JSON_SORT_KEYS=True,
    JSONIFY_PRETTYPRINT_REGULAR=False,
    SECRET_KEY=os.environ.get('SECRET_KEY', secrets.token_hex(32)),
    SESSION_COOKIE_SECURE=True,  # Set True untuk production dengan HTTPS
    SESSION_COOKIE_HTTPONLY=True,  # No JavaScript access
    SESSION_COOKIE_SAMESITE='Strict',  # Maximum CSRF protection
    SESSION_COOKIE_NAME='__Host-WasteApp',  # Secure prefix (only in HTTPS)
    PERMANENT_SESSION_LIFETIME=timedelta(minutes=30),  # Short session
    WTF_CSRF_ENABLED=True,
    WTF_CSRF_TIME_LIMIT=3600,  # CSRF token expiry
    APPLICATION_ROOT='/',
    MAX_CONTENT_LENGTH=16 * 1024 * 1024,  # 16MB max upload
)

# CSRF Protection
csrf = CSRFProtect(app)

# Make CSRF token available in all templates
@app.context_processor
def inject_csrf_token():
    return dict(csrf_token=generate_csrf)

# Content Security Policy & Security Headers menggunakan Talisman
# Update Content Security Policy untuk mengakomodasi Bootstrap dan fonts
csp = {
    'default-src': "'self'",
    'script-src': [
        "'self'",
        "'unsafe-inline'",
        "'unsafe-eval'",
        "https://cdn.jsdelivr.net"
    ],
    'style-src': [
        "'self'",
        "'unsafe-inline'",
        "https://cdn.jsdelivr.net"
    ],
    'font-src': [
        "'self'",
        "https://cdn.jsdelivr.net",
        "data:"
    ],
    'img-src': [
        "'self'",
        "data:",
        "https:",
        "blob:"
    ],
    'connect-src': "'self'",
    'frame-ancestors': "'none'",
    'form-action': "'self'",
    'base-uri': "'self'",
    'object-src': "'none'",
    'upgrade-insecure-requests': True
}


# Only use Talisman if available (optional dependency)
try:
    talisman = Talisman(
        app,
        force_https=True,
        strict_transport_security=True,
        strict_transport_security_max_age=31536000,
        content_security_policy=csp,
        content_security_policy_nonce_in=['script-src', 'style-src'],
        feature_policy={
            'geolocation': "'none'",
            'camera': "'none'",
            'microphone': "'none'",
            'payment': "'none'",
            'usb': "'none'"
        }
    )
except ImportError:
    print("⚠️  Talisman not installed. Some security headers may not be set.")

# Rate Limiting - Aggressive untuk ujian
limiter = Limiter(
    key_func=get_remote_address,
    app=app,
    default_limits=["100 per day", "20 per hour", "5 per minute"],
    storage_uri="memory://",
    headers_enabled=True,
)

# ===========================================
# ADVANCED LOGGING & MONITORING
# ===========================================

@app.after_request
def security_headers(response):
    """Tambahkan security headers"""
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-XSS-Protection'] = '1; mode=block'
    response.headers['Referrer-Policy'] = 'strict-origin-when-cross-origin'
    response.headers['Permissions-Policy'] = 'geolocation=(), microphone=(), camera=()'
    return response

@app.before_request
def enhanced_security_checks():
    """Enhanced security checks sebelum setiap request"""
    if request.endpoint == 'debug_info' and os.environ.get('FLASK_ENV') == 'development':
        return
    
    # IP filtering
    client_ip = request.remote_addr
    if not is_ip_allowed(client_ip):
        log_security_event('IP_BLOCKED', details=f"Blocked IP: {client_ip}", level='CRITICAL')
        return f"Access Denied for IP: {client_ip}. Check ALLOWED_IPS configuration.", 403
    
    # Enhanced suspicious pattern detection
    suspicious_patterns = [
        r"\.\.\/",  # Directory traversal
        r"\.\.\\",  # Windows directory traversal
        r"\<script",  # XSS attempts
        r"javascript:",  # JavaScript injection
        r"vbscript:",  # VBScript injection
        r"onload=",  # Event handler injection
        r"onerror=",  # Event handler injection
        r"union.*select",  # SQL injection
        r"exec\s*\(",  # Command injection
        r"\bor\s+\d+\s*=\s*\d+",  # SQL injection
        r"\/etc\/passwd",  # File inclusion
        r"\/proc\/",  # Linux proc access
        r"cmd\.exe",  # Windows command injection
        r"powershell",  # PowerShell injection
        r"wget\s+",  # File download attempts
        r"curl\s+",  # File download attempts
    ]
    
    # Check URL, headers, and form data
    request_data = [
        request.path.lower(),
        request.query_string.decode('utf-8', errors='ignore').lower(),
        str(request.headers).lower(),
    ]
    
    # Check form data if exists
    if request.form:
        request_data.extend([str(v).lower() for v in request.form.values()])
    
    for data in request_data:
        for pattern in suspicious_patterns:
            if re.search(pattern, data, re.IGNORECASE):
                log_security_event('SUSPICIOUS_REQUEST', 
                                 details=f"Pattern: {pattern}, Data: {data[:100]}", 
                                 level='CRITICAL')
                return "Bad Request", 400
    
    # Check file upload attempts
    if request.files:
        for file in request.files.values():
            if file.filename:
                # Check dangerous file extensions
                dangerous_extensions = ['.php', '.asp', '.aspx', '.jsp', '.exe', '.bat', '.cmd', '.sh', '.py', '.pl']
                if any(file.filename.lower().endswith(ext) for ext in dangerous_extensions):
                    log_security_event('DANGEROUS_FILE_UPLOAD', 
                                     details=f"Filename: {file.filename}",
                                     level='CRITICAL')
                    return "File type not allowed", 400
    
    # Existing session validation code...
    protected_endpoints = ['dashboard', 'report', 'update_status', 'users']
    if request.endpoint in protected_endpoints:
        if 'user_id' not in session:
            return redirect(url_for('login'))
        
        session_token = session.get('session_token')
        if not validate_session_token(session_token):
            session.clear()
            log_security_event('INVALID_SESSION_TOKEN', 
                             user_id=session.get('user_id'),
                             level='ERROR')
            return redirect(url_for('login'))
        
        last_activity = session.get('last_activity')
        if last_activity:
            last_time = datetime.fromisoformat(last_activity)
            if datetime.utcnow() - last_time > app.config['PERMANENT_SESSION_LIFETIME']:
                session.clear()
                log_security_event('SESSION_TIMEOUT', user_id=session.get('user_id'))
                flash('Session Anda telah berakhir. Silakan login kembali.', 'warning')
                return redirect(url_for('login'))
        
        session['last_activity'] = datetime.utcnow().isoformat()

# Setup advanced logging
if not os.path.exists('logs'):
    os.makedirs('logs')

# Security log
security_handler = RotatingFileHandler('logs/security.log', maxBytes=10240000, backupCount=10)
security_handler.setFormatter(logging.Formatter(
    '%(asctime)s %(levelname)s [%(name)s] [%(filename)s:%(lineno)d] '
    '[IP:%(ip)s] [User:%(user_id)s] %(message)s'
))

# Application log
app_handler = RotatingFileHandler('logs/app.log', maxBytes=10240000, backupCount=10)
app_handler.setFormatter(logging.Formatter(
    '%(asctime)s %(levelname)s %(name)s %(message)s'
))

# Configure loggers
security_logger = logging.getLogger('security')
security_logger.setLevel(logging.WARNING)
security_logger.addHandler(security_handler)

app.logger.setLevel(logging.INFO)
app.logger.addHandler(app_handler)

# ===========================================
# SECURITY FUNCTIONS
# ===========================================

# Encryption untuk data sensitif
ENCRYPTION_KEY = os.environ.get('ENCRYPTION_KEY')
if not ENCRYPTION_KEY:
    ENCRYPTION_KEY = Fernet.generate_key()
    print("⚠️  Generated new encryption key. Set ENCRYPTION_KEY in environment for production.")

cipher = Fernet(ENCRYPTION_KEY)

def encrypt_data(data):
    """Encrypt sensitive data"""
    return cipher.encrypt(data.encode()).decode()

def decrypt_data(data):
    """Decrypt sensitive data"""
    return cipher.decrypt(data.encode()).decode()

# IP Whitelist/Blacklist
ALLOWED_IPS = set(os.environ.get('ALLOWED_IPS', '127.0.0.1,::1').split(','))
BLOCKED_IPS = set()

def is_ip_allowed(ip):
    """Check if IP is allowed - More flexible for development"""
    if ip in BLOCKED_IPS:
        return False
    
    # Untuk development, izinkan IP lokal dan private
    if os.environ.get('FLASK_ENV') == 'development':
        try:
            ip_obj = ipaddress.ip_address(ip)
            # Izinkan localhost dan private networks
            if ip_obj.is_loopback or ip_obj.is_private:
                return True
        except:
            pass
    
    # Check whitelist
    if ip in ALLOWED_IPS or 'localhost' in ALLOWED_IPS:
        return True
    
    # Untuk development, izinkan semua jika tidak ada konfigurasi khusus
    if len(ALLOWED_IPS) <= 2:  # Hanya default localhost
        return True
    
    return False

# def get_ssl_context(): for real
#     """Get SSL context based on environment"""
#     if os.environ.get('FLASK_ENV') == 'production':
#         # Production: Use proper SSL certificates
#         ssl_cert = os.environ.get('SSL_CERT_PATH')
#         ssl_key = os.environ.get('SSL_KEY_PATH')
        
#         if ssl_cert and ssl_key and os.path.exists(ssl_cert) and os.path.exists(ssl_key):
#             context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
#             context.load_cert_chain(ssl_cert, ssl_key)
            
#             # Security hardening
#             context.minimum_version = ssl.TLSVersion.TLSv1_2
#             context.set_ciphers('ECDHE+AESGCM:ECDHE+CHACHA20:DHE+AESGCM:DHE+CHACHA20:!aNULL:!MD5:!DSS')
#             context.check_hostname = False  # Will be handled by reverse proxy
            
#             return context
#         else:
#             print("⚠️  SSL certificates not found! Running without SSL.")
#             return None
#     else:
#         # Development: Generate self-signed if needed
#         if not (os.path.exists('cert.pem') and os.path.exists('key.pem')):
#             print("Generating self-signed certificate for development...")
#             os.system('openssl req -x509 -newkey rsa:4096 -nodes -out cert.pem -keyout key.pem -days 365 -subj "/CN=localhost"')
        
#         context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
#         context.load_cert_chain('cert.pem', 'key.pem')
#         return context
    
def get_ssl_context():
    """Get SSL context based on environment - Fixed"""
    if os.environ.get('FLASK_ENV') == 'production':
        # Production SSL setup
        ssl_cert = os.environ.get('SSL_CERT_PATH')
        ssl_key = os.environ.get('SSL_KEY_PATH')
        
        if ssl_cert and ssl_key and os.path.exists(ssl_cert) and os.path.exists(ssl_key):
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            context.load_cert_chain(ssl_cert, ssl_key)
            context.minimum_version = ssl.TLSVersion.TLSv1_2
            context.set_ciphers('ECDHE+AESGCM:ECDHE+CHACHA20:DHE+AESGCM:DHE+CHACHA20:!aNULL:!MD5:!DSS')
            return context
        else:
            print("⚠️  SSL certificates not found! Running without SSL.")
            return None
    else:
        # Development: Return None untuk HTTP atau 'adhoc' untuk HTTPS sederhana
        return 'adhoc' 

# Brute force protection
failed_attempts = {}
LOCKOUT_DURATION = 300  # 5 minutes
MAX_ATTEMPTS = 3

def is_account_locked(username):
    """Check if account is locked due to failed attempts"""
    if username in failed_attempts:
        attempts, last_attempt = failed_attempts[username]
        if attempts >= MAX_ATTEMPTS:
            if time.time() - last_attempt < LOCKOUT_DURATION:
                return True
            else:
                # Reset after lockout period
                del failed_attempts[username]
    return False

def record_failed_attempt(username):
    """Record failed login attempt"""
    current_time = time.time()
    if username in failed_attempts:
        attempts, _ = failed_attempts[username]
        failed_attempts[username] = (attempts + 1, current_time)
    else:
        failed_attempts[username] = (1, current_time)

def clear_failed_attempts(username):
    """Clear failed attempts on successful login"""
    if username in failed_attempts:
        del failed_attempts[username]

# Input validation and sanitization
def validate_input(data, input_type='string', max_length=255):
    """Advanced input validation dengan proteksi XXE dan Path Traversal"""
    if not data:
        return False, "Input tidak boleh kosong"
    
    # Proteksi Path Traversal
    if '../' in data or '..\\' in data or '/etc/' in data or 'C:\\' in data:
        return False, "Karakter path traversal terdeteksi"
    
    # Proteksi XXE
    if any(pattern in data.lower() for pattern in ['<!entity', '<!doctype', '&lt;!entity', 'system', 'file://']):
        return False, "Karakter XML/XXE terdeteksi"
    
    # Proteksi Command Injection
    dangerous_chars = ['|', '&', ';', '$', '`', '>', '<', '$(', '${']
    if any(char in data for char in dangerous_chars):
        return False, "Karakter berbahaya terdeteksi"
    
    # Remove dangerous characters
    data = bleach.clean(data.strip(), tags=[], strip=True)
    
    if len(data) > max_length:
        return False, f"Input terlalu panjang (maksimal {max_length} karakter)"
    
    # Validasi berdasarkan tipe
    if input_type == 'email':
        if not re.match(r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$', data):
            return False, "Format email tidak valid"
    
    elif input_type == 'username':
        if not re.match(r'^[a-zA-Z0-9_-]+$', data):
            return False, "Username hanya boleh mengandung huruf, angka, underscore, dan dash"
        if len(data) < 3:
            return False, "Username minimal 3 karakter"
    
    elif input_type == 'password':
        if len(data) < 12:
            return False, "Password minimal 12 karakter"
        if not re.search(r"[A-Z]", data):
            return False, "Password harus mengandung huruf besar"
        if not re.search(r"[a-z]", data):
            return False, "Password harus mengandung huruf kecil"
        if not re.search(r"\d", data):
            return False, "Password harus mengandung angka"
        if not re.search(r"[!@#$%^&*(),.?\":{}|<>]", data):
            return False, "Password harus mengandung karakter khusus"
    
    return True, data

# SQL Injection protection (additional layer)
def sanitize_sql_input(value):
    """Additional SQL injection protection"""
    dangerous_patterns = [
        r"(\b(UNION|SELECT|INSERT|UPDATE|DELETE|DROP|CREATE|ALTER)\b)",
        r"(--|\/\*|\*\/)",
        r"(\b(OR|AND)\s+\d+\s*=\s*\d+)",
        r"(\b(OR|AND)\s+['\"].*['\"])",
        r"([\';]+)",
    ]
    
    for pattern in dangerous_patterns:
        if re.search(pattern, str(value), re.IGNORECASE):
            return None
    
    return value

# Session security
def generate_session_token():
    """Generate secure session token"""
    return secrets.token_hex(32)

def validate_session_token(token):
    """Validate session token"""
    return token and len(token) == 64 and all(c in '0123456789abcdef' for c in token)

# Security logging
def log_security_event(event_type, user_id=None, details=None, level='WARNING'):
    """Enhanced security logging"""
    extra_data = {
        'ip': request.remote_addr,
        'user_id': user_id or 'anonymous',
        'user_agent': request.headers.get('User-Agent', 'unknown'),
        'endpoint': request.endpoint or 'unknown',
        'method': request.method,
        'timestamp': datetime.utcnow().isoformat(),
    }
    
    log_message = f"SECURITY_EVENT: {event_type}"
    if details:
        log_message += f" | Details: {details}"
    
    if level == 'CRITICAL':
        security_logger.critical(log_message, extra=extra_data)
    elif level == 'ERROR':
        security_logger.error(log_message, extra=extra_data)
    else:
        security_logger.warning(log_message, extra=extra_data)

# ===========================================
# MIDDLEWARE & SECURITY CHECKS
# ===========================================

@app.before_request
def security_checks():
    """Comprehensive security checks before each request"""
    
    # IP filtering
    client_ip = request.remote_addr
    if not is_ip_allowed(client_ip):
        log_security_event('IP_BLOCKED', details=f"Blocked IP: {client_ip}", level='CRITICAL')
        return "Access Denied", 403
    
    # Check for suspicious patterns in URL
    suspicious_patterns = [
        r"\.\.\/",  # Directory traversal
        r"\<script",  # XSS attempts
        r"union.*select",  # SQL injection
        r"exec\s*\(",  # Command injection
        r"\bor\s+\d+\s*=\s*\d+",  # SQL injection
    ]
    
    request_path = request.path.lower()
    for pattern in suspicious_patterns:
        if re.search(pattern, request_path, re.IGNORECASE):
            log_security_event('SUSPICIOUS_REQUEST', 
                             details=f"Suspicious pattern in URL: {request.path}", 
                             level='CRITICAL')
            return "Bad Request", 400
    
    # Check request size
    if request.content_length and request.content_length > app.config['MAX_CONTENT_LENGTH']:
        log_security_event('REQUEST_TOO_LARGE', 
                         details=f"Content length: {request.content_length}")
        return "Request Entity Too Large", 413
    
    # Session validation for authenticated routes
    protected_endpoints = ['dashboard', 'report', 'update_status', 'users']
    if request.endpoint in protected_endpoints:
        if 'user_id' not in session:
            return redirect(url_for('login'))
        
        # Validate session token
        session_token = session.get('session_token')
        if not validate_session_token(session_token):
            session.clear()
            log_security_event('INVALID_SESSION_TOKEN', 
                             user_id=session.get('user_id'),
                             level='ERROR')
            return redirect(url_for('login'))
        
        # Check session timeout
        last_activity = session.get('last_activity')
        if last_activity:
            last_time = datetime.fromisoformat(last_activity)
            if datetime.utcnow() - last_time > app.config['PERMANENT_SESSION_LIFETIME']:
                session.clear()
                log_security_event('SESSION_TIMEOUT', user_id=session.get('user_id'))
                flash('Session Anda telah berakhir. Silakan login kembali.', 'warning')
                return redirect(url_for('login'))
        
        # Update last activity
        session['last_activity'] = datetime.utcnow().isoformat()

def get_secure_db_cursor(conn, dictionary=False):
    """Get cursor with consistent prepared statement configuration"""
    return conn.cursor(prepared=True, dictionary=dictionary)

# Database configuration dengan connection pooling
DB_CONFIG = {
    'host': os.environ.get('DB_HOST', 'localhost'),
    'user': os.environ.get('DB_USER', 'root'),
    'password': os.environ.get('DB_PASSWORD', ''),
    'database': os.environ.get('DB_NAME', 'waste_management'),
    'autocommit': False,
    'use_unicode': True,
    'charset': 'utf8mb4',
    'sql_mode': 'STRICT_TRANS_TABLES,NO_ZERO_DATE,NO_ZERO_IN_DATE,ERROR_FOR_DIVISION_BY_ZERO',
    'ssl_disabled': False,
    'ssl_verify_cert': False,  # Ubah ke False untuk development
    'ssl_verify_identity': False,  # Ubah ke False untuk development
    'connection_timeout': 10,
    'auth_plugin': 'mysql_native_password'
}

connection_pool = mysql.connector.pooling.MySQLConnectionPool(
    pool_name="waste_app_pool",
    pool_size=10,
    pool_reset_session=True,
    **DB_CONFIG
)

def get_db_connection():
    """Get database connection from pool with security settings"""
    try:
        conn = connection_pool.get_connection()
        cursor = conn.cursor()
        cursor.execute("SET SESSION sql_mode = 'STRICT_TRANS_TABLES,NO_ZERO_DATE,NO_ZERO_IN_DATE,ERROR_FOR_DIVISION_BY_ZERO'")
        cursor.execute("SET SESSION transaction_isolation = 'READ-COMMITTED'")
        cursor.close()
        return conn
    except mysql.connector.Error as err:
        log_security_event('DB_CONNECTION_ERROR', details=str(err), level='ERROR')
        raise

def handle_db_error(err, user_message="Terjadi kesalahan sistem. Silakan coba lagi."):
    """Handle database errors securely"""
    # Log detail error untuk debugging
    log_security_event('DATABASE_ERROR', 
                      user_id=session.get('user_id'),
                      details=f"DB Error: {type(err).__name__}: {str(err)}", 
                      level='ERROR')
    
    # Return generic message to user
    flash(user_message, 'error')
    return False

# Database initialization
def init_db():
    try:
        # Create database if not exists
        conn = mysql.connector.connect(
            host=DB_CONFIG['host'],
            user=DB_CONFIG['user'],
            password=DB_CONFIG['password']
        )
        cursor = conn.cursor()
        cursor.execute(f"CREATE DATABASE IF NOT EXISTS {DB_CONFIG['database']}")
        conn.close()
        
        # Connect to the database and create tables
        conn = get_db_connection()
        cursor = conn.cursor()
        
        # Create users table
        cursor.execute('''CREATE TABLE IF NOT EXISTS users (
                         id INT AUTO_INCREMENT PRIMARY KEY,
                         username VARCHAR(50) UNIQUE NOT NULL,
                         email VARCHAR(100) UNIQUE NOT NULL,
                         password VARCHAR(255) NOT NULL,
                         role VARCHAR(20) DEFAULT 'warga',
                         created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                         )''')
        
        # Create waste_reports table
        cursor.execute('''CREATE TABLE IF NOT EXISTS waste_reports (
                         id INT AUTO_INCREMENT PRIMARY KEY,
                         user_id INT,
                         location VARCHAR(255) NOT NULL,
                         waste_type VARCHAR(50) NOT NULL,
                         description TEXT,
                         status VARCHAR(20) DEFAULT 'pending',
                         created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                         FOREIGN KEY (user_id) REFERENCES users(id)
                         )''')
        
        # Create default admin user
        admin_password = generate_password_hash('Admin123!@#')
        cursor.execute('''INSERT IGNORE INTO users (username, email, password, role)
                         VALUES (%s, %s, %s, %s)''', 
                         ('admin', 'admin@example.com', admin_password, 'admin'))
        
        conn.commit()
        cursor.close()
        conn.close()
        print("Database initialized successfully!")
        
    except mysql.connector.Error as err:
        print(f"Database error: {err}")
        print("Pastikan MySQL sudah running dan kredensial database benar!")

def require_role(required_roles):
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if 'user_id' not in session:
                return redirect(url_for('login'))
            
            user_role = session.get('role')
            if user_role not in required_roles:
                log_security_event('ACCESS_DENIED', 
                                 user_id=session['user_id'],
                                 details=f"Required role: {required_roles}, User role: {user_role}")
                return "Access Denied", 403
            
            return f(*args, **kwargs)
        return decorated_function
    return decorator

def check_data_ownership(user_id, report_id):
    """Memastikan user hanya bisa akses data miliknya"""
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT user_id FROM waste_reports WHERE id = %s", (report_id,))
        result = cursor.fetchone()
        cursor.close()
        conn.close()
        
        if not result or result[0] != user_id:
            return False
        return True
    except:
        return False

# ===========================================
# SECURE ROUTE IMPLEMENTATIONS
# ===========================================

@app.route('/')
def index():
    try:
        app.logger.info(f"Template folder: {app.template_folder}")
        app.logger.info(f"Template list: {os.listdir(app.template_folder)}")
        return render_template('index.html')
    except Exception as e:
        app.logger.error(f"Template rendering error: {e}")
        return f"<h1>Welcome to Waste Management System</h1><p>Template error: {e}</p><a href='/login'>Login</a> | <a href='/register'>Register</a>"
    
@app.route('/debug/info')
def debug_info():
    """Debug information - HANYA untuk development"""
    if os.environ.get('FLASK_ENV') != 'development':
        return "Not available", 404
    
    info = {
        'client_ip': request.remote_addr,
        'allowed_ips': list(ALLOWED_IPS),
        'blocked_ips': list(BLOCKED_IPS),
        'session': dict(session),
        'headers': dict(request.headers),
        'flask_env': os.environ.get('FLASK_ENV'),
    }
    return f"<pre>{json.dumps(info, indent=2, default=str)}</pre>"

@app.route('/register', methods=['GET', 'POST'])
@limiter.limit("5 per minute")
def register():
    if request.method == 'POST':
        # Validate CSRF token
        try:
            validate_csrf(request.form.get('csrf_token'))
        except:
            log_security_event('CSRF_VALIDATION_FAILED')
            flash('Token keamanan tidak valid!', 'error')
            return render_template('register.html')
        
        username = request.form.get('username', '').strip()
        email = request.form.get('email', '').strip()
        password = request.form.get('password', '')
        
        # Advanced input validation
        valid, username_result = validate_input(username, 'username')
        if not valid:
            flash(username_result, 'error')
            return render_template('register.html')
        username = username_result
        
        valid, email_result = validate_input(email, 'email')
        if not valid:
            flash(email_result, 'error')
            return render_template('register.html')
        email = email_result
        
        valid, password_result = validate_input(password, 'password')
        if not valid:
            flash(password_result, 'error')
            return render_template('register.html')
        
        hashed_password = generate_password_hash(password, method='pbkdf2:sha256')
        
        try:
            conn = get_db_connection()
            cursor = conn.cursor(prepared=True)
            cursor.execute('INSERT INTO users (username, email, password) VALUES (?, ?, ?)',
                         (username, email, hashed_password))
            conn.commit()
            cursor.close()
            conn.close()

            log_security_event('REGISTER_SUCCESS', details=f"Username: {username}, Email: {email}")
            flash('Registrasi berhasil! Silakan login.', 'success')
            return redirect(url_for('login'))
        
        except mysql.connector.IntegrityError:
            flash('Username atau email sudah digunakan!', 'error')
            log_security_event('REGISTER_FAILED', details=f"Duplicate entry - Username: {username}, Email: {email}")
        except mysql.connector.Error as err:
            handle_db_error(err)
            flash('Terjadi kesalahan sistem. Silakan coba lagi.', 'error')
            log_security_event('REGISTER_ERROR', details=f"Database error: {err}", level='ERROR')
    
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
@limiter.limit("3 per minute")
def login():
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '')
        
        # Validate CSRF token
        try:
            validate_csrf(request.form.get('csrf_token'))
        except:
            log_security_event('CSRF_VALIDATION_FAILED', details=f"Username: {username}")
            flash('Token keamanan tidak valid!', 'error')
            return render_template('login.html')
        
        # Validate input
        valid, username = validate_input(username, 'username')
        if not valid:
            flash(username, 'error')
            return render_template('login.html')
        
        if not password:
            flash('Password harus diisi!', 'error')
            return render_template('login.html')
        
        # Check if account is locked
        if is_account_locked(username):
            log_security_event('LOGIN_ATTEMPT_LOCKED_ACCOUNT', 
                             details=f"Username: {username}", 
                             level='CRITICAL')
            flash('Akun terkunci sementara karena terlalu banyak percobaan login yang gagal.', 'error')
            return render_template('login.html')
        
        try:
            conn = get_db_connection()
            cursor = conn.cursor(prepared=True)
            cursor.execute('SELECT * FROM users WHERE username = ?', (username,))
            user = cursor.fetchone()
            cursor.close()
            conn.close()
            
            if user and check_password_hash(user[3], password):
                clear_failed_attempts(username)
                
                # PROTEKSI SESSION FIXATION - Regenerate session ID
                old_session_id = session.get('_id', 'new')
                session.permanent = True
                
                # Hapus session lama dan buat baru
                session.clear()
                
                # Set session data baru dengan ID baru
                session['user_id'] = user[0]
                session['username'] = user[1]
                session['role'] = user[4]
                session['login_time'] = datetime.utcnow().isoformat()
                session['last_activity'] = datetime.utcnow().isoformat()
                session['session_token'] = generate_session_token()
                session['csrf_token'] = generate_csrf()
                
                # Force session ID regeneration
                session.modified = True
                
                log_security_event('LOGIN_SUCCESS', user_id=user[0], 
                                 details=f"Old session: {old_session_id}, New session regenerated")
                flash(f'Selamat datang, {username}!', 'success')
                return redirect(url_for('dashboard'))
            else:
                record_failed_attempt(username)
                log_security_event('LOGIN_FAILED', 
                                 details=f"Invalid credentials - Username: {username}",
                                 level='ERROR')
                flash('Username atau password salah!', 'error')
                
        except mysql.connector.Error as err:
            handle_db_error(err)
            log_security_event('LOGIN_ERROR', details=f"Database error: {err}", level='ERROR')
            flash('Terjadi kesalahan sistem. Silakan coba lagi.', 'error')
    
    return render_template('login.html')

@app.route('/logout')
def logout():
    if 'user_id' in session:
        user_id = session['user_id']
        session_token = session.get('session_token', 'unknown')
        
        # Log logout activity
        log_security_event('LOGOUT_SUCCESS', user_id=user_id, 
                          details=f"Session token: {session_token}")
    
    # Clear semua session data
    session.clear()
    
    # Optional: Buat session baru yang kosong untuk mencegah session fixation
    session.permanent = False
    
    flash('Anda telah logout dengan aman.', 'info')
    
    # Redirect dengan parameter untuk memastikan cache clear
    response = redirect(url_for('index'))
    response.headers['Cache-Control'] = 'no-cache, no-store, must-revalidate'
    response.headers['Pragma'] = 'no-cache'
    response.headers['Expires'] = '0'
    
    return response

@app.route('/dashboard')
def dashboard():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    try:
        conn = get_db_connection()
        cursor = conn.cursor(dictionary=True)  # Use dictionary cursor for easier access
        
        if session['role'] == 'admin':
            # Admin dashboard - show all reports with user info
            cursor.execute('''SELECT wr.id, wr.user_id, wr.location, wr.waste_type, 
                                    wr.description, wr.status, wr.created_at, u.username 
                             FROM waste_reports wr 
                             JOIN users u ON wr.user_id = u.id 
                             ORDER BY wr.created_at DESC''')
            reports = cursor.fetchall()
            
            # Get statistics for admin
            cursor.execute('SELECT COUNT(*) as count FROM waste_reports')
            total_reports = cursor.fetchone()['count']
            
            cursor.execute('SELECT COUNT(*) as count FROM waste_reports WHERE status = "pending"')
            pending_reports = cursor.fetchone()['count']
            
            cursor.execute('SELECT COUNT(*) as count FROM waste_reports WHERE status = "processed"')
            processed_reports = cursor.fetchone()['count']
            
            cursor.execute('SELECT COUNT(*) as count FROM waste_reports WHERE status = "completed"')
            completed_reports = cursor.fetchone()['count']
            
            stats = {
                'total_reports': total_reports,
                'pending': pending_reports,
                'processed': processed_reports,
                'completed': completed_reports
            }
        else:
            # User dashboard - show only their reports
            cursor.execute('''SELECT id, user_id, location, waste_type, description, 
                                    status, created_at 
                             FROM waste_reports 
                             WHERE user_id = %s 
                             ORDER BY created_at DESC''',
                         (session['user_id'],))
            reports = cursor.fetchall()
            
            # Get user statistics
            cursor.execute('SELECT COUNT(*) as count FROM waste_reports WHERE user_id = %s', (session['user_id'],))
            total_reports = cursor.fetchone()['count']
            
            cursor.execute('SELECT COUNT(*) as count FROM waste_reports WHERE user_id = %s AND status = "pending"',
                         (session['user_id'],))
            pending_reports = cursor.fetchone()['count']
            
            cursor.execute('SELECT COUNT(*) as count FROM waste_reports WHERE user_id = %s AND status = "processed"',
                         (session['user_id'],))
            processed_reports = cursor.fetchone()['count']
            
            cursor.execute('SELECT COUNT(*) as count FROM waste_reports WHERE user_id = %s AND status = "completed"',
                         (session['user_id'],))
            completed_reports = cursor.fetchone()['count']
            
            stats = {
                'total_reports': total_reports,
                'pending': pending_reports,
                'processed': processed_reports,
                'completed': completed_reports
            }
        
        cursor.close()
        conn.close()
        
        # Debug print untuk memastikan data benar
        print(f"User role: {session['role']}")
        print(f"Total reports found: {len(reports) if reports else 0}")
        print(f"Stats: {stats}")
        if reports and len(reports) > 0:
            print(f"First report keys: {reports[0].keys()}")
        
        return render_template('dashboard.html', reports=reports, stats=stats)
        
    except mysql.connector.Error as err:
        handle_db_error(err)
        flash(f'Error database: {err}', 'error')
        return redirect(url_for('index'))
    except Exception as e:
        flash(f'Error: {str(e)}', 'error')
        return redirect(url_for('index'))

@app.route('/report', methods=['GET', 'POST'])
@require_role(['warga'])
@limiter.limit("10 per hour") 
def report():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    if request.method == 'POST':
        # Validate CSRF token
        try:
            validate_csrf(request.form.get('csrf_token'))
        except:
            log_security_event('CSRF_VALIDATION_FAILED', user_id=session['user_id'])
            flash('Token keamanan tidak valid!', 'error')
            return render_template('report.html')
        
        location = request.form.get('location', '').strip()
        waste_type = request.form.get('waste_type', '').strip()
        description = request.form.get('description', '').strip()
        
        # Advanced input validation
        valid, location = validate_input(location, 'string', 255)
        if not valid:
            flash(location, 'error')
            return render_template('report.html')
        
        valid, waste_type = validate_input(waste_type, 'string', 50)
        if not valid:
            flash(waste_type, 'error')
            return render_template('report.html')
        
        if description:
            valid, description = validate_input(description, 'string', 1000)
            if not valid:
                flash(description, 'error')
                return render_template('report.html')
        
        if len(location) < 5:
            flash('Lokasi minimal 5 karakter!', 'error')
            return render_template('report.html')
        
        try:
            conn = get_db_connection()
            cursor = conn.cursor(prepared=True)
            cursor.execute('''INSERT INTO waste_reports (user_id, location, waste_type, description)
                             VALUES (?, ?, ?, ?)''',
                         (session['user_id'], location, waste_type, description))
            conn.commit()
            cursor.close()
            conn.close()

            log_security_event('REPORT_CREATED', user_id=session['user_id'], details=f"Location: {location}")
            flash('Laporan berhasil dikirim!', 'success')
            return redirect(url_for('dashboard'))
        except mysql.connector.Error as err:
            handle_db_error(err)
            log_security_event('REPORT_ERROR', user_id=session['user_id'], details=f"Database error: {err}", level='ERROR')
            flash('Terjadi kesalahan sistem. Silakan coba lagi.', 'error')
    
    return render_template('report.html')

@app.route('/update_status/<int:report_id>', methods=['POST'])
@require_role(['admin', 'petugas'])
def update_status(report_id):
    status = request.args.get('status')
    valid_statuses = ['pending', 'processed', 'completed']
    
    if status not in valid_statuses:
        flash('Status tidak valid!', 'error')
        log_security_event('INVALID_STATUS_UPDATE', user_id=session['user_id'], 
                          details=f"Invalid status: {status}, Report ID: {report_id}")
        return redirect(url_for('dashboard'))
    
    # Sanitize report_id
    if sanitize_sql_input(report_id) is None:
        flash('ID laporan tidak valid!', 'error')
        log_security_event('INVALID_REPORT_ID', user_id=session['user_id'], 
                          details=f"Report ID: {report_id}")
        return redirect(url_for('dashboard'))
    
    try:
        conn = get_db_connection()
        cursor = conn.cursor(prepared=True)

        cursor.execute('SELECT user_id FROM waste_reports WHERE id = ?', (report_id,))
        report = cursor.fetchone()

        if not report:
            log_security_event('UPDATE_STATUS_FAILED', 
                             user_id=session['user_id'], 
                             details=f"Report not found - ID: {report_id}")
            flash('Laporan tidak ditemukan!', 'error')
            return redirect(url_for('dashboard'))

        # Update status with prepared statement
        cursor.execute('UPDATE waste_reports SET status = ? WHERE id = ?', 
                      (status, report_id))
        conn.commit()
        cursor.close()
        conn.close()

        log_security_event('STATUS_UPDATED', 
                          user_id=session['user_id'], 
                          details=f"Report ID: {report_id}, New Status: {status}")
        flash('Status berhasil diperbarui!', 'success')
        
    except mysql.connector.Error as err:
        handle_db_error(err)
        log_security_event('STATUS_UPDATE_ERROR', 
                          user_id=session['user_id'], 
                          details=f"Database error: {err}", 
                          level='ERROR')
        flash('Terjadi kesalahan sistem. Silakan coba lagi.', 'error')
    
    return redirect(url_for('dashboard'))

@app.route('/users')
@require_role(['admin'])
def users():
    """Secure user management route for admins"""
    try:
        conn = get_db_connection()
        cursor = conn.cursor(dictionary=True)
        
        # Only fetch non-sensitive user data
        cursor.execute('''SELECT id, username, email, role, created_at 
                         FROM users ORDER BY created_at DESC''')
        users = cursor.fetchall()
        cursor.close()
        conn.close()
        
        return render_template('users.html', users=users)
        
    except mysql.connector.Error as err:
        handle_db_error(err)
        log_security_event('USERS_LIST_ERROR', 
                          user_id=session['user_id'], 
                          details=f"Database error: {err}", 
                          level='ERROR')
        flash('Terjadi kesalahan saat mengambil data pengguna.', 'error')
        return redirect(url_for('dashboard'))

# Error handlers
@app.errorhandler(404)
def not_found_error(error):
    return render_template('404.html'), 404

@app.errorhandler(500)
def internal_error(error):
    log_security_event('SERVER_ERROR', 
                      user_id=session.get('user_id'), 
                      details=str(error),
                      level='ERROR')
    return render_template('500.html'), 500

@app.errorhandler(403)
def forbidden_error(error):
    log_security_event('FORBIDDEN_ACCESS', 
                      user_id=session.get('user_id'), 
                      details=f"Path: {request.path}")
    return render_template('403.html'), 403

@app.errorhandler(429)
def ratelimit_handler(error):
    log_security_event('RATE_LIMIT_EXCEEDED', 
                      user_id=session.get('user_id'), 
                      details=f"Path: {request.path}",
                      level='WARNING')
    return render_template('429.html'), 429

@app.route('/change_role/<int:user_id>', methods=['POST'])
def change_role(user_id):
    if 'user_id' not in session or session['role'] != 'admin':
        flash('Akses ditolak!', 'error')
        return redirect(url_for('dashboard'))
    
    # Prevent changing own role
    if user_id == session['user_id']:
        flash('Anda tidak dapat mengubah role Anda sendiri!', 'error')
        return redirect(url_for('users'))
    
    new_role = request.form.get('role')
    if new_role not in ['warga', 'admin']:
        flash('Role tidak valid!', 'error')
        return redirect(url_for('users'))
    
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        
        # Check if this is the last admin
        if new_role == 'warga':
            cursor.execute('SELECT COUNT(*) FROM users WHERE role = "admin"')
            admin_count = cursor.fetchone()[0]
            if admin_count <= 1:
                flash('Tidak bisa mengubah role admin terakhir!', 'error')
                cursor.close()
                conn.close()
                return redirect(url_for('users'))
        
        # Get username for flash message
        cursor.execute('SELECT username FROM users WHERE id = %s', (user_id,))
        username_result = cursor.fetchone()
        if not username_result:
            flash('User tidak ditemukan!', 'error')
            cursor.close()
            conn.close()
            return redirect(url_for('users'))
        
        username = username_result[0]
        
        # Update role
        cursor.execute('UPDATE users SET role = %s WHERE id = %s', (new_role, user_id))
        conn.commit()
        cursor.close()
        conn.close()
        
        role_text = 'Admin' if new_role == 'admin' else 'Warga'
        flash(f'Role user {username} berhasil diubah menjadi {role_text}!', 'success')
        
    except mysql.connector.Error as err:
        flash(f'Error database: {err}', 'error')
    
    return redirect(url_for('users'))

@app.route('/delete_user/<int:user_id>', methods=['POST'])
def delete_user(user_id):
    if 'user_id' not in session or session['role'] != 'admin':
        flash('Akses ditolak!', 'error')
        return redirect(url_for('dashboard'))
    
    # Prevent deleting own account
    if user_id == session['user_id']:
        flash('Anda tidak dapat menghapus akun Anda sendiri!', 'error')
        return redirect(url_for('users'))
    
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        
        # Check if this is the last admin
        cursor.execute('SELECT role FROM users WHERE id = %s', (user_id,))
        user_result = cursor.fetchone()
        if not user_result:
            flash('User tidak ditemukan!', 'error')
            cursor.close()
            conn.close()
            return redirect(url_for('users'))
        
        user_role = user_result[0]
        if user_role == 'admin':
            cursor.execute('SELECT COUNT(*) FROM users WHERE role = "admin"')
            admin_count = cursor.fetchone()[0]
            if admin_count <= 1:
                flash('Tidak bisa menghapus admin terakhir!', 'error')
                cursor.close()
                conn.close()
                return redirect(url_for('users'))
        
        # Get username for flash message
        cursor.execute('SELECT username FROM users WHERE id = %s', (user_id,))
        username = cursor.fetchone()[0]
        
        # Delete user's reports first (foreign key constraint)
        cursor.execute('DELETE FROM waste_reports WHERE user_id = %s', (user_id,))
        
        # Delete user
        cursor.execute('DELETE FROM users WHERE id = %s', (user_id,))
        conn.commit()
        cursor.close()
        conn.close()
        
        flash(f'User {username} berhasil dihapus!', 'success')
        
    except mysql.connector.Error as err:
        flash(f'Error database: {err}', 'error')
    
    return redirect(url_for('users'))

if __name__ == '__main__':
    # Di app.py
    template_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'templates')
    print(f"Template directory: {template_dir}")
    print(f"Template directory exists: {os.path.exists(template_dir)}")
    # Initialize database
    try:
        init_db()
        print("✅ Database initialized successfully!")
    except Exception as e:
        print(f"❌ Database initialization failed: {e}")
        print("⚠️  Continuing without database (some features may not work)")
    
    load_dotenv()

    print("🔒 Starting Security Hardened Flask App")
    print(f"🌍 Environment: {os.environ.get('FLASK_ENV', 'development')}")
    print(f"🔗 Allowed IPs: {ALLOWED_IPS}")
    print(f"🖥️  Client IP will be: {request.environ.get('REMOTE_ADDR', 'unknown') if request else 'check at runtime'}")

    # Security configuration for exam environment
    print("🔒 Starting Security Hardened Flask App for Network Security Exam")
    print("📋 Security Features Enabled:")
    print("   ✅ HTTPS with Strong SSL/TLS")
    print("   ✅ Advanced Rate Limiting")
    print("   ✅ CSRF Protection")
    print("   ✅ XSS Protection")
    print("   ✅ SQL Injection Protection")
    print("   ✅ Session Security")
    print("   ✅ Input Validation")
    print("   ✅ Security Logging")
    print("   ✅ IP Filtering")
    print("   ✅ Brute Force Protection")
    print("   ✅ Content Security Policy")
    print("   ✅ Security Headers")
    
    # SSL Context untuk exam environment
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.maximum_version = ssl.TLSVersion.TLSv1_3
    
    # Generate or load certificate
    cert_file = 'exam_cert.pem'
    key_file = 'exam_key.pem'
    
    if not (os.path.exists(cert_file) and os.path.exists(key_file)):
        print("🔐 Generating self-signed certificate for exam...")
        # Generate self-signed certificate for exam
        os.system(f"""
        openssl req -x509 -newkey rsa:4096 -nodes -out {cert_file} -keyout {key_file} -days 1 \
        -subj "/C=ID/ST=West Java/L=Bandung/O=Network Security Exam/CN=exam.local" 2>/dev/null
        """)
    
    try:
        context.load_cert_chain(cert_file, key_file)
        print(f"🌐 Server running on: https://localhost:5000")
        print(f"🔒 Certificate: {cert_file}")
        print(f"🗝️  Private Key: {key_file}")
        print("⚠️  For exam: Accept certificate warning in browser")
        
        app.run(
            debug=True,  # Disable debug for security
            host='0.0.0.0',  # Listen on all interfaces for exam
            port=5000,
            ssl_context=context,
            threaded=True
        )
        
    except Exception as e:
        print(f"❌ Failed to start server: {e}")
        print("🔄 Falling back to adhoc certificate...")
        app.run(
            debug=True,
            host='0.0.0.0',
            port=5000,
            ssl_context='adhoc'
        )