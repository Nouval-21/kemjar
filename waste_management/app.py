from flask import Flask, render_template, request, redirect, url_for, session, flash
import mysql.connector
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime
import os

app = Flask(__name__)
app.secret_key = 'your-secret-key-here'  # Ganti dengan key yang lebih aman

# Database configuration - GANTI SESUAI SETTING MYSQL ANDA
DB_CONFIG = {
    'host': 'localhost',
    'user': 'root',          # Ganti dengan username MySQL Anda
    'password': '',          # Ganti dengan password MySQL Anda
    'database': 'waste_management'
}

# Database connection
def get_db_connection():
    return mysql.connector.connect(**DB_CONFIG)

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
        cursor.execute("CREATE DATABASE IF NOT EXISTS waste_management")
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
        admin_password = generate_password_hash('admin123')
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

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        password = request.form['password']
        
        if not username or not email or not password:
            flash('Semua field harus diisi!', 'error')
            return render_template('register.html')
        
        hashed_password = generate_password_hash(password)
        
        try:
            conn = get_db_connection()
            cursor = conn.cursor()
            cursor.execute('INSERT INTO users (username, email, password) VALUES (%s, %s, %s)',
                         (username, email, hashed_password))
            conn.commit()
            cursor.close()
            conn.close()
            
            flash('Registrasi berhasil! Silakan login.', 'success')
            return redirect(url_for('login'))
        except mysql.connector.IntegrityError:
            flash('Username atau email sudah digunakan!', 'error')
        except mysql.connector.Error as err:
            flash(f'Error database: {err}', 'error')
    
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        try:
            conn = get_db_connection()
            cursor = conn.cursor()
            cursor.execute('SELECT * FROM users WHERE username = %s', (username,))
            user = cursor.fetchone()
            cursor.close()
            conn.close()
            
            if user and check_password_hash(user[3], password):
                session['user_id'] = user[0]
                session['username'] = user[1]
                session['role'] = user[4]
                
                flash(f'Selamat datang, {username}!', 'success')
                return redirect(url_for('dashboard'))
            else:
                flash('Username atau password salah!', 'error')
        except mysql.connector.Error as err:
            flash(f'Error database: {err}', 'error')
    
    return render_template('login.html')

@app.route('/logout')
def logout():
    session.clear()
    flash('Anda telah logout.', 'info')
    return redirect(url_for('index'))

@app.route('/dashboard')
def dashboard():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        
        if session['role'] == 'admin':
            # Admin dashboard - show all reports
            cursor.execute('''SELECT wr.*, u.username 
                             FROM waste_reports wr 
                             JOIN users u ON wr.user_id = u.id 
                             ORDER BY wr.created_at DESC''')
            reports = cursor.fetchall()
            
            # Get statistics
            cursor.execute('SELECT COUNT(*) FROM waste_reports')
            total_reports = cursor.fetchone()[0]
            
            cursor.execute('SELECT COUNT(*) FROM waste_reports WHERE status = "pending"')
            pending_reports = cursor.fetchone()[0]
            
            cursor.execute('SELECT COUNT(*) FROM waste_reports WHERE status = "completed"')
            completed_reports = cursor.fetchone()[0]
            
            stats = {
                'total': total_reports,
                'pending': pending_reports,
                'completed': completed_reports
            }
        else:
            # User dashboard - show only their reports
            cursor.execute('SELECT * FROM waste_reports WHERE user_id = %s ORDER BY created_at DESC',
                         (session['user_id'],))
            reports = cursor.fetchall()
            
            # Get user statistics
            cursor.execute('SELECT COUNT(*) FROM waste_reports WHERE user_id = %s', (session['user_id'],))
            total_reports = cursor.fetchone()[0]
            
            cursor.execute('SELECT COUNT(*) FROM waste_reports WHERE user_id = %s AND status = "pending"',
                         (session['user_id'],))
            pending_reports = cursor.fetchone()[0]
            
            cursor.execute('SELECT COUNT(*) FROM waste_reports WHERE user_id = %s AND status = "completed"',
                         (session['user_id'],))
            completed_reports = cursor.fetchone()[0]
            
            stats = {
                'total': total_reports,
                'pending': pending_reports,
                'completed': completed_reports
            }
        
        cursor.close()
        conn.close()
        return render_template('dashboard.html', reports=reports, stats=stats)
        
    except mysql.connector.Error as err:
        flash(f'Error database: {err}', 'error')
        return redirect(url_for('index'))

@app.route('/report', methods=['GET', 'POST'])
def report():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    if request.method == 'POST':
        location = request.form['location']
        waste_type = request.form['waste_type']
        description = request.form['description']
        
        if not location or not waste_type:
            flash('Lokasi dan jenis sampah harus diisi!', 'error')
            return render_template('report.html')
        
        try:
            conn = get_db_connection()
            cursor = conn.cursor()
            cursor.execute('''INSERT INTO waste_reports (user_id, location, waste_type, description)
                             VALUES (%s, %s, %s, %s)''',
                         (session['user_id'], location, waste_type, description))
            conn.commit()
            cursor.close()
            conn.close()
            
            flash('Laporan berhasil dikirim!', 'success')
            return redirect(url_for('dashboard'))
        except mysql.connector.Error as err:
            flash(f'Error database: {err}', 'error')
    
    return render_template('report.html')

@app.route('/update_status/<int:report_id>')
def update_status(report_id):
    if 'user_id' not in session or session['role'] != 'admin':
        flash('Akses ditolak!', 'error')
        return redirect(url_for('dashboard'))
    
    status = request.args.get('status')
    if status not in ['pending', 'processed', 'completed']:
        flash('Status tidak valid!', 'error')
        return redirect(url_for('dashboard'))
    
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute('UPDATE waste_reports SET status = %s WHERE id = %s', (status, report_id))
        conn.commit()
        cursor.close()
        conn.close()
        
        flash(f'Status laporan berhasil diubah menjadi {status}!', 'success')
    except mysql.connector.Error as err:
        flash(f'Error database: {err}', 'error')
    
    return redirect(url_for('dashboard'))

@app.route('/users')
def users():
    if 'user_id' not in session or session['role'] != 'admin':
        flash('Akses ditolak!', 'error')
        return redirect(url_for('dashboard'))
    
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute('SELECT id, username, email, role, created_at FROM users ORDER BY created_at DESC')
        user_list = cursor.fetchall()
        cursor.close()
        conn.close()
        
        return render_template('users.html', users=user_list)
    except mysql.connector.Error as err:
        flash(f'Error database: {err}', 'error')
        return redirect(url_for('dashboard'))

if __name__ == '__main__':
    init_db()
    app.run(debug=True)

# Install mysql-connector-python
# pip install mysql-connector-python