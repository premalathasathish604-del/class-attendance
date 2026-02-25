from flask import Flask, render_template, request, redirect, url_for, session, flash
import sqlite3
from werkzeug.security import generate_password_hash, check_password_hash
from functools import wraps
import os

app = Flask(__name__)
app.secret_key = 'super_secret_key'
DB_PATH = 'database.db'

def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

# Auth Decorators
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if session.get('role') != 'admin':
            flash('Admin access required!', 'danger')
            return redirect(url_for('student_dashboard'))
        return f(*args, **kwargs)
    return decorated_function

def management_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if session.get('role') not in ['management', 'admin']:
            flash('Management access required!', 'danger')
            return redirect(url_for('student_dashboard'))
        return f(*args, **kwargs)
    return decorated_function

def faculty_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if session.get('role') not in ['faculty', 'admin', 'management']:
            flash('Faculty access required!', 'danger')
            return redirect(url_for('student_dashboard'))
        return f(*args, **kwargs)
    return decorated_function

@app.route('/')
def index():
    if 'user_id' in session:
        role = session['role']
        if role == 'admin':
            return redirect(url_for('admin_dashboard'))
        elif role == 'management':
            return redirect(url_for('management_dashboard'))
        elif role == 'faculty':
            return redirect(url_for('faculty_dashboard'))
        return redirect(url_for('student_dashboard'))
    return redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        login_id = request.form['login_id'] # Can be email or username
        password = request.form['password']
        
        db = get_db()
        # Allow login via email or username
        user = db.execute('SELECT * FROM users WHERE email = ? OR username = ?', (login_id, login_id)).fetchone()
        db.close()
        
        if user and check_password_hash(user['password'], password):
            session['user_id'] = user['id']
            session['name'] = user['name']
            session['role'] = user['role']
            flash(f'Welcome back, {user["name"]}!', 'success')
            
            role = user['role']
            if role == 'admin':
                return redirect(url_for('admin_dashboard'))
            elif role == 'management':
                return redirect(url_for('management_dashboard'))
            elif role == 'faculty':
                return redirect(url_for('faculty_dashboard'))
            return redirect(url_for('student_dashboard'))
        else:
            flash('Invalid credentials', 'danger')
            
    return render_template('login.html')

@app.route('/logout')
def logout():
    session.clear()
    flash('You have been logged out.', 'info')
    return redirect(url_for('login'))

@app.route('/admin/dashboard')
@login_required
@admin_required
def admin_dashboard():
    db = get_db()
    total_students = db.execute('SELECT COUNT(*) FROM users WHERE role = "student"').fetchone()[0]
    total_faculty = db.execute('SELECT COUNT(*) FROM users WHERE role = "faculty"').fetchone()[0]
    pending_requests = db.execute('SELECT COUNT(*) FROM leave_requests WHERE status = "Pending"').fetchone()[0]
    db.close()
    return render_template('admin_dashboard.html', total_students=total_students, 
                           total_faculty=total_faculty, pending_requests=pending_requests)

@app.route('/student/dashboard')
@login_required
def student_dashboard():
    db = get_db()
    user_id = session['user_id']
    leaves = db.execute('SELECT * FROM leave_requests WHERE student_id = ?', (user_id,)).fetchall()
    attendance = db.execute('SELECT * FROM attendance WHERE student_id = ?', (user_id,)).fetchall()
    
    total_days = len(attendance)
    present_days = sum(1 for a in attendance if a['status'] == 'Present')
    attendance_pct = (present_days / total_days * 100) if total_days > 0 else 0
    
    db.close()
    return render_template('student_dashboard.html', leaves=leaves, attendance_pct=round(attendance_pct, 1))

import csv
from io import StringIO
from flask import make_response

@app.route('/admin/attendance', methods=['GET', 'POST'])
@login_required
@admin_required
def admin_attendance():
    db = get_db()
    date = request.form.get('date', os.popen('date /t').read().strip())
    if request.method == 'POST' and 'mark' in request.form:
        for key, value in request.form.items():
            if key.startswith('status_'):
                student_id = key.split('_')[1]
                existing = db.execute('SELECT id FROM attendance WHERE student_id = ? AND date = ?', 
                                     (student_id, date)).fetchone()
                if existing:
                    db.execute('UPDATE attendance SET status = ? WHERE id = ?', (value, existing['id']))
                else:
                    db.execute('INSERT INTO attendance (student_id, date, status) VALUES (?, ?, ?)',
                               (student_id, date, value))
        db.commit()
        flash('Attendance updated!', 'success')
                
    students = db.execute('SELECT * FROM users WHERE role = "student"').fetchall()
    db.close()
    return render_template('admin_attendance.html', students=students, date=date)

@app.route('/admin/export_attendance')
@login_required
@admin_required
def export_attendance():
    db = get_db()
    attendance = db.execute('''
        SELECT users.name, attendance.date, attendance.status 
        FROM attendance 
        JOIN users ON attendance.student_id = users.id
        ORDER BY date DESC
    ''').fetchall()
    db.close()

    si = StringIO()
    cw = csv.writer(si)
    cw.writerow(['Student Name', 'Date', 'Status'])
    for row in attendance:
        cw.writerow([row['name'], row['date'], row['status']])

    output = make_response(si.getvalue())
    output.headers["Content-Disposition"] = "attachment; filename=attendance_report.csv"
    output.headers["Content-type"] = "text/csv"
    return output

@app.route('/faculty/dashboard')
@login_required
@faculty_required
def faculty_dashboard():
    db = get_db()
    user_id = session['user_id']
    requests = db.execute('SELECT * FROM leave_requests WHERE student_id = ?', (user_id,)).fetchall()
    db.close()
    return render_template('faculty_dashboard.html', requests=requests)

@app.route('/management/dashboard')
@login_required
@management_required
def management_dashboard():
    db = get_db()
    total_students = db.execute('SELECT COUNT(*) FROM users WHERE role = "student"').fetchone()[0]
    total_faculty = db.execute('SELECT COUNT(*) FROM users WHERE role = "faculty"').fetchone()[0]
    total_requests = db.execute('SELECT COUNT(*) FROM leave_requests').fetchone()[0]
    db.close()
    return render_template('management_dashboard.html', total_students=total_students, 
                           total_faculty=total_faculty, total_requests=total_requests)

@app.route('/admin/users', methods=['GET', 'POST'])
@login_required
@admin_required
def manage_users():
    db = get_db()
    search = request.args.get('search', '')
    role_filter = request.args.get('role', '')
    
    if request.method == 'POST':
        name = request.form['name']
        email = request.form.get('email')
        username = request.form.get('username')
        password = generate_password_hash(request.form['password'])
        role = request.form['role']
        try:
            db.execute('INSERT INTO users (name, email, username, password, role) VALUES (?, ?, ?, ?, ?)',
                       (name, email, username, password, role))
            db.commit()
            flash(f'{role.capitalize()} added successfully!', 'success')
        except sqlite3.IntegrityError:
            flash('Email or Username already exists!', 'danger')
            
    query = 'SELECT * FROM users WHERE role NOT IN ("admin")'
    params = []
    if search:
        query += ' AND (name LIKE ? OR email LIKE ?)'
        params.extend(['%' + search + '%', '%' + search + '%'])
    if role_filter:
        query += ' AND role = ?'
        params.append(role_filter)
        
    users = db.execute(query, params).fetchall()
    db.close()
    return render_template('manage_users.html', users=users, search=search, role_filter=role_filter)

@app.route('/admin/delete_user/<int:id>')
@login_required
@admin_required
def delete_user(id):
    db = get_db()
    db.execute('DELETE FROM users WHERE id = ?', (id,))
    db.commit()
    db.close()
    flash('User deleted!', 'info')
    return redirect(url_for('manage_users'))

@app.route('/admin/requests')
@login_required
@admin_required
def view_requests():
    db = get_db()
    requests = db.execute('''
        SELECT leave_requests.*, users.name, users.role 
        FROM leave_requests 
        JOIN users ON leave_requests.student_id = users.id
        ORDER BY status DESC, from_date DESC
    ''').fetchall()
    db.close()
    return render_template('admin_requests.html', requests=requests)

@app.route('/admin/request/<int:id>/<action>')
@login_required
@admin_required
def handle_request(id, action):
    status = 'Approved' if action == 'approve' else 'Rejected'
    db = get_db()
    db.execute('UPDATE leave_requests SET status = ? WHERE id = ?', (status, id))
    db.commit()
    db.close()
    flash(f'Request {status}!', 'success')
    return redirect(url_for('view_requests'))

# Unified Apply Request Route
@app.route('/apply_request', methods=['GET', 'POST'])
@login_required
def apply_request():
    if request.method == 'POST':
        db = get_db()
        db.execute('''
            INSERT INTO leave_requests (student_id, from_date, to_date, reason, req_type, category) 
            VALUES (?, ?, ?, ?, ?, ?)
        ''', (session['user_id'], request.form['from_date'], 
              request.form['to_date'], request.form['reason'], 
              request.form['req_type'], request.form['category']))
        db.commit()
        db.close()
        flash(f'{request.form["req_type"]} request submitted!', 'success')
        if session['role'] == 'faculty':
            return redirect(url_for('faculty_dashboard'))
        return redirect(url_for('student_dashboard'))
    return render_template('apply_request.html')

if __name__ == '__main__':
    app.run(debug=True)
