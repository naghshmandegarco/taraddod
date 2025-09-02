# app.py
# این فایل بک‌اند (Backend) برنامه است و منطق اصلی را مدیریت می‌کند.

from flask import Flask, render_template, request, redirect, url_for, jsonify, Response, session, send_from_directory, flash
import sqlite3
from datetime import datetime
import os
import csv
import io
import jdatetime # Import the jdatetime library
import urllib.parse
import zipfile
from functools import wraps
import json
from werkzeug.security import generate_password_hash, check_password_hash

# یک فایل دیتابیس به نام time_tracker.db ایجاد می‌کنیم
DB_FILE = 'time_tracker.db'
app = Flask(__name__)
app.secret_key = 'a_very_secure_and_random_key_that_is_changed_often' # تغییر به یک کلید امنیتی قوی

# Helper function to check for permissions
def has_permission(page_name):
    user_permissions = session.get('user', {}).get('permissions', {})
    # Admin has all permissions by default
    if session.get('user', {}).get('role') == 'admin':
        return True
    return user_permissions.get(page_name, False)

# Decorator to check if user is logged in
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user' not in session:
            flash("لطفاً برای دسترسی به این صفحه وارد شوید.", "error")
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

# Decorator to check if user has a specific role
def role_required(role):
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if 'user' not in session or session['user']['role'] != role:
                flash("شما به این بخش دسترسی ندارید.", "error")
                return redirect(url_for('index'))
            return f(*args, **kwargs)
        return decorated_function
    return decorator

# تابع برای اتصال به دیتابیس
def get_db_connection():
    conn = sqlite3.connect(DB_FILE)
    conn.row_factory = sqlite3.Row
    return conn

# تابع برای ایجاد جداول دیتابیس و بروزرسانی ساختار
def init_db():
    conn = get_db_connection()
    cursor = conn.cursor()
    # جدول time_logs: برای ثبت ورود و خروج
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS time_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            employee_id TEXT NOT NULL,
            action TEXT NOT NULL,
            timestamp TEXT NOT NULL
        )
    ''')
    # جدول employees: برای مدیریت اطلاعات کارکنان
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS employees (
            employee_id TEXT PRIMARY KEY,
            name TEXT NOT NULL
        )
    ''')
    # جدول users: برای ورود و کنترل دسترسی (رمز عبور حالا هش شده است)
    # اضافه شدن فیلد "name" به جدول users
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            username TEXT PRIMARY KEY,
            name TEXT NOT NULL,
            password TEXT NOT NULL,
            role TEXT NOT NULL,
            permissions TEXT NOT NULL DEFAULT '{}'
        )
    ''')
    # جدول user_logs: برای ثبت فعالیت‌های کاربران
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS user_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL,
            action TEXT NOT NULL,
            details TEXT,
            timestamp TEXT NOT NULL
        )
    ''')
    # NEW TABLE: petty_cash for managing petty cash transactions
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS petty_cash (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            date TEXT NOT NULL,
            description TEXT,
            unit TEXT,
            amount INTEGER,
            unit_price REAL,
            discount TEXT,
            total_amount REAL,
            location TEXT,
            notes TEXT,
            source TEXT,
            invoice_number TEXT,
            settlement_status TEXT NOT NULL,
            payer TEXT NOT NULL,
            receipt_image BLOB,
            timestamp TEXT NOT NULL
        )
    ''')
    
    # Check if 'name' column exists in 'users' table, and add it if not
    try:
        cursor.execute("SELECT name FROM users LIMIT 1")
    except sqlite3.OperationalError:
        cursor.execute("ALTER TABLE users ADD COLUMN name TEXT")
        cursor.execute("UPDATE users SET name = username WHERE name IS NULL")
        
    conn.commit()
    conn.close()

# این تابع در هنگام اجرای برنامه، دیتابیس را آماده می‌کند
# با فراخوانی init_db در هر بار اجرا، از وجود تمام جداول اطمینان حاصل می‌شود.
init_db()

# این بخش فقط در صورتی اجرا می‌شود که کاربر admin برای اولین بار ایجاد شود.
conn = get_db_connection()
try:
    admin_exists = conn.execute("SELECT 1 FROM users WHERE username = 'admin'").fetchone()
    if not admin_exists:
        hashed_password = generate_password_hash('admin')
        conn.execute("INSERT INTO users (username, name, password, role, permissions) VALUES (?, ?, ?, ?, ?)", 
                     ('admin', 'مدیر سیستم', hashed_password, 'admin', json.dumps({'index': True, 'management': True, 'reports': True, 'users': True, 'petty_cash': True})))
        conn.commit()
finally:
    conn.close()

# تابع کمکی برای ثبت فعالیت‌های کاربر
def log_action(username, action, details=""):
    conn = get_db_connection()
    try:
        timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        conn.execute('INSERT INTO user_logs (username, action, details, timestamp) VALUES (?, ?, ?, ?)',
                     (username, action, details, timestamp))
        conn.commit()
    except Exception as e:
        print(f"Error logging action: {e}")
        conn.rollback()
    finally:
        conn.close()

# NEW ROUTE: Login page
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username'].lower()
        password = request.form['password']
        
        conn = get_db_connection()
        user = conn.execute("SELECT * FROM users WHERE username = ?", (username,)).fetchone()
        conn.close()
        
        if user and check_password_hash(user['password'], password):
            session['user'] = {
                'username': user['username'],
                'name': user['name'],
                'role': user['role'],
                'permissions': json.loads(user['permissions'])
            }
            log_action(user['username'], 'ورود به سیستم', 'ورود موفق')
            flash("ورود با موفقیت انجام شد.", "success")
            return redirect(url_for('index'))
        else:
            flash("نام کاربری یا رمز عبور اشتباه است.", "error")
            return redirect(url_for('login'))
    
    return render_template('login.html')

# NEW ROUTE: Logout
@app.route('/logout')
def logout():
    username = session.get('user', {}).get('username')
    if username:
        log_action(username, 'خروج از سیستم', 'خروج موفق')
    session.pop('user', None)
    flash("شما با موفقیت از سیستم خارج شدید.", "success")
    return redirect(url_for('login'))

# روت برای صفحه اصلی
@app.route('/')
@login_required
def index():
    if not has_permission('index'):
        flash("شما به این بخش دسترسی ندارید.", "error")
        return redirect(url_for('login'))
        
    conn = get_db_connection()
    try:
        employees = conn.execute('SELECT * FROM employees ORDER BY name').fetchall()
        total_employees_row = conn.execute('SELECT COUNT(*) AS count FROM employees').fetchone()
        total_employees = total_employees_row['count'] if total_employees_row else 0
        
        present_employees_names = []
        
        employees_dict = {str(emp['employee_id']): emp['name'] for emp in employees}

        latest_actions = conn.execute('''
            SELECT employee_id, action
            FROM time_logs
            WHERE id IN (
                SELECT MAX(id)
                FROM time_logs
                GROUP BY employee_id
            )
        ''').fetchall()

        for action_log in latest_actions:
            if action_log['action'] == 'ورود':
                employee_id = action_log['employee_id']
                if employee_id in employees_dict:
                    present_employees_names.append(employees_dict[employee_id])
        
        present_employees_count = len(present_employees_names)
    finally:
        conn.close()
    
    return render_template('index.html', 
                           employees=employees,
                           total_employees=total_employees,
                           present_employees=present_employees_count,
                           present_employees_names=present_employees_names)

# NEW ROUTE: Check the status of selected employees before bulk submission
@app.route('/check_status', methods=['POST'])
@login_required
def check_status():
    if not has_permission('index'):
        return jsonify({'error': 'Access Denied'}), 403
        
    conn = get_db_connection()
    employee_ids = request.json.get('employee_ids')
    status = {}
    try:
        for employee_id in employee_ids:
            latest_action_row = conn.execute('SELECT action FROM time_logs WHERE employee_id = ? ORDER BY timestamp DESC LIMIT 1', (employee_id,)).fetchone()
            status[employee_id] = latest_action_row['action'] if latest_action_row else 'خروج'
    finally:
        conn.close()
    return jsonify(status)

# روت برای صفحه مدیریت کارکنان
@app.route('/management')
@login_required
def management():
    if not has_permission('management'):
        flash("شما به این بخش دسترسی ندارید.", "error")
        return redirect(url_for('index'))

    conn = get_db_connection()
    try:
        employees = conn.execute('SELECT * FROM employees ORDER BY CAST(employee_id AS INTEGER) ASC').fetchall()
        
        next_employee_id = get_next_employee_id(conn)
    finally:
        conn.close()

    log_action(session['user']['username'], 'مشاهده صفحه مدیریت کارکنان')
    return render_template('management.html', employees=employees, next_employee_id=next_employee_id)

def get_next_employee_id(conn):
    last_id_row = conn.execute('SELECT employee_id FROM employees ORDER BY CAST(employee_id AS INTEGER) DESC LIMIT 1').fetchone()
    if last_id_row:
        try:
            last_id = int(last_id_row['employee_id'])
            return str(last_id + 1)
        except (ValueError, TypeError):
            return '1'
    return '1'

# روت برای صفحه گزارشات
@app.route('/reports')
@login_required
def reports():
    if not has_permission('reports'):
        flash("شما به این بخش دسترسی ندارید.", "error")
        return redirect(url_for('index'))

    conn = get_db_connection()
    
    employee_id_filter = request.args.get('employee_id')
    start_date_fa = request.args.get('start_date')
    end_date_fa = request.args.get('end_date')

    query = '''
        SELECT tl.id, tl.employee_id, e.name, tl.action, tl.timestamp
        FROM time_logs tl
        JOIN employees e ON tl.employee_id = e.employee_id
    '''
    params = []
    conditions = []
    
    if employee_id_filter and employee_id_filter != 'all':
        conditions.append('tl.employee_id = ?')
        params.append(employee_id_filter)
    
    if start_date_fa:
        try:
            j_date_parts = start_date_fa.split('/')
            j_date = jdatetime.date(int(j_date_parts[0]), int(j_date_parts[1]), int(j_date_parts[2]))
            g_date = j_date.togregorian()
            conditions.append('tl.timestamp >= ?')
            params.append(g_date.strftime('%Y-%m-%d 00:00:00'))
        except (ValueError, IndexError):
            flash("فرمت تاریخ شروع نامعتبر است.", "error")
            pass
            
    if end_date_fa:
        try:
            j_date_parts = end_date_fa.split('/')
            j_date = jdatetime.date(int(j_date_parts[0]), int(j_date_parts[1]), int(j_date_parts[2]))
            g_date = j_date.togregorian()
            conditions.append('tl.timestamp <= ?')
            params.append(g_date.strftime('%Y-%m-%d 23:59:59'))
        except (ValueError, IndexError):
            flash("فرمت تاریخ پایان نامعتبر است.", "error")
            pass

    if conditions:
        query += ' WHERE ' + ' AND '.join(conditions)

    query += ' ORDER BY tl.timestamp DESC'

    try:
        records = conn.execute(query, params).fetchall()
        employees = conn.execute('SELECT * FROM employees ORDER BY name').fetchall()
    finally:
        conn.close()

    fa_records = []
    for record in records:
        miladi_dt = datetime.strptime(record['timestamp'], '%Y-%m-%d %H:%M:%S')
        shamsi_dt = jdatetime.datetime.fromgregorian(datetime=miladi_dt)
        fa_records.append({
            'id': record['id'],
            'employee_id': record['employee_id'],
            'name': record['name'],
            'action': record['action'],
            'timestamp_fa': shamsi_dt.strftime('%Y/%m/%d %H:%M:%S'),
            'timestamp_miladi': miladi_dt.strftime('%Y-%m-%d %H:%M:%S')
        })

    log_action(session['user']['username'], 'مشاهده صفحه گزارشات')
    return render_template('reports.html', 
                           records=fa_records, 
                           employees=employees,
                           selected_employee_id=employee_id_filter,
                           start_date=start_date_fa,
                           end_date=end_date_fa)

# NEW ROUTE: Submit bulk entries/exits
@app.route('/bulk_submit', methods=['POST'])
@login_required
def bulk_submit():
    if not has_permission('index'):
        flash("شما به این بخش دسترسی ندارید.", "error")
        return redirect(url_for('index'))

    employee_ids = request.form.getlist('employee_ids')
    action = request.form.get('action')
    timestamps_list = request.form.getlist('timestamps')
    
    if not employee_ids or not action or not timestamps_list:
        flash("هیچ کارمندی برای ثبت انتخاب نشد.", "warning")
        return redirect(url_for('index'))

    conn = get_db_connection()

    try:
        for i, employee_id in enumerate(employee_ids):
            try:
                shamsi_datetime_str = timestamps_list[i]
                persian_digits = '۰۱۲۳۴۵۶۷۸۹'
                english_digits = '0123456789'
                translation_table = str.maketrans(persian_digits, english_digits)
                shamsi_datetime_str_en = shamsi_datetime_str.translate(translation_table)

                shamsi_dt = jdatetime.datetime.strptime(shamsi_datetime_str_en, '%Y/%m/%d %H:%M:%S')
                miladi_dt = shamsi_dt.togregorian()
                timestamp = miladi_dt.strftime('%Y-%m-%d %H:%M:%S')
            except (ValueError, IndexError):
                timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')

            conn.execute('INSERT INTO time_logs (employee_id, action, timestamp) VALUES (?, ?, ?)',
                         (employee_id, action, timestamp))
        conn.commit()
        flash(f"ثبت {action} برای {len(employee_ids)} کارمند با موفقیت انجام شد.", "success")
        log_action(session['user']['username'], f'ثبت {action}', f'برای کارمندان: {", ".join(employee_ids)}')
    except Exception as e:
        conn.rollback()
        flash("خطایی در ثبت اطلاعات رخ داد.", "error")
        print(f"Error submitting bulk data: {e}")
    finally:
        conn.close()

    return redirect(url_for('index'))

# روت جدید برای ویرایش یک رکورد
@app.route('/edit_log/<int:log_id>', methods=['POST'])
@login_required
def edit_log(log_id):
    if not has_permission('reports'):
        flash("شما به این بخش دسترسی ندارید.", "error")
        return redirect(url_for('reports'))

    employee_id = request.form['employeeId']
    action = request.form['action']
    date_fa = request.form['date']
    time_fa = request.form['time']

    try:
        shamsi_dt = jdatetime.datetime.strptime(f'{date_fa} {time_fa}', '%Y/%m/%d %H:%M:%S')
        miladi_dt = shamsi_dt.togregorian()
        timestamp = miladi_dt.strftime('%Y-%m-%d %H:%M:%S')
    except ValueError:
        flash("فرمت تاریخ یا ساعت نامعتبر است.", "error")
        return redirect(url_for('reports'))

    conn = get_db_connection()
    try:
        conn.execute('''
            UPDATE time_logs
            SET employee_id = ?, action = ?, timestamp = ?
            WHERE id = ?
        ''', (employee_id, action, timestamp, log_id))
        conn.commit()
        flash("رکورد با موفقیت ویرایش شد.", "success")
        log_action(session['user']['username'], 'ویرایش رکورد تردد', f'رکورد با شناسه {log_id} ویرایش شد.')
    except Exception as e:
        flash("خطایی در ویرایش رکورد رخ داد.", "error")
        print(f"Error editing log: {e}")
    finally:
        conn.close()
    return redirect(url_for('reports'))

# روت جدید برای حذف یک رکورد
@app.route('/delete_log/<int:log_id>', methods=['POST'])
@login_required
def delete_log(log_id):
    if not has_permission('reports'):
        flash("شما به این بخش دسترسی ندارید.", "error")
        return redirect(url_for('reports'))

    conn = get_db_connection()
    try:
        conn.execute('DELETE FROM time_logs WHERE id = ?', (log_id,))
        conn.commit()
        flash("رکورد با موفقیت حذف شد.", "success")
        log_action(session['user']['username'], 'حذف رکورد تردد', f'رکورد با شناسه {log_id} حذف شد.')
    except Exception as e:
        flash("خطایی در حذف رکورد رخ داد.", "error")
        print(f"Error deleting log: {e}")
    finally:
        conn.close()
    return redirect(url_for('reports'))

# روت جدید برای پاک کردن تمام اطلاعات
@app.route('/clear_data', methods=['POST'])
@login_required
def clear_data():
    if not has_permission('reports'):
        flash("شما به این بخش دسترسی ندارید.", "error")
        return redirect(url_for('reports'))

    conn = get_db_connection()
    try:
        conn.execute('DELETE FROM time_logs')
        conn.commit()
        flash("تمام داده‌ها با موفقیت پاک شدند.", "success")
        log_action(session['user']['username'], 'پاک کردن تمام داده‌های تردد')
    except Exception as e:
        flash("خطایی در پاک کردن داده‌ها رخ داد.", "error")
        print(f"Error clearing data: {e}")
    finally:
        conn.close()
    return redirect(url_for('reports'))

# روت جدید برای اضافه کردن کارمند
@app.route('/add_employee', methods=['POST'])
@login_required
def add_employee():
    if not has_permission('management'):
        flash("شما به این بخش دسترسی ندارید.", "error")
        return redirect(url_for('index'))

    employee_id = request.form['employeeId']
    name = request.form['name']
    
    conn = get_db_connection()
    try:
        conn.execute('INSERT INTO employees (employee_id, name) VALUES (?, ?)',
                     (employee_id, name))
        conn.commit()
        log_action(session['user']['username'], 'افزودن کارمند', f'کارمند جدید: {name} ({employee_id})')
        flash(f"کارمند '{name}' با موفقیت اضافه شد.", "success")
    except sqlite3.IntegrityError:
        flash(f"شماره پرسنلی '{employee_id}' قبلاً ثبت شده است.", "error")
    finally:
        conn.close()
        
    return redirect(url_for('management'))

# روت جدید برای حذف کردن کارمند
@app.route('/delete_employee', methods=['POST'])
@login_required
def delete_employee():
    if not has_permission('management'):
        flash("شما به این بخش دسترسی ندارید.", "error")
        return redirect(url_for('index'))

    employee_id = request.form['employeeId']
    
    conn = get_db_connection()
    try:
        conn.execute('DELETE FROM employees WHERE employee_id = ?', (employee_id,))
        conn.commit()
        flash("کارمند با موفقیت حذف شد.", "success")
        log_action(session['user']['username'], 'حذف کارمند', f'کارمند با شناسه: {employee_id} حذف شد.')
    except Exception as e:
        flash("خطایی در حذف کارمند رخ داد.", "error")
        print(f"Error deleting employee: {e}")
    finally:
        conn.close()
    return redirect(url_for('management'))

# NEW ROUTES for user management
@app.route('/users')
@login_required
def users():
    if not has_permission('users'):
        flash("شما به این بخش دسترسی ندارید.", "error")
        return redirect(url_for('index'))

    conn = get_db_connection()
    try:
        users = conn.execute("SELECT * FROM users").fetchall()
    finally:
        conn.close()
    log_action(session['user']['username'], 'مشاهده صفحه مدیریت کاربران')
    return render_template('users.html', users=users)

# NEW ROUTE: Get permissions for a user
@app.route('/get_permissions/<username>')
@login_required
@role_required('admin')
def get_permissions(username):
    conn = get_db_connection()
    try:
        user = conn.execute("SELECT permissions FROM users WHERE username = ?", (username,)).fetchone()
    finally:
        conn.close()
    if user:
        return jsonify({'permissions': json.loads(user['permissions'])})
    return jsonify({})

# NEW ROUTE: Get user logs for a specific user
@app.route('/get_user_logs/<username>')
@login_required
def get_user_logs(username):
    if not has_permission('users') and session.get('user', {}).get('username') != username:
        return "Access Denied", 403

    conn = get_db_connection()
    try:
        logs = conn.execute('SELECT * FROM user_logs WHERE username = ? ORDER BY timestamp DESC', (username,)).fetchall()
    finally:
        conn.close()

    fa_logs = []
    for log in logs:
        miladi_dt = datetime.strptime(log['timestamp'], '%Y-%m-%d %H:%M:%S')
        shamsi_dt = jdatetime.datetime.fromgregorian(datetime=miladi_dt)
        fa_logs.append({
            'action': log['action'],
            'details': log['details'],
            'timestamp_fa': shamsi_dt.strftime('%Y/%m/%d %H:%M:%S')
        })

    return jsonify(fa_logs)

@app.route('/add_user', methods=['POST'])
@login_required
def add_user():
    if not has_permission('users'):
        flash("شما به این بخش دسترسی ندارید.", "error")
        return redirect(url_for('users'))
        
    username = request.form['username'].lower()
    name = request.form['name']
    password = request.form['password']
    role = request.form['role']
    permissions = json.dumps({'index': True, 'management': False, 'reports': False, 'users': False})
    if role == 'admin':
        permissions = json.dumps({'index': True, 'management': True, 'reports': True, 'users': True})
        
    hashed_password = generate_password_hash(password)

    conn = get_db_connection()
    try:
        conn.execute("INSERT INTO users (username, name, password, role, permissions) VALUES (?, ?, ?, ?, ?)", (username, name, hashed_password, role, permissions))
        conn.commit()
        flash(f"کاربر '{name}' با موفقیت اضافه شد.", "success")
        log_action(session['user']['username'], 'افزودن کاربر جدید', f'کاربر: {name} با نقش {role}')
    except sqlite3.IntegrityError:
        flash(f"نام کاربری '{username}' قبلاً ثبت شده است.", "error")
    finally:
        conn.close()
    return redirect(url_for('users'))

@app.route('/delete_user', methods=['POST'])
@login_required
def delete_user():
    if not has_permission('users'):
        flash("شما به این بخش دسترسی ندارید.", "error")
        return redirect(url_for('users'))
        
    username = request.form['username']
    
    conn = get_db_connection()
    try:
        if username != 'admin':
            conn.execute('DELETE FROM users WHERE username = ?', (username,))
            conn.commit()
            flash(f"کاربر '{username}' با موفقیت حذف شد.", "success")
            log_action(session['user']['username'], 'حذف کاربر', f'کاربر: {username} حذف شد.')
        else:
            flash("کاربر 'admin' قابل حذف نیست.", "error")
    finally:
        conn.close()
    return redirect(url_for('users'))

@app.route('/edit_user', methods=['POST'])
@login_required
def edit_user():
    if not has_permission('users'):
        flash("شما به این بخش دسترسی ندارید.", "error")
        return redirect(url_for('users'))
        
    username = request.form['username']
    name = request.form['name']
    password = request.form['password']
    role = request.form['role']
    
    conn = get_db_connection()
    try:
        if username != 'admin':
            hashed_password = generate_password_hash(password)
            conn.execute("UPDATE users SET name = ?, password = ?, role = ? WHERE username = ?", (name, hashed_password, role, username))
            conn.commit()
            flash(f"اطلاعات کاربر '{name}' با موفقیت ویرایش شد.", "success")
            log_action(session['user']['username'], 'ویرایش کاربر', f'اطلاعات کاربر {name} ویرایش شد.')
        else:
            flash("کاربر 'admin' قابل ویرایش نیست.", "error")
    finally:
        conn.close()
    return redirect(url_for('users'))

@app.route('/update_permissions', methods=['POST'])
@login_required
def update_permissions():
    if not has_permission('users'):
        flash("شما به این بخش دسترسی ندارید.", "error")
        return redirect(url_for('users'))
        
    username = request.form['username']
    permissions = {
        'index': 'index' in request.form,
        'management': 'management' in request.form,
        'reports': 'reports' in request.form,
        'users': 'users' in request.form,
        'petty_cash': 'petty_cash' in request.form # Add petty_cash permission
    }

    conn = get_db_connection()
    try:
        if username != 'admin':
            conn.execute("UPDATE users SET permissions = ? WHERE username = ?", (json.dumps(permissions), username))
            conn.commit()
            flash(f"دسترسی‌های کاربر '{username}' با موفقیت به‌روزرسانی شد.", "success")
            log_action(session['user']['username'], 'به‌روزرسانی دسترسی‌ها', f'دسترسی‌های کاربر {username} به‌روزرسانی شد.')
        else:
            flash("دسترسی‌های کاربر 'admin' قابل ویرایش نیست.", "error")
    finally:
        conn.close()
    return redirect(url_for('users'))

# روت برای جستجوی نام یا شماره پرسنلی
@app.route('/lookup_employee', methods=['POST'])
@login_required
def lookup_employee():
    if not has_permission('index'):
        return "Access Denied", 403

    conn = get_db_connection()
    query = request.json.get('query')
    query_type = request.json.get('type')
    employee = None
    try:
        if query_type == 'id':
            employee = conn.execute('SELECT * FROM employees WHERE employee_id = ?', (query,)).fetchone()
        elif query_type == 'name':
            employee = conn.execute('SELECT * FROM employees WHERE name LIKE ?', ('%' + query + '%',)).fetchone()
    finally:
        conn.close()
    
    if employee:
        return jsonify({
            'employeeId': employee['employee_id'],
            'name': employee['name']
        })
    else:
        return jsonify({})

# EXPORT ROUTE: Export all time logs to a CSV file
@app.route('/export/all')
@login_required
def export_all():
    if not has_permission('reports'):
        return "Access Denied", 403
        
    conn = get_db_connection()
    try:
        records = conn.execute('''
            SELECT tl.employee_id, e.name, tl.action, tl.timestamp
            FROM time_logs tl
            JOIN employees e ON tl.employee_id = e.employee_id
            ORDER BY tl.timestamp DESC
        ''').fetchall()
    finally:
        conn.close()

    si = io.StringIO()
    writer = csv.writer(si, dialect='excel')
    headers = ['شماره پرسنلی', 'نام کارمند', 'عملیات', 'تاریخ', 'ساعت']
    writer.writerow(headers)

    for record in records:
        miladi_dt = datetime.strptime(record['timestamp'], '%Y-%m-%d %H:%M:%S')
        shamsi_dt = jdatetime.datetime.fromgregorian(datetime=miladi_dt)
        date_part = shamsi_dt.strftime('%Y/%m/%d')
        time_part = shamsi_dt.strftime('%H:%M:%S')
        writer.writerow([record['employee_id'], record['name'], record['action'], date_part, time_part])

    output = si.getvalue().encode('utf-8-sig') 
    response = Response(output, mimetype='text/csv')
    response.headers['Content-Disposition'] = 'attachment; filename=all_time_logs.csv'
    
    log_action(session['user']['username'], 'خروجی گرفتن از تمام گزارشات تردد')
    return response

# EXPORT ROUTE: Export a single employee's time logs to a CSV file
@app.route('/export/employee/<employee_id>')
@login_required
def export_employee(employee_id):
    if not has_permission('reports'):
        return "Access Denied", 403
        
    conn = get_db_connection()
    try:
        records = conn.execute('''
            SELECT tl.employee_id, e.name, tl.action, tl.timestamp
            FROM time_logs tl
            JOIN employees e ON tl.employee_id = e.employee_id
            WHERE tl.employee_id = ? 
            ORDER BY tl.timestamp DESC
        ''', (employee_id,)).fetchall()
    finally:
        conn.close()

    if not records:
        return "No data found for this employee.", 404

    si = io.StringIO()
    writer = csv.writer(si, dialect='excel')
    headers = ['شماره پرسنلی', 'نام کارمند', 'عملیات', 'تاریخ', 'ساعت']
    writer.writerow(headers)

    for record in records:
        miladi_dt = datetime.strptime(record['timestamp'], '%Y-%m-%d %H:%M:%S')
        shamsi_dt = jdatetime.datetime.fromgregorian(datetime=miladi_dt)
        date_part = shamsi_dt.strftime('%Y/%m/%d')
        time_part = shamsi_dt.strftime('%H:%M:%S')
        writer.writerow([record['employee_id'], record['name'], record['action'], date_part, time_part])

    si.seek(0)
    output = si.getvalue().encode('utf-8-sig')
    
    filename = 'time_log.csv'
    if records and records[0]['name']:
        filename_persian = f"time_log_{records[0]['name'].replace(' ', '_')}.csv"
        filename = urllib.parse.quote(filename_persian)

    response = Response(output, mimetype='text/csv')
    response.headers['Content-Disposition'] = f"attachment; filename*=UTF-8''{filename}"
    
    log_action(session['user']['username'], 'خروجی گرفتن از گزارش تردد', f'برای کارمند: {employee_id}')
    return response

# EXPORT ROUTE: Export all employees' logs to a single ZIP file with separate CSVs
@app.route('/export/zip')
@login_required
def export_zip():
    if not has_permission('reports'):
        return "Access Denied", 403
        
    conn = get_db_connection()
    employees = conn.execute('SELECT employee_id, name FROM employees').fetchall()
    conn.close()

    if not employees:
        return "No employees found.", 404

    zip_buffer = io.BytesIO()
    with zipfile.ZipFile(zip_buffer, 'w', zipfile.ZIP_DEFLATED) as zip_file:
        for employee in employees:
            employee_id = employee['employee_id']
            employee_name = employee['name']
            
            conn = get_db_connection()
            try:
                records = conn.execute('''
                    SELECT tl.employee_id, e.name, tl.action, tl.timestamp
                    FROM time_logs tl
                    JOIN employees e ON tl.employee_id = e.employee_id
                    WHERE tl.employee_id = ?
                    ORDER BY tl.timestamp DESC
                ''', (employee_id,)).fetchall()
            finally:
                conn.close()

            if records:
                si = io.StringIO()
                writer = csv.writer(si, dialect='excel')
                headers = ['شماره پرسنلی', 'نام کارمند', 'عملیات', 'تاریخ', 'ساعت']
                writer.writerow(headers)

                for record in records:
                    miladi_dt = datetime.strptime(record['timestamp'], '%Y-%m-%d %H:%M:%S')
                    shamsi_dt = jdatetime.datetime.fromgregorian(datetime=miladi_dt)
                    date_part = shamsi_dt.strftime('%Y/%m/%d')
                    time_part = shamsi_dt.strftime('%H:%M:%S')
                    writer.writerow([record['employee_id'], record['name'], record['action'], date_part, time_part])

                csv_filename = f"گزارش_{employee_name}.csv"
                zip_file.writestr(csv_filename, si.getvalue().encode('utf-8-sig'))

    zip_buffer.seek(0)
    response = Response(zip_buffer.getvalue(), mimetype='application/zip')
    response.headers['Content-Disposition'] = 'attachment; filename=all_employees_logs.zip'
    
    log_action(session['user']['username'], 'خروجی گرفتن ZIP از تمام گزارشات')
    return response

# NEW ROUTES for employee import/export
@app.route('/export/employees')
@login_required
def export_employees():
    if not has_permission('management'):
        return "Access Denied", 403
        
    conn = get_db_connection()
    try:
        employees = conn.execute('SELECT employee_id, name FROM employees ORDER BY CAST(employee_id AS INTEGER) ASC').fetchall()
    finally:
        conn.close()

    si = io.StringIO()
    writer = csv.writer(si, dialect='excel')
    headers = ['شماره پرسنلی', 'نام کارمند']
    writer.writerow(headers)
    for employee in employees:
        writer.writerow([employee['employee_id'], employee['name']])

    output = si.getvalue().encode('utf-8-sig')
    response = Response(output, mimetype='text/csv')
    response.headers['Content-Disposition'] = 'attachment; filename=employees.csv'
    
    log_action(session['user']['username'], 'خروجی گرفتن از لیست کارکنان')
    return response

@app.route('/import/employees', methods=['POST'])
@login_required
def import_employees():
    if not has_permission('management'):
        flash("شما به این بخش دسترسی ندارید.", "error")
        return redirect(url_for('management'))

    file = request.files['file']
    if not file or not file.filename.endswith('.csv'):
        flash("فرمت فایل نامعتبر است. لطفاً یک فایل CSV آپلود کنید.", "error")
        return redirect(url_for('management'))

    conn = get_db_connection()
    conn.execute('BEGIN TRANSACTION')
    try:
        stream = io.StringIO(file.stream.read().decode("utf-8-sig"), newline=None)
        reader = csv.reader(stream, delimiter=',')
        header = next(reader, None) # Skip header row
        
        count = 0
        for row in reader:
            if len(row) >= 2:
                employee_id = row[0].strip()
                name = row[1].strip()
                if employee_id and name:
                    conn.execute('INSERT OR IGNORE INTO employees (employee_id, name) VALUES (?, ?)', (employee_id, name))
                    count += 1
        conn.commit()
        flash(f"{count} کارمند جدید با موفقیت اضافه شد.", "success")
        log_action(session['user']['username'], 'ورودی از فایل CSV', f'{count} کارمند جدید اضافه شد.')
    except Exception as e:
        conn.rollback()
        flash(f"هنگام وارد کردن اطلاعات خطایی رخ داد: {e}", "error")
    finally:
        conn.close()

    return redirect(url_for('management'))

# NEW ROUTE: Petty cash page
@app.route('/petty_cash')
@login_required
def petty_cash():
    if not has_permission('petty_cash'):
        flash("شما به این بخش دسترسی ندارید.", "error")
        return redirect(url_for('index'))
    
    conn = get_db_connection()
    try:
        # Fetch data for petty cash report
        records = conn.execute('''
            SELECT * FROM petty_cash ORDER BY timestamp DESC
        ''').fetchall()
        
        # Get list of all users for the payer dropdown
        users = conn.execute("SELECT username, name, role FROM users ORDER BY name").fetchall()
        
    finally:
        conn.close()
    
    return render_template('petty_cash.html', records=records, users=users)

# NEW ROUTE: Add petty cash transaction
@app.route('/add_petty_cash', methods=['POST'])
@login_required
def add_petty_cash():
    if not has_permission('petty_cash'):
        flash("شما به این بخش دسترسی ندارید.", "error")
        return redirect(url_for('petty_cash'))

    try:
        date_fa = request.form['date_fa']
        description = request.form['description']
        unit = request.form['unit']
        amount = request.form['amount']
        unit_price = request.form['unit_price']
        discount = request.form['discount']
        total_amount = request.form['total_amount']
        location = request.form['location']
        notes = request.form['notes']
        source = request.form['source']
        invoice_number = request.form['invoice_number']
        settlement_status = request.form['settlement_status']
        payer = request.form['payer']
        
        # Handle the receipt image
        receipt_image = request.files.get('receipt_image')
        image_data = None
        if receipt_image and receipt_image.filename != '':
            image_data = receipt_image.read()

        # Convert date from Persian to Gregorian and get timestamp
        shamsi_dt = jdatetime.datetime.strptime(f'{date_fa}', '%Y/%m/%d')
        miladi_dt = shamsi_dt.togregorian()
        timestamp = miladi_dt.strftime('%Y-%m-%d %H:%M:%S')

        conn = get_db_connection()
        conn.execute('''
            INSERT INTO petty_cash (date, description, unit, amount, unit_price, discount, total_amount, location, notes, source, invoice_number, settlement_status, payer, receipt_image, timestamp)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (date_fa, description, unit, amount, unit_price, discount, total_amount, location, notes, source, invoice_number, settlement_status, payer, image_data, timestamp))
        conn.commit()
        
        flash("ثبت تنخواه با موفقیت انجام شد.", "success")
        log_action(session['user']['username'], 'ثبت تنخواه جدید', f'شرح: {description}, مبلغ کل: {total_amount}')
    except Exception as e:
        flash(f"خطا در ثبت تنخواه: {e}", "error")
        print(f"Error adding petty cash: {e}")
    finally:
        conn.close()
    
    return redirect(url_for('petty_cash'))

# API route to get distinct values for autocomplete
@app.route('/autocomplete/petty_cash_field/<field_name>')
@login_required
def autocomplete_petty_cash_field(field_name):
    conn = get_db_connection()
    try:
        if field_name in ['description', 'unit', 'location', 'source']:
            distinct_values = conn.execute(f"SELECT DISTINCT {field_name} FROM petty_cash WHERE {field_name} IS NOT NULL AND {field_name} != ''").fetchall()
            return jsonify([row[0] for row in distinct_values])
    finally:
        conn.close()
    return jsonify([])

# API route to get all users for the payer dropdown
@app.route('/get_users_for_dropdown')
@login_required
def get_users_for_dropdown():
    conn = get_db_connection()
    try:
        users = conn.execute("SELECT name FROM users ORDER BY name").fetchall()
        return jsonify([user['name'] for user in users])
    finally:
        conn.close()

if __name__ == '__main__':
    app.run(host='0.0.0.0', debug=True)
