import os
import json
import re
import random
import sqlite3
import secrets
import hmac
import smtplib
import ssl
import threading
import webbrowser
from email.message import EmailMessage
from uuid import uuid4
from urllib.parse import urlparse
from urllib.request import Request as URLRequest, urlopen
from urllib.error import HTTPError, URLError
from datetime import datetime, timedelta
from flask import Flask, render_template_string, request, redirect, url_for, session, jsonify, send_from_directory, abort
from werkzeug.utils import secure_filename
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
# Keep SQLite data beside this app in the account's persistent home storage.
DATABASE_PATH = os.path.join(app.root_path, 'cyber_portal.db')
app.secret_key = os.environ.get('CYBERSHIELD_SECRET_KEY') or secrets.token_hex(32)
app.config.update(
    MAX_CONTENT_LENGTH=8 * 1024 * 1024,
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE='Lax',
    SESSION_COOKIE_SECURE=os.environ.get('CYBERSHIELD_HTTPS', '').lower() == 'true',
)
# Fixed demo credentials requested for the local hackathon build.
ADMIN_ID = '9078031122'
ADMIN_PASSWORD = '@sashi00Q'
ALLOWED_UPLOAD_EXTENSIONS = {'pdf', 'png', 'jpg', 'jpeg', 'webp', 'txt', 'mp3', 'wav', 'ogg', 'm4a', 'mp4', 'webm', 'mov'}
ODISHA_DISTRICTS = ['Angul', 'Balangir', 'Balasore', 'Bargarh', 'Bhadrak', 'Boudh', 'Cuttack', 'Deogarh', 'Dhenkanal', 'Gajapati', 'Ganjam', 'Jagatsinghpur', 'Jajpur', 'Jharsuguda', 'Kalahandi', 'Kandhamal', 'Kendrapara', 'Kendujhar', 'Khordha', 'Koraput', 'Malkangiri', 'Mayurbhanj', 'Nabarangpur', 'Nayagarh', 'Nuapada', 'Puri', 'Rayagada', 'Sambalpur', 'Subarnapur', 'Sundargarh']
_DISTRICT_CANONICAL = {name.casefold(): name for name in ODISHA_DISTRICTS}
_DISTRICT_CANONICAL.update({'keonjhar': 'Kendujhar', 'sonepur': 'Subarnapur'})
def canonical_district(value):
    return _DISTRICT_CANONICAL.get((value or '').strip().casefold())

def hash_password(password):
    return generate_password_hash(password, method='scrypt')

def verify_password(stored, supplied):
    if not stored:
        return False, False
    if check_password_hash(stored, supplied):
        return True, False
    # One-time migration for accounts created by the original plaintext-password build.
    if hmac.compare_digest(stored, supplied):
        return True, True
    return False, False

def new_login_captcha(role):
    a, b = secrets.randbelow(8) + 2, secrets.randbelow(8) + 2
    session[f'{role}_captcha_answer'] = str(a + b)
    return a, b

def get_login_lock(role, login_id):
    conn = sqlite3.connect(DATABASE_PATH)
    row = conn.execute('SELECT failures, lock_until FROM login_attempts WHERE role=? AND login_id=?',
                       (role, (login_id or '').strip().lower())).fetchone()
    conn.close()
    if not row: return 0, 0
    failures, until = row
    remaining = max(0, int(float(until or 0) - datetime.utcnow().timestamp() + 0.999))
    return (0 if remaining == 0 else failures), remaining

def record_login_failure(role, login_id):
    key = (role, (login_id or '').strip().lower())
    conn = sqlite3.connect(DATABASE_PATH)
    row = conn.execute('SELECT failures, lock_until FROM login_attempts WHERE role=? AND login_id=?', key).fetchone()
    now = datetime.utcnow().timestamp()
    failures = row[0] if row and float(row[1] or 0) > now else 0
    failures += 1
    lock_until = now + 180 if failures >= 2 else 0
    if lock_until: failures = 0
    conn.execute('INSERT OR REPLACE INTO login_attempts (role, login_id, failures, lock_until) VALUES (?, ?, ?, ?)',
                 (key[0], key[1], failures, lock_until))
    conn.commit(); conn.close()
    return max(0, int(lock_until - now + 0.999))

def clear_login_failures(role, login_id):
    conn = sqlite3.connect(DATABASE_PATH)
    conn.execute('DELETE FROM login_attempts WHERE role=? AND login_id=?', (role, (login_id or '').strip().lower()))
    conn.commit(); conn.close()

def render_login_page(template, role, error=None, login_id='', lock_seconds=0):
    a, b = new_login_captcha(role)
    return render_template_string(template, error=error, captcha_a=a, captcha_b=b, lock_seconds=lock_seconds, login_id=login_id)

def save_upload(file_obj, prefix='file', allowed=None):
    if not file_obj or not file_obj.filename:
        return ''
    original = secure_filename(file_obj.filename)
    if '.' not in original:
        raise ValueError('File type is not allowed.')
    ext = original.rsplit('.', 1)[1].lower()
    if ext not in (allowed or ALLOWED_UPLOAD_EXTENSIONS):
        raise ValueError('File type is not allowed.')
    saved = f"{prefix}_{uuid4().hex}.{ext}"
    file_obj.save(os.path.join(app.config['UPLOAD_FOLDER'], saved))
    return saved


UPLOAD_FOLDER = os.path.join(app.root_path, 'uploads')
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

def init_db():
    conn = sqlite3.connect(DATABASE_PATH)
    cursor = conn.cursor()
    
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            mobile TEXT UNIQUE,
            password TEXT
        )
    ''')
    
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS citizen_profiles (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            mobile TEXT UNIQUE,
            fullname TEXT,
            district TEXT,
            block TEXT,
            panchayat TEXT,
            pincode TEXT,
            phone TEXT,
            is_completed INTEGER DEFAULT 0
        )
    ''')
    
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS admin_profile (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            admin_id TEXT UNIQUE,
            name TEXT,
            designation TEXT,
            department TEXT,
            email TEXT
        )
    ''')
    
    cursor.execute("SELECT * FROM admin_profile WHERE admin_id = '99999'")
    if not cursor.fetchone():
        cursor.execute('''
            INSERT INTO admin_profile (admin_id, name, designation, department, email)
            VALUES ('99999', 'Demo Administrator', 'Project Administrator', 'CyberShield Demo Project', 'admin@example.invalid')
        ''')

    cursor.execute('''
        CREATE TABLE IF NOT EXISTS sub_admins (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            sub_admin_id TEXT UNIQUE,
            password TEXT,
            name TEXT,
            designation TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')

    cursor.execute('''
        CREATE TABLE IF NOT EXISTS complaints (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            mobile TEXT,
            complainant_name TEXT,
            father_name TEXT,
            father_status TEXT,
            mother_name TEXT,
            mother_status TEXT,
            dob TEXT,
            district TEXT,
            block TEXT,
            panchayat TEXT,
            active_mobile TEXT,
            permanent_address TEXT,
            present_address TEXT,
            gps_lat TEXT,
            gps_lon TEXT,
            title TEXT,
            description TEXT,
            status TEXT DEFAULT 'Pending',
            evidence_file TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            responded_at TIMESTAMP,
            contact_email TEXT,
            email_status TEXT DEFAULT 'not_configured',
            voice_recording TEXT
        )
    ''')

    complaint_columns = {row[1] for row in cursor.execute('PRAGMA table_info(complaints)').fetchall()}
    if 'contact_email' not in complaint_columns:
        cursor.execute('ALTER TABLE complaints ADD COLUMN contact_email TEXT')
    if 'email_status' not in complaint_columns:
        cursor.execute("ALTER TABLE complaints ADD COLUMN email_status TEXT DEFAULT 'not_configured'")
    if 'voice_recording' not in complaint_columns:
        cursor.execute('ALTER TABLE complaints ADD COLUMN voice_recording TEXT')

    cursor.execute('''
        CREATE TABLE IF NOT EXISTS feedbacks (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT,
            email_or_phone TEXT,
            message TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')

    cursor.execute('''
        CREATE TABLE IF NOT EXISTS login_attempts (
            role TEXT NOT NULL,
            login_id TEXT NOT NULL,
            failures INTEGER NOT NULL DEFAULT 0,
            lock_until REAL NOT NULL DEFAULT 0,
            PRIMARY KEY (role, login_id)
        )
    ''')

    cursor.execute('''
        CREATE TABLE IF NOT EXISTS system_settings (
            key TEXT PRIMARY KEY,
            value TEXT
        )
    ''')

    cursor.execute("INSERT OR IGNORE INTO system_settings (key, value) VALUES ('notice_text', 'DEMO NOTICE: Never share OTP, UPI PIN, or bank passwords. For real cybercrime reporting, use the official cybercrime.gov.in portal or call 1930 for online financial fraud.')")
    cursor.execute("INSERT OR IGNORE INTO system_settings (key, value) VALUES ('notice_photo1', '')")
    cursor.execute("INSERT OR IGNORE INTO system_settings (key, value) VALUES ('notice_photo2', '')")

    cursor.execute('''
        CREATE TABLE IF NOT EXISTS admin_chat_messages (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            sub_admin_id TEXT,
            sender_role TEXT,
            message_text TEXT,
            file_attachment TEXT,
            file_type TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')

    cursor.execute('''
        CREATE TABLE IF NOT EXISTS complaint_remarks (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            complaint_id INTEGER,
            sender_type TEXT,
            sender_name TEXT,
            message TEXT,
            attachment TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')

    cursor.execute('''
        CREATE TABLE IF NOT EXISTS citizen_chat_timer (
            complaint_id INTEGER PRIMARY KEY,
            first_msg_time TIMESTAMP,
            cooldown_until TIMESTAMP
        )
    ''')

    conn.commit()
    conn.close()

init_db()

def send_complaint_confirmation(recipient, case_id, complainant, category):
    host = os.environ.get('CYBERSHIELD_SMTP_HOST', 'smtp.gmail.com').strip()
    username = os.environ.get('CYBERSHIELD_SMTP_USER', 'sashikantamohanty797@gmail.com').strip()
    password = os.environ.get('CYBERSHIELD_SMTP_PASSWORD', '')
    sender = os.environ.get('CYBERSHIELD_SMTP_FROM', '').strip() or username
    if not (host and username and password and sender):
        return 'not_configured'
    msg = EmailMessage()
    msg['Subject'] = f'CyberShield demo complaint received — Case #{case_id}'
    msg['From'] = sender
    msg['To'] = recipient
    msg.set_content(
        f"Hello {complainant or 'Citizen'},\n\n"
        f"Your complaint form was received by the CyberShield demo portal.\n"
        f"Demo case reference: #{case_id}\n"
        f"Category: {category or 'Cyber incident'}\n\n"
        "This is an automated confirmation from a hackathon project. It is not an official police/FIR filing and is not forwarded to a government authority. For real cybercrime reporting, use cybercrime.gov.in; for online financial fraud call 1930.\n"
    )
    try:
        port = int(os.environ.get('CYBERSHIELD_SMTP_PORT', '587'))
        if os.environ.get('CYBERSHIELD_SMTP_USE_SSL', '').lower() == 'true':
            with smtplib.SMTP_SSL(host, port, timeout=15, context=ssl.create_default_context()) as server:
                server.login(username, password)
                server.send_message(msg)
        else:
            with smtplib.SMTP(host, port, timeout=15) as server:
                server.ehlo()
                server.starttls(context=ssl.create_default_context())
                server.ehlo()
                server.login(username, password)
                server.send_message(msg)
        return 'sent'
    except Exception:
        app.logger.exception('Complaint confirmation email delivery failed for case %s', case_id)
        return 'failed'

def get_setting(key):
    conn = sqlite3.connect(DATABASE_PATH)
    cursor = conn.cursor()
    cursor.execute("SELECT value FROM system_settings WHERE key = ?", (key,))
    row = cursor.fetchone()
    conn.close()
    return row[0] if row else ""

def set_setting(key, value):
    conn = sqlite3.connect(DATABASE_PATH)
    cursor = conn.cursor()
    cursor.execute("INSERT OR REPLACE INTO system_settings (key, value) VALUES (?, ?)", (key, value))
    conn.commit()
    conn.close()

def get_district_report_counts():
    counts = {name: 0 for name in ODISHA_DISTRICTS}
    conn = sqlite3.connect(DATABASE_PATH)
    try:
        rows = conn.execute("SELECT district, COUNT(*) FROM complaints WHERE district IS NOT NULL AND TRIM(district) != '' GROUP BY LOWER(TRIM(district))").fetchall()
    finally:
        conn.close()
    for district, count in rows:
        canonical = canonical_district(district)
        if canonical:
            counts[canonical] += count
    return [{'district': name, 'count': counts[name]} for name in ODISHA_DISTRICTS if counts[name] > 0]

def get_live_analytics():
    conn = sqlite3.connect(DATABASE_PATH)
    cursor = conn.cursor()
    
    cursor.execute("SELECT COUNT(*) FROM complaints")
    total_complaints = cursor.fetchone()[0] or 0

    cursor.execute("SELECT COUNT(*) FROM complaints WHERE status LIKE '%Resolved%' OR status LIKE '%Congratulations%'")
    resolved_complaints = cursor.fetchone()[0] or 0

    cursor.execute("SELECT COUNT(*) FROM complaints WHERE status = 'Pending'")
    pending_complaints = cursor.fetchone()[0] or 0

    cursor.execute("""
        SELECT AVG((JULIANDAY(responded_at) - JULIANDAY(created_at)) * 86400) 
        FROM complaints 
        WHERE responded_at IS NOT NULL
    """)
    avg_seconds = cursor.fetchone()[0]
    conn.close()

    if avg_seconds is None or avg_seconds <= 0:
        avg_response_text = "6 Hours"
    else:
        avg_seconds = int(avg_seconds)
        if avg_seconds < 3600:
            avg_response_text = f"{max(1, avg_seconds // 60)} Mins"
        else:
            avg_response_text = f"{avg_seconds // 3600} Hours"

    return {
        "total": total_complaints,
        "resolved": resolved_complaints,
        "pending": pending_complaints,
        "avg_response": avg_response_text
    }

@app.route('/uploads/<filename>')
def uploaded_file(filename):
    # Publicly expose only admin-selected notice images. Evidence and chat files require access checks.
    if filename in {get_setting('notice_photo1'), get_setting('notice_photo2')} and filename:
        if filename.rsplit('.', 1)[-1].lower() not in {'png', 'jpg', 'jpeg', 'webp'}:
            abort(404)
        return send_from_directory(app.config['UPLOAD_FOLDER'], filename, as_attachment=False)
    conn = sqlite3.connect(DATABASE_PATH)
    cur = conn.cursor()
    cur.execute('SELECT mobile FROM complaints WHERE evidence_file = ? OR voice_recording = ?', (filename, filename))
    row = cur.fetchone()
    if not row:
        cur.execute('SELECT c.mobile FROM complaint_remarks r JOIN complaints c ON c.id=r.complaint_id WHERE r.attachment=?', (filename,))
        row = cur.fetchone()
    if not row:
        cur.execute('SELECT sub_admin_id FROM admin_chat_messages WHERE file_attachment=?', (filename,))
        chat_row = cur.fetchone()
    else:
        chat_row = None
    conn.close()
    allowed = bool(session.get('is_head_admin') or session.get('is_sub_admin'))
    if row and session.get('user_mobile') == row[0]:
        allowed = True
    if chat_row and (session.get('is_head_admin') or (session.get('is_sub_admin') and session.get('sub_admin_id') == chat_row[0])):
        allowed = True
    if not allowed:
        abort(404)
    return send_from_directory(app.config['UPLOAD_FOLDER'], filename, as_attachment=True)

@app.errorhandler(413)
def upload_too_large(_error):
    return 'Upload too large. Maximum file size is 8 MB.', 413

SITE_LANGUAGE_SCRIPT = r"""
<script>
(function(){
 const od={
  'English':'ଇଂରାଜୀ','Odia':'ଓଡ଼ିଆ','Login':'ଲଗଇନ୍','Log In':'ଲଗଇନ୍','Logout':'ଲଗଆଉଟ୍','Register':'ପଞ୍ଜୀକରଣ','Register Account':'ଖାତା ଖୋଲନ୍ତୁ','Back to Home':'ମୂଳ ପୃଷ୍ଠାକୁ ଫେରନ୍ତୁ','Back to Login':'ଲଗଇନ୍‌କୁ ଫେରନ୍ତୁ','Return to Dashboard':'ଡ୍ୟାସବୋର୍ଡକୁ ଫେରନ୍ତୁ','Dashboard':'ଡ୍ୟାସବୋର୍ଡ','Home':'ମୂଳ ପୃଷ୍ଠା','Save Profile':'ପ୍ରୋଫାଇଲ୍ ସେଭ୍ କରନ୍ତୁ','Save Profile →':'ପ୍ରୋଫାଇଲ୍ ସେଭ୍ କରନ୍ତୁ →','View Saved Profile':'ସେଭ୍ ହୋଇଥିବା ପ୍ରୋଫାଇଲ୍ ଦେଖନ୍ତୁ','Submit Complaint →':'ଅଭିଯୋଗ ଦାଖଲ କରନ୍ତୁ →','Submit Complaint':'ଅଭିଯୋଗ ଦାଖଲ କରନ୍ତୁ','Check Status':'ସ୍ଥିତି ଯାଞ୍ଚ କରନ୍ତୁ','Check Complaint Status':'ଅଭିଯୋଗର ସ୍ଥିତି ଯାଞ୍ଚ କରନ୍ତୁ','Check Status & Remarks 🔍':'ସ୍ଥିତି ଓ ମତାମତ ଦେଖନ୍ତୁ 🔍','Download / Print Certificate (PDF)':'ସାର୍ଟିଫିକେଟ୍ ଡାଉନଲୋଡ୍ / ପ୍ରିଣ୍ଟ (PDF)','Print / Save as PDF':'ପ୍ରିଣ୍ଟ / PDF ଭାବେ ସେଭ୍ କରନ୍ତୁ','Next':'ଆଗକୁ','Cancel':'ବାତିଲ୍','Close':'ବନ୍ଦ କରନ୍ତୁ','Search':'ଖୋଜନ୍ତୁ','Submit':'ଦାଖଲ କରନ୍ତୁ','Save':'ସେଭ୍ କରନ୍ତୁ','Update':'ଅପଡେଟ୍ କରନ୍ତୁ','Delete':'ଡିଲିଟ୍ କରନ୍ତୁ','Status':'ସ୍ଥିତି','Pending':'ବିଚାରାଧୀନ','Resolved':'ସମାଧାନ ହୋଇଛି','Name':'ନାମ','Full Name':'ପୂରା ନାମ','Full Name:':'ପୂରା ନାମ:','Mobile Number':'ମୋବାଇଲ୍ ନମ୍ବର','Registered Mobile':'ପଞ୍ଜୀକୃତ ମୋବାଇଲ୍','Password':'ପାସୱାର୍ଡ','Confirm Password':'ପାସୱାର୍ଡ ନିଶ୍ଚିତ କରନ୍ତୁ','Email':'ଇମେଲ୍','Email address':'ଇମେଲ୍ ଠିକଣା','District':'ଜିଲ୍ଲା','Block':'ବ୍ଲକ୍','Panchayat / Village':'ପଞ୍ଚାୟତ / ଗାଁ','PIN Code':'ପିନ୍ କୋଡ୍','Select district':'ଜିଲ୍ଲା ବାଛନ୍ତୁ','Alternate Phone Number':'ବିକଳ୍ପ ଫୋନ୍ ନମ୍ବର','Initial Citizen Verification':'ନାଗରିକଙ୍କ ପ୍ରାରମ୍ଭିକ ଯାଞ୍ଚ','Citizen Profile Details':'ନାଗରିକ ପ୍ରୋଫାଇଲ୍ ବିବରଣୀ','Saved citizen details':'ସେଭ୍ ହୋଇଥିବା ନାଗରିକ ବିବରଣୀ','Your citizen profile has been saved. No complaint has been filed.':'ଆପଣଙ୍କ ନାଗରିକ ପ୍ରୋଫାଇଲ୍ ସେଭ୍ ହୋଇଛି। ଏଯାଏଁ କୌଣସି ଅଭିଯୋଗ ଦାଖଲ ହୋଇନାହିଁ।','Go to Home':'ମୂଳ ପୃଷ୍ଠାକୁ ଯାଆନ୍ତୁ','Citizen Operations Dashboard':'ନାଗରିକ ଡ୍ୟାସବୋର୍ଡ','Cyber Incident Demo Form':'ସାଇବର ଘଟଣା ଡେମୋ ଫର୍ମ','Complaint Details':'ଅଭିଯୋଗ ବିବରଣୀ','Complaint ID':'ଅଭିଯୋଗ ID','Complainant Name':'ଅଭିଯୋଗକାରୀଙ୍କ ନାମ','Father\'s Name':'ପିତାଙ୍କ ନାମ','Mother\'s Name':'ମାତାଙ୍କ ନାମ','Date of Birth':'ଜନ୍ମ ତାରିଖ','Active Contact Mobile':'ଯୋଗାଯୋଗ ମୋବାଇଲ୍','Permanent Address':'ସ୍ଥାୟୀ ଠିକଣା','Present Address':'ବର୍ତ୍ତମାନର ଠିକଣା','Description':'ବିବରଣୀ','Title':'ଶୀର୍ଷକ','Evidence':'ପ୍ରମାଣ','Location':'ସ୍ଥାନ','Regional & GPS Location':'ଅଞ୍ଚଳ ଓ GPS ସ୍ଥାନ','GPS Coordinates':'GPS ସ୍ଥାନାଙ୍କ','Your complaint form was received by the CyberShield demo portal.':'CyberShield ଡେମୋ ପୋର୍ଟାଲ୍ ଆପଣଙ୍କ ଅଭିଯୋଗ ଗ୍ରହଣ କରିଛି।','DEMO RECEIPT · NOT OFFICIAL':'ଡେମୋ ରସିଦ · ସରକାରୀ ନୁହେଁ','NOT A GOVERNMENT RECEIPT':'ସରକାରୀ ରସିଦ ନୁହେଁ','Local URL & UPI Risk Clue Checker':'URL ଓ UPI ସନ୍ଦେହ ସୂଚନା ଯାଞ୍ଚକାରୀ','Check Suspicious Link / URL':'ସନ୍ଦେହଜନକ ଲିଙ୍କ୍ / URL ଯାଞ୍ଚ କରନ୍ତୁ','Check UPI VPA ID':'UPI VPA ID ଯାଞ୍ଚ କରନ୍ତୁ','Scan Website URL →':'Website URL ଯାଞ୍ଚ କରନ୍ତୁ →','Verify UPI ID →':'UPI ID ଯାଞ୍ଚ କରନ୍ତୁ →','Open Camera & Scan QR':'କ୍ୟାମେରା ଖୋଲି QR ସ୍କାନ୍ କରନ୍ତୁ','Stop Camera':'କ୍ୟାମେରା ବନ୍ଦ କରନ୍ତୁ','Scan a QR with your phone camera':'ଫୋନ୍ କ୍ୟାମେରାରେ QR ସ୍କାନ୍ କରନ୍ତୁ','Local Heuristic Demo Scanner':'ସ୍ଥାନୀୟ ନିୟମ ଆଧାରିତ ଡେମୋ ସ୍କାନର୍','High risk clues':'ଅଧିକ ବିପଦ ସୂଚନା','Some risk clues':'କିଛି ବିପଦ ସୂଚନା','A few risk clues':'କିଛି ସନ୍ଦେହ ସୂଚନା','No obvious heuristic flags':'ସ୍ପଷ୍ଟ ସନ୍ଦେହ ସୂଚନା ମିଳିଲାନି','Odia Scam Recovery Guide':'ଓଡ଼ିଆ ସ୍କାମ୍ ସୁରକ୍ଷା ମାର୍ଗଦର୍ଶିକା','Next steps':'ପରବର୍ତ୍ତୀ ପଦକ୍ଷେପ','Call 1930 (financial cyber fraud)':'୧୯୩୦କୁ କଲ୍ କରନ୍ତୁ (ଆର୍ଥିକ ସାଇବର ଠକେଇ)','Official cybercrime portal':'ସରକାରୀ ସାଇବର ଅପରାଧ ପୋର୍ଟାଲ୍','FAQ':'ସାଧାରଣ ପ୍ରଶ୍ନ','Frequently Asked Questions':'ବାରମ୍ବାର ପଚରାଯାଉଥିବା ପ୍ରଶ୍ନ','Follow Us:':'ଆମକୁ ଅନୁସରଣ କରନ୍ତୁ:','Email Me':'ଇମେଲ୍ କରନ୍ତୁ','Print':'ପ୍ରିଣ୍ଟ କରନ୍ତୁ','Download':'ଡାଉନଲୋଡ୍ କରନ୍ତୁ','Admin Login':'ଆଡମିନ୍ ଲଗଇନ୍','Head Admin Login':'ମୁଖ୍ୟ ଆଡମିନ୍ ଲଗଇନ୍','Sub-Admin Login':'ସବ୍-ଆଡମିନ୍ ଲଗଇନ୍','Login as Head Admin':'ମୁଖ୍ୟ ଆଡମିନ୍ ଭାବେ ଲଗଇନ୍','Login as Sub-Admin':'ସବ୍-ଆଡମିନ୍ ଭାବେ ଲଗଇନ୍','Admin ID':'ଆଡମିନ୍ ID','Captcha':'କ୍ୟାପ୍ଚା','Verify':'ଯାଞ୍ଚ କରନ୍ତୁ','Feedback':'ମତାମତ','Send Feedback':'ମତାମତ ପଠାନ୍ତୁ','Notice':'ସୂଚନା','Important':'ଗୁରୁତ୍ୱପୂର୍ଣ୍ଣ','Report Cyber Frauds & Secure Online Assets Real-Time':'ସାଇବର ଠକେଇ ରିପୋର୍ଟ କରନ୍ତୁ ଓ ଅନଲାଇନ୍ ସମ୍ପତ୍ତି ସୁରକ୍ଷିତ ରଖନ୍ତୁ','Cyber Incident Filing Categories':'ସାଇବର ଘଟଣା ଅଭିଯୋଗ ବିଭାଗ','Select Category to Register':'ପଞ୍ଜୀକରଣ ପାଇଁ ବିଭାଗ ବାଛନ୍ତୁ','File Complaint':'ଅଭିଯୋଗ ଦାଖଲ କରନ୍ତୁ','District-wise cyber reports':'ଜିଲ୍ଲା ଅନୁସାରେ ସାଇବର ରିପୋର୍ଟ','Home':'ମୂଳ ପୃଷ୍ଠା','Privacy Policy':'ଗୋପନୀୟତା ନୀତି','Website Policies & Terms':'ୱେବସାଇଟ୍ ନୀତି ଓ ସର୍ତ୍ତାବଳୀ','Disclaimer':'ଅସ୍ୱୀକୃତି','Track Complaint Status':'ଅଭିଯୋଗ ସ୍ଥିତି ଟ୍ରାକ୍ କରନ୍ତୁ','Welcome':'ସ୍ୱାଗତ','Continue':'ଜାରି ରଖନ୍ତୁ','Clear saved draft':'ସେଭ୍ ଡ୍ରାଫ୍ଟ ହଟାନ୍ତୁ','Draft auto-saves in this browser':'ଏହି ବ୍ରାଉଜରରେ ଡ୍ରାଫ୍ଟ ଆପେଆପେ ସେଭ୍ ହୁଏ','Start recording':'ରେକର୍ଡିଂ ଆରମ୍ଭ କରନ୍ତୁ','Remove recording':'ରେକର୍ଡିଂ ହଟାନ୍ତୁ','Voice Complaint (optional)':'ଭଏସ୍ ଅଭିଯୋଗ (ଇଚ୍ଛାଧୀନ)','Save Draft':'ଡ୍ରାଫ୍ଟ ସେଭ୍ କରନ୍ତୁ','Send Message':'ମେସେଜ୍ ପଠାନ୍ତୁ','Reply':'ଉତ୍ତର ଦିଅନ୍ତୁ','View Details':'ବିବରଣୀ ଦେଖନ୍ତୁ','Action':'କାର୍ଯ୍ୟ','Date':'ତାରିଖ','Time':'ସମୟ','Amount':'ରାଶି','Fraud Amount (in Rs.)':'ଠକେଇ ରାଶି (ଟଙ୍କାରେ)','Transaction ID / UTR Number':'କାରବାର ID / UTR ନମ୍ବର','Scammer Mobile / UPI / Link':'ଠକଙ୍କ ମୋବାଇଲ୍ / UPI / ଲିଙ୍କ୍','Required':'ଆବଶ୍ୟକ','Optional':'ଇଚ୍ଛାଧୀନ','Choose file':'ଫାଇଲ୍ ବାଛନ୍ତୁ','No file chosen':'କୌଣସି ଫାଇଲ୍ ବଛାଯାଇନାହିଁ',
  'Citizen Registration':'ନାଗରିକ ପଞ୍ଜୀକରଣ','Create credentials to access cyber complaint filing':'ସାଇବର ଅଭିଯୋଗ ପାଇଁ ଲଗଇନ୍ ବିବରଣୀ ତିଆରି କରନ୍ତୁ','Security Captcha:':'ସୁରକ୍ଷା କ୍ୟାପ୍ଚା:','Register Account →':'ଖାତା ପଞ୍ଜୀକରଣ କରନ୍ତୁ →','OTP Verification':'OTP ଯାଞ୍ଚ','Citizen Secure Login':'ନାଗରିକ ସୁରକ୍ଷିତ ଲଗଇନ୍','Target Category:':'ବାଛିଥିବା ବିଭାଗ:','Simulated SMS Demo OTP:':'ଡେମୋ SMS OTP:','DEMO ONLY — no SMS is sent. This code is shown for hackathon testing.':'କେବଳ ଡେମୋ—କୌଣସି SMS ପଠାଯାଏନି। Hackathon ପରୀକ୍ଷା ପାଇଁ ଏହି code ଦେଖାଯାଉଛି।','Verify OTP →':'OTP ଯାଞ୍ଚ କରନ୍ତୁ →','Request OTP →':'OTP ମାଗନ୍ତୁ →','Registration complete':'ପଞ୍ଜୀକରଣ ସମ୍ପୂର୍ଣ୍ଣ','Full name':'ପୂରା ନାମ','Registered mobile':'ପଞ୍ଜୀକୃତ ମୋବାଇଲ୍','Alternate phone':'ବିକଳ୍ପ ଫୋନ୍','PIN code':'ପିନ୍ କୋଡ୍','Complainant Full Name *':'ଅଭିଯୋଗକାରୀଙ୍କ ପୂରା ନାମ *','Present Location Real GPS Auto Detect':'ବର୍ତ୍ତମାନ ସ୍ଥାନର GPS ଚିହ୍ନଟ','Auto-Detect Real GPS 📍':'GPS ସ୍ଥାନ ଚିହ୍ନଟ କରନ୍ତୁ 📍','📍 Live Real-Time Satellite / OpenStreetMap Location:':'📍 ବର୍ତ୍ତମାନର OpenStreetMap ସ୍ଥାନ:','If typing is difficult, record the incident details here. You can listen before submitting. Maximum 3 minutes; recording is sent with this complaint for authorized Head Admin/Sub-Admin review.':'ଟାଇପ୍ କରିବା କଷ୍ଟ ହେଲେ ଘଟଣାଟି ଏଠାରେ ରେକର୍ଡ କରନ୍ତୁ। ଦାଖଲ ପୂର୍ବରୁ ଶୁଣିପାରିବେ। ସର୍ବାଧିକ ୩ ମିନିଟ୍; ରେକର୍ଡିଂଟି ଏହି ଅଭିଯୋଗ ସହ ଅନୁମୋଦିତ Head Admin/Sub-Adminଙ୍କୁ ଦେଖାଯିବ।','Microphone permission is needed when you start recording.':'ରେକର୍ଡିଂ ଆରମ୍ଭ କଲେ microphone ଅନୁମତି ଦରକାର।','Only record information relevant to this report. The audio is stored with the demo case and can be heard by authorized admins.':'ଏହି ରିପୋର୍ଟ ସହ ଜଡ଼ିତ କଥା ମାତ୍ର ରେକର୍ଡ କରନ୍ତୁ। Audio ଡେମୋ case ସହ ସେଭ୍ ହେବ ଏବଂ ଅନୁମୋଦିତ admin ଶୁଣିପାରିବେ।','Draft not saved yet.':'ଡ୍ରାଫ୍ଟ ଏଯାଏଁ ସେଭ୍ ହୋଇନାହିଁ।','Use only on a trusted device. Evidence files and voice recordings are not saved in the draft.':'ଭରସାଯୋଗ୍ୟ deviceରେ ମାତ୍ର ବ୍ୟବହାର କରନ୍ତୁ। ପ୍ରମାଣ ଫାଇଲ୍ ଓ ଭଏସ୍ ରେକର୍ଡିଂ ଡ୍ରାଫ୍ଟରେ ସେଭ୍ ହୁଏନି।','Local heuristic only: this demo does not query a live cybercrime database':'ଏହା କେବଳ ସ୍ଥାନୀୟ ନିୟମ ଆଧାରିତ ଯାଞ୍ଚ; live cybercrime database ଦେଖେନି।','Camera access is used only in this browser. The QR is decoded locally; nothing is uploaded.':'କ୍ୟାମେରା କେବଳ ଏହି browserରେ ବ୍ୟବହୃତ ହୁଏ। QR ଏଠାରେ decode ହୁଏ; କିଛି upload ହୁଏନି।','Scan Website URL →':'Website URL ଯାଞ୍ଚ କରନ୍ତୁ →','Verify UPI ID →':'UPI ID ଯାଞ୍ଚ କରନ୍ତୁ →','A QR scan can decode its contents, but cannot prove that a payment recipient or website is genuine. Verify the payee name in your payment app before paying.':'QR scan ଏହାର ତଥ୍ୟ ପଢ଼ିପାରେ, କିନ୍ତୁ payee କିମ୍ବା website ଅସଲି ବୋଲି ପ୍ରମାଣ କରେନି। ଟଙ୍କା ପଠାଇବା ପୂର୍ବରୁ payment appରେ payee ନାମ ଯାଞ୍ଚ କରନ୍ତୁ।','Return to Dashboard':'ଡ୍ୟାସବୋର୍ଡକୁ ଫେରନ୍ତୁ','Download / Print Certificate (PDF)':'ରସିଦ ଡାଉନଲୋଡ୍ / ପ୍ରିଣ୍ଟ (PDF)','Generated by CyberShield AI Intelligence System':'CyberShield ଡେମୋ ଦ୍ୱାରା ତିଆରି','Cyber Crime Incident Particulars':'ସାଇବର ଅପରାଧ ଘଟଣାର ବିବରଣୀ','Incident Category / Title:':'ଘଟଣା ବିଭାଗ / ଶୀର୍ଷକ:','Detailed Crime Report:':'ଅପରାଧର ବିସ୍ତୃତ ବିବରଣୀ:','Filing Date & Time:':'ଦାଖଲ ତାରିଖ ଓ ସମୟ:','Initial Status:':'ପ୍ରାରମ୍ଭିକ ସ୍ଥିତି:','Email confirmation:':'ଇମେଲ୍ ନିଶ୍ଚିତକରଣ:','This is a project demo receipt, not an official police complaint or FIR filing.':'ଏହା ପ୍ରୋଜେକ୍ଟର demo ରସିଦ; ସରକାରୀ ପୋଲିସ୍ ଅଭିଯୋଗ କିମ୍ବା FIR ନୁହେଁ।','Officer ID':'ଅଧିକାରୀ ID','Secure gateway for authorized officers':'ଅନୁମୋଦିତ ଅଧିକାରୀଙ୍କ ପାଇଁ ସୁରକ୍ଷିତ ପ୍ରବେଶ','Privileged access · monitored session':'ସୀମିତ ଅଧିକାର · session ନିରୀକ୍ଷଣରେ ରହେ','Security check':'ସୁରକ୍ଷା ଯାଞ୍ଚ','Authenticate securely →':'ସୁରକ୍ଷିତ ଭାବେ ପ୍ରବେଶ କରନ୍ତୁ →','Enter control room →':'Control roomକୁ ପ୍ରବେଶ କରନ୍ତୁ →','← Back to portal':'← ପୋର୍ଟାଲ୍‌କୁ ଫେରନ୍ତୁ','Cyber Incident Demo Form':'ସାଇବର ଘଟଣା ଡେମୋ ଫର୍ମ','District-wise cyber reports':'ଜିଲ୍ଲା ଅନୁସାରେ ସାଇବର ରିପୋର୍ଟ','CHECK COMPLAINT STATUS':'ଅଭିଯୋଗର ସ୍ଥିତି ଯାଞ୍ଚ କରନ୍ତୁ','LOCAL URL & UPI CHECK':'URL ଓ UPI ଯାଞ୍ଚ','FIR DRAFT GENERATOR':'FIR ଡ୍ରାଫ୍ଟ ତିଆରିକାରୀ',
  'Helpline:':'ସହାୟତା ନମ୍ବର:','🚨 EMERGENCY':'🚨 ଜରୁରୀକାଳୀନ','INDEPENDENT CYBER SAFETY DEMO PROJECT':'ସ୍ୱତନ୍ତ୍ର ସାଇବର ସୁରକ୍ଷା ଡେମୋ ପ୍ରକଳ୍ପ','LIVE BREAKING NEWS':'ତାଜା ସାଇବର ସତର୍କତା','Send Feedback to CyberShield Team':'CyberShield ଟିମ୍‌କୁ ମତାମତ ପଠାନ୍ତୁ','Share your thoughts or suggest platform enhancements':'ଆପଣଙ୍କ ମତାମତ ଦିଅନ୍ତୁ କିମ୍ବା ପ୍ରସ୍ତାବ ରଖନ୍ତୁ','Submit Feedback':'ମତାମତ ଦାଖଲ କରନ୍ତୁ','CyberShield Live Operational Stats':'CyberShieldର ବର୍ତ୍ତମାନ ସାଂଖ୍ୟିକ ତଥ୍ୟ','COMPLAINTS REGISTERED':'ଦାଖଲ ହୋଇଥିବା ଅଭିଯୋଗ','REPORT RESOLVED':'ସମାଧାନ ହୋଇଥିବା ରିପୋର୍ଟ','PENDING ACTIONS':'ବାକି ଥିବା କାର୍ଯ୍ୟ','AVG RESPONSE TIME':'ଉତ୍ତରର ହାରାହାରି ସମୟ','Odisha overview':'ଓଡ଼ିଶାର ତଥ୍ୟ','Aggregated reports registered in this demo portal.':'ଏହି ଡେମୋ ପୋର୍ଟାଲରେ ଦାଖଲ ହୋଇଥିବା ମୋଟ ରିପୋର୍ଟ।','Counts only · no personal details':'କେବଳ ସଂଖ୍ୟା · ବ୍ୟକ୍ତିଗତ ତଥ୍ୟ ନାହିଁ','These are local demo submissions, not official police or government statistics. For real cybercrime reporting, use cybercrime.gov.in or call 1930 for financial fraud.':'ଏଗୁଡ଼ିକ ଏହି ଡେମୋର ରିପୋର୍ଟ; ସରକାରୀ ତଥ୍ୟ ନୁହେଁ। ପ୍ରକୃତ ସାଇବର ଅପରାଧ ପାଇଁ cybercrime.gov.in ବ୍ୟବହାର କରନ୍ତୁ କିମ୍ବା ଆର୍ଥିକ ଠକେଇରେ ୧୯୩୦କୁ କଲ୍ କରନ୍ତୁ।','HELP & SUPPORT':'ସହାୟତା','Register a Complaint':'ଅଭିଯୋଗ ଦାଖଲ କରନ୍ତୁ','Contact Us & Support':'ଯୋଗାଯୋଗ ଓ ସହାୟତା','INFORMATION & POLICIES':'ସୂଚନା ଓ ନୀତି','CONTACT US - LEAD DEVELOPER':'ମୁଖ୍ୟ ଡେଭେଲପର୍‌ଙ୍କ ସହ ଯୋଗାଯୋଗ','Formal FIR Draft Application':'FIR ଡ୍ରାଫ୍ଟ ଆବେଦନ','← Edit Form Details':'← ଫର୍ମ ବିବରଣୀ ବଦଳାନ୍ତୁ','🖨️ Print / Save as PDF FIR Draft':'🖨️ FIR ଡ୍ରାଫ୍ଟ ପ୍ରିଣ୍ଟ / PDF ଭାବେ ସେଭ୍','To,':'ପ୍ରତି,','Respected Sir/Madam,':'ମାନ୍ୟବର ମହୋଦୟ/ମହୋଦୟା,','Incident Particulars:':'ଘଟଣାର ବିବରଣୀ:','Financial Loss Details:':'ଆର୍ଥିକ କ୍ଷତିର ବିବରଣୀ:','Total Defrauded Amount:':'ଠକେଇ ହୋଇଥିବା ମୋଟ ରାଶି:','My Affected Bank Account:':'ମୋର ପ୍ରଭାବିତ ବ୍ୟାଙ୍କ ଖାତା:','PRAYER / REQUEST:':'ନିବେଦନ:','Complainant:':'ଅଭିଯୋଗକାରୀ:','Signature of Complainant / ଆବେଦନକାରୀଙ୍କ ଦସ୍ତଖତ':'ଅଭିଯୋଗକାରୀଙ୍କ ଦସ୍ତଖତ','Citizen Case Vault':'ନାଗରିକ ଅଭିଯୋଗ କେନ୍ଦ୍ର','Check Complaint Status':'ଅଭିଯୋଗ ସ୍ଥିତି ଯାଞ୍ଚ କରନ୍ତୁ','Enter registered mobile and password to track filed complaints':'ଦାଖଲ ଅଭିଯୋଗ ଦେଖିବାକୁ ପଞ୍ଜୀକୃତ ମୋବାଇଲ୍ ଓ ପାସୱାର୍ଡ ଦିଅନ୍ତୁ','Account Password *':'ଖାତା ପାସୱାର୍ଡ *','Track My Status →':'ମୋ ଅଭିଯୋଗର ସ୍ଥିତି ଦେଖନ୍ତୁ →','Citizen Complaint Status Center':'ନାଗରିକ ଅଭିଯୋଗ ସ୍ଥିତି କେନ୍ଦ୍ର','New Complaint +':'ନୂଆ ଅଭିଯୋଗ +','Filed Complaints':'ଦାଖଲ ହୋଇଥିବା ଅଭିଯୋଗ','No complaints filed under this account.':'ଏହି ଖାତାରୁ କୌଣସି ଅଭିଯୋଗ ଦାଖଲ ହୋଇନାହିଁ।','Download Receipt':'ରସିଦ ଡାଉନଲୋଡ୍ କରନ୍ତୁ','Attached Media / Photo':'ସଂଲଗ୍ନ ଫାଇଲ୍ / ଫଟୋ','No remark messages exchanged with Admin for this case yet.':'ଏହି ଅଭିଯୋଗ ପାଇଁ ଏଯାଏଁ Admin ସହ କୌଣସି ମେସେଜ୍ ହୋଇନାହିଁ।','Send →':'ପଠାନ୍ତୁ →','Attach Photo/Doc:':'ଫଟୋ/ଦଲିଲ୍ ଯୋଡ଼ନ୍ତୁ:','Select a complaint from left to track status & chat with Admin.':'ସ୍ଥିତି ଦେଖିବା ଓ Admin ସହ କଥା ହେବା ପାଇଁ ବାମପଟୁ ଅଭିଯୋଗ ବାଛନ୍ତୁ।','Officer Remark Desk':'ଅଧିକାରୀଙ୍କ ମତାମତ କେନ୍ଦ୍ର','Complainant:':'ଅଭିଯୋଗକାରୀ:','No remarks exchanged for this case yet.':'ଏହି ଅଭିଯୋଗରେ ଏଯାଏଁ କୌଣସି ମତାମତ ନାହିଁ।','Send Unlimited →':'ପଠାନ୍ତୁ →','Attach Photo/Document:':'ଫଟୋ/ଦଲିଲ୍ ଯୋଡ଼ନ୍ତୁ:','Local URL & UPI Risk Clue Checker':'URL ଓ UPI ସନ୍ଦେହ ସୂଚନା ଯାଞ୍ଚକାରୀ','No complaints filed under this account.':'ଏହି ଖାତାରୁ ଅଭିଭୋଗ ଦାଖଲ ହୋଇନାହିଁ।','Security Captcha:':'ସୁରକ୍ଷା କ୍ୟାପ୍ଚା:','Too many failed attempts. Try again in':'ଅଧିକ ଭୁଲ୍ ଚେଷ୍ଟା ହୋଇଛି। ପୁଣି ଚେଷ୍ଟା କରିବାକୁ ଅପେକ୍ଷା କରନ୍ତୁ','Follow Us:':'ଆମକୁ ଅନୁସରଣ କରନ୍ତୁ:','Contact the site developer':'ସାଇଟ୍ ଡେଭେଲପର୍‌ଙ୍କୁ ଯୋଗାଯୋଗ କରନ୍ତୁ','Last reviewed: October 20, 2026':'ଶେଷ ଯାଞ୍ଚ: ୨୦ ଅକ୍ଟୋବର ୨୦୨୬','Print this page':'ଏହି ପୃଷ୍ଠା ପ୍ରିଣ୍ଟ କରନ୍ତୁ','Read the other pages':'ଅନ୍ୟ ପୃଷ୍ଠା ପଢ଼ନ୍ତୁ',
  'HEAD OFFICER CONTROL':'ମୁଖ୍ୟ ଅଧିକାରୀ ନିୟନ୍ତ୍ରଣ','LOGOUT':'ଲଗଆଉଟ୍','1. Complaints':'୧. ଅଭିଯୋଗ','2. Feedbacks':'୨. ମତାମତ','3. Gen Sub-Admin':'୩. ସବ୍-ଆଡମିନ୍ ତିଆରି','4. Notices':'୪. ସୂଚନା','5. Sub-Admin Chat':'୫. ସବ୍-ଆଡମିନ୍ ଚାଟ୍','Section 1: All Registered Complaints Vault':'ବିଭାଗ ୧: ସମସ୍ତ ପଞ୍ଜୀକୃତ ଅଭିଯୋଗ','Section 2: Received User Feedbacks Vault':'ବିଭାଗ ୨: ମିଳିଥିବା ମତାମତ','Section 3: Generate Sub-Admin Credentials':'ବିଭାଗ ୩: ସବ୍-ଆଡମିନ୍ ଲଗଇନ୍ ତିଆରି','Section 4: Live Notice Board & Banner Updates':'ବିଭାଗ ୪: ସୂଚନା ବୋର୍ଡ ଓ ବ୍ୟାନର୍ ଅପଡେଟ୍','Section 5: Sub-Admin Helpdesk Messenger':'ବିଭାଗ ୫: ସବ୍-ଆଡମିନ୍ ସହାୟତା ମେସେଞ୍ଜର୍','Total:':'ମୋଟ:','Case #':'ଅଭିଯୋଗ #','Complainant:':'ଅଭିଯୋଗକାରୀ:','Contact:':'ଯୋଗାଯୋଗ:','District:':'ଜିଲ୍ଲା:','💬 Citizen Complaint Remarks Window':'💬 ନାଗରିକ ଅଭିଯୋଗ ମତାମତ','Open Citizen Remark Chat →':'ନାଗରିକଙ୍କ ଚାଟ୍ ଖୋଲନ୍ତୁ →','🗺️ Live Satellite GPS Map Location:':'🗺️ GPS ମାନଚିତ୍ର ସ୍ଥାନ:','📷 Evidence:':'📷 ପ୍ରମାଣ:','View File 📁':'ଫାଇଲ୍ ଦେଖନ୍ତୁ 📁','🎙️ Citizen voice complaint':'🎙️ ନାଗରିକଙ୍କ ଭଏସ୍ ଅଭିଯୋଗ','Your browser does not support audio playback.':'ଆପଣଙ୍କ browserରେ audio ଚାଲିପାରିବ ନାହିଁ।','Working...':'କାମ ଚାଲିଛି...','Congratulations! (Case Solved)':'ଅଭିନନ୍ଦନ! (ମାମଲା ସମାଧାନ)','Update Status':'ସ୍ଥିତି ଅପଡେଟ୍ କରନ୍ତୁ','No complaints registered in vault.':'କୌଣସି ଅଭିଯୋଗ ପଞ୍ଜୀକୃତ ହୋଇନାହିଁ।','No complaints available in queue.':'କୌଣସି ଅଭିଯୋଗ ମିଳିଲାନି।','No user feedbacks received yet.':'ଏଯାଏଁ କୌଣସି ମତାମତ ମିଳିନାହିଁ।','Create new Sub-Admin logins for field nodal officers':'କ୍ଷେତ୍ର ଅଧିକାରୀଙ୍କ ପାଇଁ ନୂଆ ସବ୍-ଆଡମିନ୍ ଲଗଇନ୍ ତିଆରି କରନ୍ତୁ','Sub-Admin ID *':'ସବ୍-ଆଡମିନ୍ ID *','Officer Name *':'ଅଧିକାରୀଙ୍କ ନାମ *','Generate Sub-Admin Account →':'ସବ୍-ଆଡମିନ୍ ଖାତା ତିଆରି କରନ୍ତୁ →','Control scrolling marquee text and front page awareness photo banners':'Home pageର notice ଓ ସଚେତନତା ବ୍ୟାନର୍ ନିୟନ୍ତ୍ରଣ କରନ୍ତୁ','1. Marquee Notice Text Update':'୧. ଚଳନ୍ତା ସୂଚନା ଅପଡେଟ୍','Update Notice':'ସୂଚନା ଅପଡେଟ୍ କରନ୍ତୁ','2. Cyber Awareness Photo Banners (Up to 2 Photos)':'୨. ସାଇବର ସଚେତନତା ଫଟୋ ବ୍ୟାନର୍ (୨ଟି ପର୍ଯ୍ୟନ୍ତ)','Photo Banner Slot #1':'ଫଟୋ ବ୍ୟାନର୍ ସ୍ଥାନ #୧','Upload Photo #1':'ଫଟୋ ଅପଲୋଡ୍ #୧','Delete Slot #1 🗑️':'ସ୍ଥାନ #୧ ଡିଲିଟ୍ 🗑️','Photo Banner Slot #2':'ଫଟୋ ବ୍ୟାନର୍ ସ୍ଥାନ #୨','Upload Photo #2':'ଫଟୋ ଅପଲୋଡ୍ #୨','Delete Slot #2 🗑️':'ସ୍ଥାନ #୨ ଡିଲିଟ୍ 🗑️','Directly chat and reply to Sub-Admins with text, photos, recordings, and files':'ସବ୍-ଆଡମିନ୍‌ଙ୍କୁ ମେସେଜ୍, ଫଟୋ, ରେକର୍ଡିଂ ଓ ଫାଇଲ୍ ପଠାନ୍ତୁ','Select Sub-Admin Officer':'ସବ୍-ଆଡମିନ୍ ଅଧିକାରୀ ବାଛନ୍ତୁ','No Sub-Admins generated yet.':'ଏଯାଏଁ କୌଣସି ସବ୍-ଆଡମିନ୍ ତିଆରି ହୋଇନାହାନ୍ତି।','Refresh 🔄':'ରିଫ୍ରେଶ୍ 🔄','📄 View Document Attachment':'ସଂଲଗ୍ନ ଦଲିଲ୍ ଦେଖନ୍ତୁ','No messages exchanged yet.':'ଏଯାଏଁ କୌଣସି ମେସେଜ୍ ନାହିଁ।','Attach File/Media:':'ଫାଇଲ୍/ମିଡିଆ ଯୋଡ଼ନ୍ତୁ:','Please select a Sub-Admin officer from left panel to open live messenger chat.':'ଚାଟ୍ ଆରମ୍ଭ କରିବା ପାଇଁ ବାମପଟୁ ସବ୍-ଆଡମିନ୍ ବାଛନ୍ତୁ।','SUB-ADMIN OFFICER':'ସବ୍-ଆଡମିନ୍ ଅଧିକାରୀ','1. All Complaints Vault':'୧. ସମସ୍ତ ଅଭିଯୋଗ','2. Citizen Feedbacks':'୨. ନାଗରିକ ମତାମତ','3. Direct Head Admin Help':'୩. ମୁଖ୍ୟ ଆଡମିନ୍ ସହାୟତା','Section 1: Shared Citizen Complaints Queue':'ବିଭାଗ ୧: ନାଗରିକ ଅଭିଯୋଗ ତାଲିକା','📷 Submitted Evidence Photo / Document:':'📷 ଦାଖଲ ହୋଇଥିବା ପ୍ରମାଣ ଫଟୋ / ଦଲିଲ୍:','View Evidence File 📁':'ପ୍ରମାଣ ଫାଇଲ୍ ଦେଖନ୍ତୁ 📁','Open Citizen Remark Chat →':'ନାଗରିକଙ୍କ ମତାମତ ଚାଟ୍ ଖୋଲନ୍ତୁ →','Section 2: Citizen Feedbacks Queue':'ବିଭାଗ ୨: ନାଗରିକ ମତାମତ ତାଲିକା','Section 3: Direct Live Chat with Head Admin':'ବିଭାଗ ୩: ମୁଖ୍ୟ ଆଡମିନ୍ ସହ ସିଧା ଚାଟ୍','Send messages, photos, videos, voice recordings, PDFs or document files directly to Head Officer':'ମୁଖ୍ୟ ଅଧିକାରୀଙ୍କୁ ମେସେଜ୍, ଫଟୋ, ଭିଡିଓ, ଭଏସ୍ ରେକର୍ଡିଂ କିମ୍ବା ଦଲିଲ୍ ପଠାନ୍ତୁ','💬 Head Admin Direct Helpdesk':'💬 ମୁଖ୍ୟ ଆଡମିନ୍ ସହାୟତା କେନ୍ଦ୍ର','No previous messages exchanged with Head Admin.':'ମୁଖ୍ୟ ଆଡମିନ୍ ସହ ଏଯାଏଁ କୌଣସି ମେସେଜ୍ ନାହିଁ।','Attach Photo/Video/Audio/PDF:':'ଫଟୋ/ଭିଡିଓ/Audio/PDF ଯୋଡ଼ନ୍ତୁ:','My Complaint Status & Remarks':'ମୋ ଅଭିଯୋଗର ସ୍ଥିତି ଓ ମତାମତ','Mobile:':'ମୋବାଇଲ୍:','Case ID #':'ଅଭିଯୋଗ ID #','📄 Download Receipt':'📄 ରସିଦ ଡାଉନଲୋଡ୍ କରନ୍ତୁ','📁 Attached Media / Photo':'📁 ସଂଲଗ୍ନ ଫାଇଲ୍ / ଫଟୋ','🔒 Citizen Chat Locked (5-Min Time Limit Reached)':'🔒 ନାଗରିକ ଚାଟ୍ ଲକ୍ (୫ ମିନିଟ୍ ସମୟ ସୀମା ଶେଷ)','You can send messages again after':'ଆପଣ ପୁଣି ମେସେଜ୍ ପଠାଇପାରିବେ','⚠️ Active Window: 5 Mins Max limit':'⚠️ ସକ୍ରିୟ ସମୟ: ସର୍ବାଧିକ ୫ ମିନିଟ୍','Officer Citizen Chat Remark Desk':'ଅଧିକାରୀ-ନାଗରିକ ମତାମତ ଚାଟ୍','← Back to Dashboard':'← ଡ୍ୟାସବୋର୍ଡକୁ ଫେରନ୍ତୁ','Send Unlimited →':'ପଠାନ୍ତୁ →','Attach Photo/Document:':'ଫଟୋ/ଦଲିଲ୍ ଯୋଡ଼ନ୍ତୁ:'
 };
 const dynamicPrefixes={'Congratulations, ':'ଅଭିନନ୍ଦନ, ','Registered Mobile: ':'ପଞ୍ଜୀକୃତ ମୋବାଇଲ୍: ','Case ID: #':'ଅଭିଯୋଗ ID: #','Active Contact Mobile: ':'ଯୋଗାଯୋଗ ମୋବାଇଲ୍: ','District: ':'ଜିଲ୍ଲା: ','Block: ':'ବ୍ଲକ୍: ','Security Captcha: ':'ସୁରକ୍ଷା କ୍ୟାପ୍ଚା: ','Incorrect CAPTCHA answer!':'ଭୁଲ CAPTCHA ଉତ୍ତର!','Enter a valid mobile number and password with at least 10 characters.':'ସଠିକ୍ ମୋବାଇଲ୍ ନମ୍ବର ଏବଂ ଅତି କମରେ ୧୦ ଅକ୍ଷରର ପାସୱାର୍ଡ ଦିଅନ୍ତୁ।','Mobile already registered! Please login.':'ଏହି ମୋବାଇଲ୍ ପୂର୍ବରୁ ପଞ୍ଜୀକୃତ। ଦୟାକରି ଲଗଇନ୍ କରନ୍ତୁ।'};
 Object.assign(od,{
  '🔒 Encrypted Registration':'🔒 ସୁରକ୍ଷିତ ପଞ୍ଜୀକରଣ','Enter 10-digit mobile':'୧୦ ଅଙ୍କର ମୋବାଇଲ୍ ନମ୍ବର ଦିଅନ୍ତୁ','Create secure password':'ସୁରକ୍ଷିତ ପାସୱାର୍ଡ ତିଆରି କରନ୍ତୁ','Enter sum':'ଯୋଗଫଳ ଲେଖନ୍ତୁ','Security Captcha:':'ସୁରକ୍ଷା କ୍ୟାପ୍ଚା:','Create credentials to access cyber complaint filing':'ସାଇବର ଅଭିଯୋଗ ଦାଖଲ ପାଇଁ ଲଗଇନ୍ ବିବରଣୀ ତିଆରି କରନ୍ତୁ',
  'CyberShield information':'CyberShield ସୂଚନା','Last reviewed: October 20, 2026':'ଶେଷ ସମୀକ୍ଷା: ୨୦ ଅକ୍ଟୋବର ୨୦୨୬','Print this page':'ଏହି ପୃଷ୍ଠା ପ୍ରିଣ୍ଟ କରନ୍ତୁ','Read the other pages':'ଅନ୍ୟ ପୃଷ୍ଠାଗୁଡ଼ିକ ଦେଖନ୍ତୁ','Contact the site developer':'ସାଇଟ୍ ଡେଭେଲପର୍‌ଙ୍କୁ ଯୋଗାଯୋଗ କରନ୍ତୁ','CyberShield Portal is an independent project. This information page does not make the site an official government service.':'CyberShield Portal ଏକ ସ୍ୱତନ୍ତ୍ର ପ୍ରକଳ୍ପ। ଏହି ସୂଚନା ପୃଷ୍ଠା ଏହାକୁ ସରକାରୀ ସେବା କରେନାହିଁ।',
  '1. Who operates this website':'୧. ଏହି ୱେବସାଇଟ୍ କିଏ ଚଳାଏ','2. Not an official complaint channel':'୨. ଏହା ସରକାରୀ ଅଭିଯୋଗ ମାଧ୍ୟମ ନୁହେଁ','3. General information only':'୩. କେବଳ ସାଧାରଣ ସୂଚନା','4. Accuracy, availability and response':'୪. ସଠିକତା, ଉପଲବ୍ଧତା ଓ ଉତ୍ତର','5. User-submitted material':'୫. ବ୍ୟବହାରକାରୀଙ୍କ ଦାଖଲ ସାମଗ୍ରୀ','6. External websites and third-party services':'୬. ବାହ୍ୟ ୱେବସାଇଟ୍ ଓ ତୃତୀୟ ପକ୍ଷ ସେବା','7. Limits and contact':'୭. ସୀମା ଓ ଯୋଗାଯୋଗ',
  '1. About these terms':'୧. ଏହି ସର୍ତ୍ତାବଳୀ ବିଷୟରେ','2. Who may use the site':'୨. କିଏ ଏହି ସାଇଟ୍ ବ୍ୟବହାର କରିପାରିବେ','3. Acceptable use':'୩. ଗ୍ରହଣଯୋଗ୍ୟ ବ୍ୟବହାର','4. Accounts, passwords and demo features':'୪. ଖାତା, ପାସୱାର୍ଡ ଓ ଡେମୋ ସୁବିଧା','5. Content and uploads':'୫. ବିଷୟବସ୍ତୁ ଓ ଅପଲୋଡ୍','6. Intellectual property and third-party links':'୬. ବୌଦ୍ଧିକ ସମ୍ପତ୍ତି ଓ ତୃତୀୟ ପକ୍ଷ ଲିଙ୍କ୍','7. Availability, changes and liability':'୭. ଉପଲବ୍ଧତା, ପରିବର୍ତ୍ତନ ଓ ଦାୟିତ୍ୱ','8. Questions and governing law':'୮. ପ୍ରଶ୍ନ ଓ ପ୍ରଯୁଜ୍ୟ ଆଇନ',
  '1. Who is responsible for information':'୧. ତଥ୍ୟ ପାଇଁ କିଏ ଦାୟୀ','2. Information the application may collect':'୨. ଆପ୍ଲିକେସନ୍ କେଉଁ ତଥ୍ୟ ସଂଗ୍ରହ କରିପାରେ','3. Why the information is used':'୩. ତଥ୍ୟ କାହିଁକି ବ୍ୟବହାର ହୁଏ','4. Where information is stored and who can see it':'୪. ତଥ୍ୟ କେଉଁଠି ରହେ ଓ କିଏ ଦେଖିପାରେ','5. Sharing and disclosure':'୫. ତଥ୍ୟ ବାଣ୍ଟିବା ଓ ପ୍ରକାଶ','6. Retention, correction and deletion':'୬. ତଥ୍ୟ ରଖିବା, ସଂଶୋଧନ ଓ ହଟାଇବା','7. Children, security incidents and updates':'୭. ଶିଶୁ, ସୁରକ୍ଷା ଘଟଣା ଓ ଅପଡେଟ୍',
  'Understand what CyberShield Portal is, what it is not, and where to report cybercrime officially.':'CyberShield Portal କଣ, କଣ ନୁହେଁ ଏବଂ ସାଇବର ଅପରାଧ କେଉଁଠି ସରକାରୀ ଭାବେ ଜଣାଇବେ ଜାଣନ୍ତୁ।','The rules for responsible use of this independent CyberShield project and its demonstration features.':'ଏହି ସ୍ୱତନ୍ତ୍ର CyberShield ପ୍ରକଳ୍ପ ଓ ଡେମୋ ସୁବିଧାର ଦାୟିତ୍ୱପୂର୍ଣ୍ଣ ବ୍ୟବହାର ନିୟମ।','Learn what information this application may collect, how the current build stores it, and how to contact the operator.':'ଏହି ଆପ୍ କେଉଁ ତଥ୍ୟ ନେଇପାରେ, ବର୍ତ୍ତମାନର ସଂସ୍କରଣ ତାହା କିପରି ରଖେ ଓ ପରିଚାଳକଙ୍କୁ କିପରି ଯୋଗାଯୋଗ କରିବେ ଜାଣନ୍ତୁ।',
  'CyberShield Portal is an independent project, not a government reporting service. For an actual cybercrime report, use':'CyberShield Portal ଏକ ସ୍ୱତନ୍ତ୍ର ପ୍ରକଳ୍ପ, ସରକାରୀ ରିପୋର୍ଟ ସେବା ନୁହେଁ। ପ୍ରକୃତ ସାଇବର ଅପରାଧ ରିପୋର୍ଟ ପାଇଁ ବ୍ୟବହାର କରନ୍ତୁ','This website is not an official complaint channel. Do not submit sensitive real-world complaint information until the deployment has been securely reviewed.':'ଏହି ୱେବସାଇଟ୍ ସରକାରୀ ଅଭିଯୋଗ ମାଧ୍ୟମ ନୁହେଁ। ସୁରକ୍ଷା ସମୀକ୍ଷା ନହେବା ପର୍ଯ୍ୟନ୍ତ ପ୍ରକୃତ ସମ୍ବେଦନଶୀଳ ଅଭିଯୋଗ ତଥ୍ୟ ଦାଖଲ କରନ୍ତୁ ନାହିଁ।','Security note: the reviewed build stores account passwords without safe hashing and does not restrict uploaded files per user. Do not submit real sensitive information until those issues are fixed.':'ସୁରକ୍ଷା ସୂଚନା: ଯାଞ୍ଚ ହୋଇଥିବା ସଂସ୍କରଣ ଖାତା ପାସୱାର୍ଡକୁ ସୁରକ୍ଷିତ hash ବିନା ରଖେ ଏବଂ ପ୍ରତି ବ୍ୟବହାରକାରୀ ଅନୁସାରେ ଅପଲୋଡ୍ ଫାଇଲ୍ ସୀମିତ କରେନାହିଁ। ଏହି ସମସ୍ୟା ଠିକ୍ ହେବା ପର୍ଯ୍ୟନ୍ତ ପ୍ରକୃତ ସମ୍ବେଦନଶୀଳ ତଥ୍ୟ ଦାଖଲ କରନ୍ତୁ ନାହିଁ।',
  'CyberShield Portal is an independent student/developer project created for learning, demonstration and general public awareness. It is not owned, operated, authorised, sponsored or endorsed by the Government of India, the Government of Odisha, the Indian Cyber Crime Coordination Centre (I4C), the National Cyber Crime Reporting Portal, any police department, or any court. The name, design, sample dashboard figures, notices and role labels on this site must not be taken as proof of government affiliation or official authority.':'CyberShield Portal ଶିକ୍ଷା, ଡେମୋ ଓ ସାଧାରଣ ସଚେତନତା ପାଇଁ ଛାତ୍ର/ଡେଭେଲପର୍‌ଙ୍କ ସ୍ୱତନ୍ତ୍ର ପ୍ରକଳ୍ପ। ଏହା ଭାରତ ସରକାର, ଓଡ଼ିଶା ସରକାର, I4C, National Cyber Crime Reporting Portal, କୌଣସି ପୋଲିସ୍ ବିଭାଗ କିମ୍ବା ଅଦାଲତର ମାଲିକାନା/ପରିଚାଳନା/ଅନୁମୋଦନରେ ନାହିଁ। ଏଠାର ନାମ, ଡିଜାଇନ୍, ନମୁନା ସଂଖ୍ୟା, ସୂଚନା କିମ୍ବା ପଦବୀକୁ ସରକାରୀ ସମ୍ପର୍କ ବା ଅଧିକାରର ପ୍ରମାଣ ଭାବେ ଧରନ୍ତୁ ନାହିଁ।','A form submission, message, account entry, status view or document generated here does not by itself register a complaint with the police, create an FIR, preserve evidence with an authority, start an investigation, or guarantee that any public authority will receive or act on it. Do not rely on this project for urgent reporting or legal deadlines.':'ଏଠାରେ ଫର୍ମ, ମେସେଜ୍, ଖାତା ତଥ୍ୟ, ସ୍ଥିତି ଦେଖିବା କିମ୍ବା ତିଆରି ଡକ୍ୟୁମେଣ୍ଟ ଦ୍ୱାରା ପୋଲିସ୍‌ରେ ଅଭିଯୋଗ/FIR ଦାଖଲ, ପ୍ରମାଣ ସଂରକ୍ଷଣ, ତଦନ୍ତ ଆରମ୍ଭ କିମ୍ବା ସରକାରୀ କାର୍ଯ୍ୟର ନିଶ୍ଚୟତା ହୁଏନାହିଁ। ଜରୁରୀ ରିପୋର୍ଟ କିମ୍ବା ଆଇନଗତ ସମୟସୀମା ପାଇଁ ଏହି ପ୍ରକଳ୍ପ ଉପରେ ନିର୍ଭର କରନ୍ତୁ ନାହିଁ।','Articles, notices, FAQs, generated forms, sample text, analytics, status labels and other material are provided for general information and demonstration. They are not legal, financial, forensic, law-enforcement or professional advice. Laws and procedures can change, and a general explanation may not fit your situation. Obtain advice from a qualified professional or the relevant authority before acting on a serious matter.':'ଲେଖା, ସୂଚନା, FAQ, ତିଆରି ଫର୍ମ, ନମୁନା ଟେକ୍ସଟ୍, ତଥ୍ୟ ଓ ସ୍ଥିତି କେବଳ ସାଧାରଣ ସୂଚନା ଓ ଡେମୋ ପାଇଁ। ଏହା ଆଇନ, ଆର୍ଥିକ, ଫରେନସିକ୍, ପୋଲିସ୍ କିମ୍ବା ବୃତ୍ତିଗତ ପରାମର୍ଶ ନୁହେଁ। ଆଇନ ଓ ପ୍ରକ୍ରିୟା ବଦଳିପାରେ; ଗୁରୁତ୍ୱପୂର୍ଣ୍ଣ ପଦକ୍ଷେପ ପୂର୍ବରୁ ଯୋଗ୍ୟ ବିଶେଷଜ୍ଞ ବା ସମ୍ପୃକ୍ତ କର୍ତ୍ତୃପକ୍ଷଙ୍କ ପରାମର୍ଶ ନିଅନ୍ତୁ।','Any generated FIR-style document or draft is only a user-prepared document. It is not an FIR, police record, official certificate, evidence verification or proof that an authority has accepted a report.':'ତିଆରି ହୋଇଥିବା FIR ଶୈଳୀର ଡକ୍ୟୁମେଣ୍ଟ କେବଳ ବ୍ୟବହାରକାରୀଙ୍କ ନିଜସ୍ୱ ଡ୍ରାଫ୍ଟ। ଏହା FIR, ପୋଲିସ୍ ରେକର୍ଡ, ସରକାରୀ ପ୍ରମାଣପତ୍ର, ପ୍ରମାଣ ଯାଞ୍ଚ କିମ୍ବା କର୍ତ୍ତୃପକ୍ଷ ରିପୋର୍ଟ ଗ୍ରହଣ କରିଥିବାର ପ୍ରମାଣ ନୁହେଁ।',
  'The website may be changed, interrupted, unavailable, or discontinued. A message or feedback form is not an emergency service and may not receive an immediate response. No response should be interpreted as acceptance, rejection or official action on a complaint.':'ୱେବସାଇଟ୍ ବଦଳିପାରେ, ବନ୍ଦ ବା ଅସ୍ଥାୟୀ ଭାବେ ଅଚଳ ହୋଇପାରେ। ମେସେଜ୍ କିମ୍ବା ମତାମତ ଫର୍ମ ଜରୁରୀକାଳୀନ ସେବା ନୁହେଁ ଏବଂ ତୁରନ୍ତ ଉତ୍ତର ନମିଳିପାରେ। ଉତ୍ତର ନମିଳିବାକୁ ଅଭିଯୋଗ ଗ୍ରହଣ, ପ୍ରତ୍ୟାଖ୍ୟାନ କିମ୍ବା ସରକାରୀ କାର୍ଯ୍ୟ ଭାବେ ଧରନ୍ତୁ ନାହିଁ।','You are responsible for the accuracy and lawfulness of information you submit. Submit only information you are entitled to provide. Do not upload malware, threats, unlawful material, unrelated personal information, or another person\'s sensitive details unless you have lawful authority to do so. Do not use this site to harass, impersonate, threaten or make knowingly false allegations.':'ଆପଣ ଦାଖଲ କରୁଥିବା ତଥ୍ୟର ସଠିକତା ଓ ଆଇନସମ୍ମତତା ପାଇଁ ଆପଣ ଦାୟୀ। ଦେବାର ଅଧିକାର ଥିବା ତଥ୍ୟ ମାତ୍ର ଦିଅନ୍ତୁ। ମାଲୱେର୍, ଧମକ, ବେଆଇନ ସାମଗ୍ରୀ, ଅସମ୍ପର୍କିତ ବ୍ୟକ୍ତିଗତ ତଥ୍ୟ କିମ୍ବା ଅନ୍ୟଙ୍କ ସମ୍ବେଦନଶୀଳ ବିବରଣୀ ଅପଲୋଡ୍ କରନ୍ତୁ ନାହିଁ। ହଇରାଣ, ଛଦ୍ମବେଶ, ଧମକ କିମ୍ବା ଜାଣିଶୁଣି ମିଥ୍ୟା ଅଭିଯୋଗ ପାଇଁ ସାଇଟ୍ ବ୍ୟବହାର କରନ୍ତୁ ନାହିଁ।'
 });
 const skip='.lang-section,script,style,textarea,[contenteditable="true"],[data-no-translate]';
 function translatePage(lang){
  document.documentElement.lang=lang==='or'?'or':'en';
  const walker=document.createTreeWalker(document.body,NodeFilter.SHOW_TEXT);
  const nodes=[]; while(walker.nextNode()) nodes.push(walker.currentNode);
  const originalTextByNode=new WeakMap();
  for(const n of nodes){
   if(n.parentElement && n.parentElement.closest(skip)) continue;
   if(!originalTextByNode.has(n)) originalTextByNode.set(n,n.nodeValue);
   const original=originalTextByNode.get(n); const key=original.trim().replace(/\s+/g,' ');
   let translated=od[key];
   if(lang==='or' && !translated){for(const en in dynamicPrefixes)if(key.startsWith(en)){translated=dynamicPrefixes[en]+key.slice(en.length);break;}}
   if(lang==='or' && translated) { const lead=original.match(/^\s*/)[0], tail=original.match(/\s*$/)[0]; n.nodeValue=lead+translated+tail; }
   else n.nodeValue=original;
  }
  document.querySelectorAll('input[placeholder],button[aria-label],img[alt],input[type=submit][value],title').forEach(el=>{
   for(const a of ['placeholder','aria-label','alt','value']) if(el.hasAttribute(a)){
    const k='en'+a.charAt(0).toUpperCase()+a.slice(1); if(!el.dataset[k]) el.dataset[k]=el.getAttribute(a);
    const v=el.dataset[k].trim(); el.setAttribute(a,lang==='or'?(od[v]||el.dataset[k]):el.dataset[k]);
   }
  });
  if(document.getElementById('btn-en') && typeof window.switchLang==='function') window.switchLang(lang);
  if(document.getElementById('btn-fir-en') && typeof window.toggleFIRLang==='function') window.toggleFIRLang(lang);
 }
 function setLang(lang){localStorage.setItem('cybershield-language',lang); translatePage(lang);}
 window.setCyberShieldLanguage=setLang;
 const path=location.pathname;
 if(path!=='/'){
  const bar=document.createElement('div'); bar.setAttribute('data-no-translate','1'); bar.className='fixed right-3 top-3 z-[99999] flex gap-1 rounded-xl border border-cyan-500/50 bg-slate-950/95 p-1 shadow-xl';
  bar.innerHTML='<button type="button" data-site-lang="en" class="rounded-lg px-3 py-2 text-xs font-black text-white">English</button><button type="button" data-site-lang="or" class="rounded-lg px-3 py-2 text-xs font-black text-white">ଓଡ଼ିଆ</button>';
  document.body.appendChild(bar);
 }
 document.addEventListener('click',e=>{const b=e.target.closest('[data-site-lang],#btn-en,#btn-or,#btn-fir-en,#btn-fir-or');if(!b)return;const lang=b.dataset.siteLang||(b.id.endsWith('-or')?'or':'en');setLang(lang);});
 const saved=localStorage.getItem('cybershield-language')||'en';
 if(document.readyState==='loading') document.addEventListener('DOMContentLoaded',()=>translatePage(saved),{once:true}); else translatePage(saved);
 const observer=new MutationObserver(records=>{if(localStorage.getItem('cybershield-language')!=='or')return;for(const r of records)for(const n of r.addedNodes){if(n.nodeType===Node.TEXT_NODE){if(n.parentElement&&!n.parentElement.closest(skip)){const k=n.nodeValue.trim().replace(/\s+/g,' ');if(od[k])n.nodeValue=n.nodeValue.replace(n.nodeValue.trim(),od[k]);}}else if(n.nodeType===Node.ELEMENT_NODE){const w=document.createTreeWalker(n,NodeFilter.SHOW_TEXT);while(w.nextNode()){const t=w.currentNode;if(!t.parentElement.closest(skip)){const k=t.nodeValue.trim().replace(/\s+/g,' ');if(od[k])t.nodeValue=t.nodeValue.replace(t.nodeValue.trim(),od[k]);}}}}});
 observer.observe(document.body,{childList:true,subtree:true});
})();
</script>
"""

@app.after_request
def add_security_headers(response):
    response.headers.setdefault('X-Content-Type-Options', 'nosniff')
    response.headers.setdefault('X-Frame-Options', 'SAMEORIGIN')
    response.headers.setdefault('Referrer-Policy', 'strict-origin-when-cross-origin')
    if response.mimetype == 'text/html' and not response.direct_passthrough:
        html = response.get_data(as_text=True)
        if '</body>' in html:
            response.set_data(html.replace('</body>', SITE_LANGUAGE_SCRIPT + '\n</body>', 1))
    return response

# --- HOME PAGE ---
HOME_PAGE = '''
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>CyberShield - Cyber Safety Demo Portal</title>
    <script src="https://cdn.tailwindcss.com"></script>
    <link href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css" rel="stylesheet">
    <script src="https://cdnjs.cloudflare.com/ajax/libs/vanilla-tilt/1.8.0/vanilla-tilt.min.js"></script>
    <style>
        .hero-cyber-bg { background-color: #030712; position: relative; overflow: hidden; }
        canvas { position: absolute; top: 0; left: 0; width: 100%; height: 100%; pointer-events: none; z-index: 1; opacity: 0.35; }
        @keyframes fadeInUp { from { opacity: 0; transform: translateY(30px); } to { opacity: 1; transform: translateY(0); } }
        .animate-fade-in-up { animation: fadeInUp 0.8s ease-out forwards; }
        .neon-card { transition: all 0.4s cubic-bezier(0.165, 0.84, 0.44, 1); }
        .neon-card:hover { transform: translateY(-8px) scale(1.02); box-shadow: 0 0 30px rgba(59, 130, 246, 0.7), inset 0 0 15px rgba(239, 68, 68, 0.5); border-color: #3b82f6; }
        @keyframes pulse-glow { 0%, 100% { transform: scale(1); box-shadow: 0 0 15px rgba(220, 38, 38, 0.8); } 50% { transform: scale(1.05); box-shadow: 0 0 30px rgba(220, 38, 38, 1); } }
        .emergency-pulse { animation: pulse-glow 1.5s infinite; }
        .lang-section { display: none; }
        .lang-section.active { display: block; animation: fadeInUp 0.5s ease-out; }

        .slide-img {
            position: absolute;
            top: 0; left: 0;
            width: 100%; height: 100%;
            object-fit: cover;
            opacity: 0;
            transition: opacity 0.8s ease-in-out, transform 0.8s ease-in-out;
            transform: scale(1.08);
        }
        .slide-img.active-slide {
            opacity: 1;
            transform: scale(1);
        }
        .faq-hidden { display: none; }
    </style>
</head>
<body class="bg-gray-950 text-gray-100 font-sans antialiased min-h-screen flex flex-col justify-between">

    <!-- TOP NAVIGATION BAR -->
    <div class="bg-blue-950 text-white text-xs md:text-sm py-2.5 px-4 md:px-6 flex flex-wrap justify-between items-center font-medium border-b border-blue-800/65 shadow-md relative z-20 gap-2">
        <div class="flex items-center space-x-3">
            <span class="bg-red-600 text-white px-3 py-1 rounded-full text-[10px] md:text-[11px] font-black tracking-wider emergency-pulse">🚨 EMERGENCY</span>
            <span>Helpline: <strong class="text-yellow-300 font-black tracking-widest text-sm">1930</strong></span>
        </div>
        <div class="flex flex-wrap items-center space-x-2 md:space-x-3 text-xs">
            <a href="/fir-generator" class="bg-amber-400 hover:bg-amber-300 text-blue-950 px-3 py-1 rounded-lg font-black transition flex items-center gap-1.5 shadow transform hover:scale-105">
                <i class="fa-solid fa-file-contract"></i> 📄 FIR DRAFT GENERATOR
            </a>
            <span class="text-blue-300 font-bold hidden sm:inline">Language / ଭାଷା:</span>
            <button onclick="switchLang('en')" id="btn-en" class="bg-yellow-400 text-blue-950 font-black px-2.5 py-1 rounded-lg shadow transition transform hover:scale-105">English</button>
            <button onclick="switchLang('or')" id="btn-or" class="bg-gray-800 text-white font-bold px-2.5 py-1 rounded-lg hover:bg-gray-700 transition transform hover:scale-105">ଓଡ଼ିଆ</button>
            <span class="text-blue-700">|</span>
            <a href="/login" class="hover:text-yellow-300 font-bold transition flex items-center gap-1"><i class="fa-solid fa-user-lock"></i> Login</a>
            <a href="/sub-admin-login" class="bg-purple-600 hover:bg-purple-500 text-white px-2.5 py-1 rounded-lg font-black transition shadow flex items-center gap-1 transform hover:scale-105"><i class="fa-solid fa-user-shield"></i> Sub-Admin</a>
            <a href="/admin-login" class="hover:text-yellow-300 font-bold transition flex items-center gap-1"><i class="fa-solid fa-shield-halved"></i> Admin</a>
        </div>
    </div>

    <!-- DYNAMIC NOTICE BOARD MARQUEE -->
    <div class="bg-amber-500 text-blue-950 font-bold text-xs py-2 px-4 md:px-6 flex items-center justify-between shadow-inner">
        <div class="flex items-center gap-2 overflow-hidden whitespace-nowrap w-full">
            <span class="bg-blue-950 text-yellow-300 px-2 py-0.5 rounded text-[10px] font-black uppercase tracking-wider animate-pulse flex-shrink-0">📢 Notice</span>
            <marquee scrollamount="5" class="font-extrabold text-blue-950">
                {{ notice_text }}
            </marquee>
        </div>
    </div>

    <header class="bg-gray-900/90 backdrop-blur-md py-4 px-4 md:px-12 flex flex-col md:flex-row justify-between items-center border-b border-gray-800 sticky top-0 z-50 shadow-xl gap-4">
        <div class="flex items-center space-x-4">
            <div class="w-12 h-12 md:w-14 md:h-14 bg-gradient-to-tr from-blue-700 to-indigo-900 text-white rounded-2xl flex items-center justify-center text-2xl md:text-3xl font-black shadow-lg border-2 border-yellow-400">🛡️</div>
            <div>
                <h1 class="text-xl md:text-3xl font-black text-white tracking-tight">CyberShield Portal</h1>
                <p class="text-[10px] md:text-[11px] text-yellow-300 font-extrabold tracking-widest uppercase">INDEPENDENT CYBER SAFETY DEMO PROJECT</p>
            </div>
        </div>
        <div class="flex flex-wrap items-center space-x-2 md:space-x-3 w-full md:w-auto justify-center gap-2">
            <a href="/track-status-login" class="bg-emerald-600 hover:bg-emerald-500 text-white px-4 md:px-5 py-2.5 rounded-xl font-black text-xs uppercase tracking-wider shadow-lg transition text-center flex items-center gap-1.5 transform hover:scale-105 border border-emerald-400">
                <i class="fa-solid fa-magnifying-glass"></i> CHECK COMPLAINT STATUS
            </a>
            <a href="/register" class="bg-blue-600 hover:bg-blue-700 text-white px-4 md:px-5 py-2.5 rounded-xl font-bold text-xs uppercase tracking-wider shadow-lg transition text-center flex-1 md:flex-none transform hover:scale-105">REGISTER ACCOUNT</a>
            <a href="/live-checker" class="bg-gradient-to-r from-amber-500 to-yellow-400 hover:brightness-110 text-blue-950 px-4 md:px-5 py-2.5 rounded-xl font-black text-xs uppercase tracking-wider shadow-xl transition flex items-center justify-center gap-2 border-2 border-yellow-300 animate-pulse flex-1 md:flex-none transform hover:scale-105">
                <i class="fa-solid fa-shield-virus text-sm"></i> LOCAL URL & UPI CHECK
            </a>
        </div>
    </header>

    <!-- HERO SECTION -->
    <section class="hero-cyber-bg py-16 md:py-20 px-4 md:px-6 text-center relative border-b-4 border-blue-600 min-h-[400px] flex flex-col justify-center">
        <canvas id="matrixCanvas"></canvas>
        <div class="max-w-5xl mx-auto relative z-10 space-y-6 animate-fade-in-up">
            <span class="bg-red-600/40 text-yellow-300 border border-red-500/60 px-4 py-2 rounded-full text-xs font-black uppercase tracking-widest inline-block backdrop-blur-md shadow-2xl">
                🔒 Cyber Safety Learning & Complaint Workflow Demo
            </span>
            <h2 class="text-2xl md:text-5xl font-black text-white leading-tight tracking-tight">
                <span class="lang-section active" data-lang="en">Report Cyber Frauds & Secure Online Assets Real-Time</span>
                <span class="lang-section" data-lang="or">ସାଇବର ଠକେଇ ରିପୋର୍ଟ କରନ୍ତୁ ଏବଂ ଅନଲାଇନ୍ ସମ୍ପତ୍ତି ସୁରକ୍ଷିତ ରଖନ୍ତୁ</span>
            </h2>
            <p class="text-xs md:text-base text-gray-300 max-w-2xl mx-auto leading-relaxed">
                <span class="lang-section active" data-lang="en">Independent demo portal. Submissions are stored only in this project's local database and are not sent to any authority.</span>
                <span class="lang-section" data-lang="or">ସାଇବର ନୋଡାଲ୍ ଟିମ୍ ସହିତ ସିଧାସଳଖ ସଂଯୋଜିତ। ତଳୁ କାଟେଗୋରୀ ବାଛି କମ୍ପ୍ଲେନ୍ କରନ୍ତୁ।</span>
            </p>

            {% if notice_photo1 or notice_photo2 %}
            <div class="pt-6 grid grid-cols-1 md:grid-cols-2 gap-4 max-w-5xl mx-auto items-center justify-center">
                {% if notice_photo1 %}
                <div class="overflow-hidden rounded-2xl shadow-2xl border-2 border-yellow-400 bg-gray-900">
                    <img src="/uploads/{{ notice_photo1 }}" alt="Notice Photo 1" class="w-full h-auto max-h-72 object-contain mx-auto hover:scale-105 transition duration-500">
                </div>
                {% endif %}
                {% if notice_photo2 %}
                <div class="overflow-hidden rounded-2xl shadow-2xl border-2 border-yellow-400 bg-gray-900">
                    <img src="/uploads/{{ notice_photo2 }}" alt="Notice Photo 2" class="w-full h-auto max-h-72 object-contain mx-auto hover:scale-105 transition duration-500">
                </div>
                {% endif %}
            </div>
            {% endif %}
        </div>
    </section>

    <!-- LIVE BREAKING NEWS -->
    <div class="bg-red-600 text-white font-bold text-xs py-2.5 px-4 md:px-12 flex items-center shadow-lg my-4">
        <span class="bg-yellow-400 text-blue-950 px-3 py-1 rounded-full text-[10px] font-black uppercase tracking-wider flex items-center gap-1 flex-shrink-0 mr-3">
            <i class="fa-solid fa-bell"></i> LIVE BREAKING NEWS
        </span>
        <marquee scrollamount="6" class="font-bold text-white">
            🚨 CYBER ALERT: Never share OTP, UPI PIN, or bank passwords with anyone. Beware of fake Digital Arrest warrants and unauthorized loan apps! Report instantly on 1930.
        </marquee>
    </div>

    <!-- 4 COMPLAINT CATEGORIES -->
    <section class="py-10 md:py-12 px-4 md:px-6 max-w-7xl mx-auto w-full space-y-6">
        <div class="text-center">
            <span class="bg-blue-500/20 text-blue-300 border border-blue-500/40 text-[11px] font-black px-4 py-1.5 rounded-full uppercase tracking-widest inline-block">
                <span class="lang-section active" data-lang="en">⚡ Select Category to Register</span>
                <span class="lang-section" data-lang="or">⚡ ପଞ୍ଜୀକରଣ ପାଇଁ କାଟେଗୋରୀ ବାଛନ୍ତୁ</span>
            </span>
            <h3 class="text-xl md:text-3xl font-black text-white mt-2">
                <span class="lang-section active" data-lang="en">Cyber Incident Filing Categories</span>
                <span class="lang-section" data-lang="or">ସାଇବର ଅପରାଧ କାଟେଗୋରୀ ସମୂହ</span>
            </h3>
        </div>

        <div class="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-6">
            <a href="/select-category?cat=Sexual%20Harassment%20%26%20Cyber%20Stalking" data-tilt data-tilt-max="15" class="neon-card bg-gradient-to-br from-purple-900/80 to-purple-950 border-2 border-purple-500/50 p-6 rounded-3xl shadow-2xl flex flex-col justify-between animate-fade-in-up">
                <div>
                    <div class="w-12 h-12 bg-purple-600/30 text-purple-400 rounded-2xl flex items-center justify-center text-2xl mb-4 border border-purple-500/40"><i class="fa-solid fa-venus"></i></div>
                    <h4 class="text-lg font-black text-white mb-2">
                        <span class="lang-section active" data-lang="en">1. Sexual Harassment</span>
                        <span class="lang-section" data-lang="or">୧. ଯୌନ ଉତ୍ପୀଡ଼ନ ଓ ଷ୍ଟାଲ୍‌କିଂ</span>
                    </h4>
                    <p class="text-xs text-gray-400">
                        <span class="lang-section active" data-lang="en">Cyber stalking, morphing, non-consensual image abuse & online harassment.</span>
                        <span class="lang-section" data-lang="or">ଅଶ୍ଳୀଳ ଫଟୋ ଭାଇରାଲ୍, ମର୍ଫିଂ ଏବଂ ଅନଲାଇନ୍ ହଇରାଣ ହରକତ।</span>
                    </p>
                </div>
                <div class="mt-6 text-xs font-bold text-yellow-400 flex items-center gap-1"><span>File Complaint</span> <i class="fa-solid fa-arrow-right"></i></div>
            </a>

            <a href="/select-category?cat=Financial%20Fraud%20%26%20Identity%20Scam" data-tilt data-tilt-max="15" class="neon-card bg-gradient-to-br from-red-900/80 to-red-950 border-2 border-red-500/50 p-6 rounded-3xl shadow-2xl flex flex-col justify-between animate-fade-in-up" style="animation-delay: 0.1s;">
                <div>
                    <div class="w-12 h-12 bg-red-600/30 text-red-400 rounded-2xl flex items-center justify-center text-2xl mb-4 border border-red-500/40"><i class="fa-solid fa-sack-xmark"></i></div>
                    <h4 class="text-lg font-black text-white mb-2">
                        <span class="lang-section active" data-lang="en">2. Identity & UPI Scam</span>
                        <span class="lang-section" data-lang="or">୨. ଆର୍ଥିକ ଠକେଇ ଓ ୟୁପିଆଇ ସ୍କାମ୍</span>
                    </h4>
                    <p class="text-xs text-gray-400">
                        <span class="lang-section active" data-lang="en">UPI payment frauds, phishing links, OTP theft & fake lottery scams.</span>
                        <span class="lang-section" data-lang="or">ୟୁପିଆଇ ଠକେଇ, ଫିସିଂ ଲିଙ୍କ୍, ଓଟିପି ଚୋରି ଏବଂ ଲଟେରୀ ପ୍ରଲୋଭନ।</span>
                    </p>
                </div>
                <div class="mt-6 text-xs font-bold text-yellow-400 flex items-center gap-1"><span>File Complaint</span> <i class="fa-solid fa-arrow-right"></i></div>
            </a>

            <a href="/select-category?cat=Student%20Complain%20%26%20Cyberbullying" data-tilt data-tilt-max="15" class="neon-card bg-gradient-to-br from-blue-900/80 to-blue-950 border-2 border-blue-500/50 p-6 rounded-3xl shadow-2xl flex flex-col justify-between animate-fade-in-up" style="animation-delay: 0.2s;">
                <div>
                    <div class="w-12 h-12 bg-blue-600/30 text-blue-400 rounded-2xl flex items-center justify-center text-2xl mb-4 border border-blue-500/40"><i class="fa-solid fa-graduation-cap"></i></div>
                    <h4 class="text-lg font-black text-white mb-2">
                        <span class="lang-section active" data-lang="en">3. Student Complaint</span>
                        <span class="lang-section" data-lang="or">୩. ଛାତ୍ରଛାତ୍ରୀ ସମସ୍ୟା ଓ ସାଇବରବୁଲିଂ</span>
                    </h4>
                    <p class="text-xs text-gray-400">
                        <span class="lang-section active" data-lang="en">Cyberbullying, fake exam portals, social media blackmail & student safety.</span>
                        <span class="lang-section" data-lang="or">ଫେକ୍ ଏଜୁକେସନ୍ ପୋର୍ଟାଲ୍, ସାଇବରବୁଲିଂ ଏବଂ ଅନଲାଇନ୍ ବ୍ଲାକମେଲିଂ।</span>
                    </p>
                </div>
                <div class="mt-6 text-xs font-bold text-yellow-400 flex items-center gap-1"><span>File Complaint</span> <i class="fa-solid fa-arrow-right"></i></div>
            </a>

            <a href="/select-category?cat=Other%20Cyber%20Crime%20Incident" data-tilt data-tilt-max="15" class="neon-card bg-gradient-to-br from-amber-900/80 to-amber-950 border-2 border-amber-500/50 p-6 rounded-3xl shadow-2xl flex flex-col justify-between animate-fade-in-up" style="animation-delay: 0.3s;">
                <div>
                    <div class="w-12 h-12 bg-amber-600/30 text-amber-400 rounded-2xl flex items-center justify-center text-2xl mb-4 border border-amber-500/40"><i class="fa-solid fa-shield-virus"></i></div>
                    <h4 class="text-lg font-black text-white mb-2">
                        <span class="lang-section active" data-lang="en">4. Other Cyber Crime</span>
                        <span class="lang-section" data-lang="or">୪. ଅନ୍ୟାନ୍ୟ ସାଇବର ଅପରାଧ</span>
                    </h4>
                    <p class="text-xs text-gray-400">
                        <span class="lang-section active" data-lang="en">Ransomware, Hacking, Ransom threats, Digital Arrest & general reporting.</span>
                        <span class="lang-section" data-lang="or">ରାନ୍‌ସମୱେର୍, ହ୍ୟାକିଂ, ଡିଜିଟାଲ୍ ଆରେଷ୍ଟ୍ ଧମକ ଏବଂ ଅନ୍ୟାନ୍ୟ ଅପରାଧ।</span>
                    </p>
                </div>
                <div class="mt-6 text-xs font-bold text-yellow-400 flex items-center gap-1"><span>File Complaint</span> <i class="fa-solid fa-arrow-right"></i></div>
            </a>
        </div>
    </section>

    <!-- NEW 5-CARD IN A SINGLE ROW AUTOMATIC 2-SECOND IMAGE SLIDER GALLERY -->
    <section class="py-10 px-4 md:px-12 max-w-7xl mx-auto w-full space-y-6">
        <div class="text-center space-y-2">
            <span class="bg-red-600 text-white text-[10px] font-black px-4 py-1.5 rounded-full uppercase tracking-widest inline-block shadow-lg animate-pulse">
                📸 CYBER CRIME VISUAL AWARENESS CARDS
            </span>
            <h2 class="text-xl md:text-3xl font-black text-white tracking-tight">
                <span class="lang-section active" data-lang="en">Major Cyber Crime & Photo Abuse Categories</span>
                <span class="lang-section" data-lang="or">ପ୍ରମୁଖ ୧୫ ସାଇବର ଅପରାଧ ଓ ଫଟୋ ବ୍ଲାକମେଲ୍ ଶ୍ରେଣୀ</span>
            </h2>
        </div>

        <div class="grid grid-cols-1 sm:grid-cols-2 md:grid-cols-3 lg:grid-cols-5 gap-4">
            
            <div class="bg-gray-900 border-2 border-purple-500 rounded-3xl overflow-hidden shadow-2xl flex flex-col justify-between">
                <div class="p-3 bg-purple-950/80 border-b border-purple-800/60 text-center">
                    <h4 class="text-xs font-black text-purple-300 uppercase tracking-wider flex items-center justify-center gap-1">
                        <i class="fa-solid fa-venus-mars"></i> Sexual Photo Abuse
                    </h4>
                </div>
                <div class="relative w-full h-48 bg-gray-950 overflow-hidden auto-slider" id="slider-1">
                    <img src="https://images.unsplash.com/photo-1563986768609-322da13575f3?auto=format&fit=crop&w=500&q=80" alt="Photo Morphing" class="slide-img active-slide">
                    <img src="https://images.unsplash.com/photo-1618005182384-a83a8bd57fbe?auto=format&fit=crop&w=500&q=80" alt="Sextortion" class="slide-img">
                    <img src="https://images.unsplash.com/photo-1526374965328-7f61d4dc18c5?auto=format&fit=crop&w=500&q=80" alt="Fake Identity Abuse" class="slide-img">
                </div>
                <div class="p-2.5 bg-gray-900 text-center border-t border-purple-900/50">
                    <span class="text-[10px] font-extrabold text-yellow-400">2-Sec Auto Change 🔄</span>
                </div>
            </div>

            <div class="bg-gray-900 border-2 border-red-500 rounded-3xl overflow-hidden shadow-2xl flex flex-col justify-between">
                <div class="p-3 bg-red-950/80 border-b border-red-800/60 text-center">
                    <h4 class="text-xs font-black text-red-300 uppercase tracking-wider flex items-center justify-center gap-1">
                        <i class="fa-solid fa-credit-card"></i> UPI & Money Frauds
                    </h4>
                </div>
                <div class="relative w-full h-48 bg-gray-950 overflow-hidden auto-slider" id="slider-2">
                    <img src="https://images.unsplash.com/photo-1559526324-4b87b5e36e44?auto=format&fit=crop&w=500&q=80" alt="UPI QR Scam" class="slide-img active-slide">
                    <img src="https://images.unsplash.com/photo-1563013544-824ae1b704d3?auto=format&fit=crop&w=500&q=80" alt="Credit Card Fraud" class="slide-img">
                    <img src="https://images.unsplash.com/photo-1607604276583-eef5d076aa5f?auto=format&fit=crop&w=500&q=80" alt="Fake Loan Apps" class="slide-img">
                </div>
                <div class="p-2.5 bg-gray-900 text-center border-t border-red-900/50">
                    <span class="text-[10px] font-extrabold text-yellow-400">2-Sec Auto Change 🔄</span>
                </div>
            </div>

            <div class="bg-gray-900 border-2 border-blue-500 rounded-3xl overflow-hidden shadow-2xl flex flex-col justify-between">
                <div class="p-3 bg-blue-950/80 border-b border-blue-800/60 text-center">
                    <h4 class="text-xs font-black text-blue-300 uppercase tracking-wider flex items-center justify-center gap-1">
                        <i class="fa-solid fa-user-ninja"></i> Cyber Stalking
                    </h4>
                </div>
                <div class="relative w-full h-48 bg-gray-950 overflow-hidden auto-slider" id="slider-3">
                    <img src="https://images.unsplash.com/photo-1510511459019-5dee997d7db4?auto=format&fit=crop&w=500&q=80" alt="Cyber Stalking" class="slide-img active-slide">
                    <img src="https://images.unsplash.com/photo-1573164713714-d95e436ab8d6?auto=format&fit=crop&w=500&q=80" alt="Social Media Hacking" class="slide-img">
                    <img src="https://images.unsplash.com/photo-1508873696983-2df515122519?auto=format&fit=crop&w=500&q=80" alt="Cyberbullying" class="slide-img">
                </div>
                <div class="p-2.5 bg-gray-900 text-center border-t border-blue-900/50">
                    <span class="text-[10px] font-extrabold text-yellow-400">2-Sec Auto Change 🔄</span>
                </div>
            </div>

            <div class="bg-gray-900 border-2 border-emerald-500 rounded-3xl overflow-hidden shadow-2xl flex flex-col justify-between">
                <div class="p-3 bg-emerald-950/80 border-b border-emerald-800/60 text-center">
                    <h4 class="text-xs font-black text-emerald-300 uppercase tracking-wider flex items-center justify-center gap-1">
                        <i class="fa-solid fa-bug"></i> Malware & Phishing
                    </h4>
                </div>
                <div class="relative w-full h-48 bg-gray-950 overflow-hidden auto-slider" id="slider-4">
                    <img src="https://images.unsplash.com/photo-1550751827-4bd374c3f58b?auto=format&fit=crop&w=500&q=80" alt="Phishing Attack" class="slide-img active-slide">
                    <img src="https://images.unsplash.com/photo-1563206767-5b18f218e8de?auto=format&fit=crop&w=500&q=80" alt="Ransomware Virus" class="slide-img">
                    <img src="https://images.unsplash.com/photo-1526374965328-7f61d4dc18c5?auto=format&fit=crop&w=500&q=80" alt="APK Malware" class="slide-img">
                </div>
                <div class="p-2.5 bg-gray-900 text-center border-t border-emerald-900/50">
                    <span class="text-[10px] font-extrabold text-yellow-400">2-Sec Auto Change 🔄</span>
                </div>
            </div>

            <div class="bg-gray-900 border-2 border-amber-500 rounded-3xl overflow-hidden shadow-2xl flex flex-col justify-between">
                <div class="p-3 bg-amber-950/80 border-b border-amber-800/60 text-center">
                    <h4 class="text-xs font-black text-amber-300 uppercase tracking-wider flex items-center justify-center gap-1">
                        <i class="fa-solid fa-handcuffs"></i> Digital Arrest & Fake Jobs
                    </h4>
                </div>
                <div class="relative w-full h-48 bg-gray-950 overflow-hidden auto-slider" id="slider-5">
                    <img src="https://images.unsplash.com/photo-1589829545856-d10d557cf95f?auto=format&fit=crop&w=500&q=80" alt="Digital Arrest Call" class="slide-img active-slide">
                    <img src="https://images.unsplash.com/photo-1521791136064-7986c2920216?auto=format&fit=crop&w=500&q=80" alt="Fake Job Scam" class="slide-img">
                    <img src="https://images.unsplash.com/photo-1531482615713-2afd69097998?auto=format&fit=crop&w=500&q=80" alt="Student Scholarship Scam" class="slide-img">
                </div>
                <div class="p-2.5 bg-gray-900 text-center border-t border-amber-900/50">
                    <span class="text-[10px] font-extrabold text-yellow-400">2-Sec Auto Change 🔄</span>
                </div>
            </div>

        </div>
    </section>

    <!-- COMPREHENSIVE CYBER ARTICLE SECTION -->
    <section class="py-8 px-4 md:px-12 max-w-7xl mx-auto w-full">
        <div class="bg-gray-900/90 border border-gray-800 p-6 md:p-10 rounded-3xl space-y-6 shadow-2xl text-xs md:text-sm leading-relaxed text-gray-300">
            <div class="lang-section active" data-lang="en">
                <h2 class="text-xl md:text-3xl font-black text-white mb-2 border-b border-gray-800 pb-3">
                    Understanding Cyber Crime: Causes, Types, and Complaint Procedure
                </h2>
                <p class="text-xs text-yellow-400 font-bold mb-4">Authored by Lead Developer: Sashikanta Mohanty (B.Tech IT, IIIT Bhubaneswar)</p>
                <div class="space-y-4">
                    <p><strong>1. Introduction to Cyber Crime in Modern India:</strong> Protecting digital identities and reporting incidents immediately to CyberShield or 1930 is vital in countering financial fraud and harassment.</p>
                    <p><strong>2. Mechanisms & Safeguards:</strong> Cyber fraudsters exploit phishing links and digital arrest tactics. Users must register official complaints along with active GPS location tags for quick nodal response.</p>
                </div>
            </div>
            <div class="lang-section" data-lang="or">
                <h2 class="text-xl md:text-3xl font-black text-white mb-2 border-b border-gray-800 pb-3">
                    ସାଇବର ଅପରାଧ ବୁଝନ୍ତୁ: କାରଣ, ପ୍ରକାର ଏବଂ ଅଭିଯୋଗ ପ୍ରକ୍ରିୟା
                </h2>
                <p class="text-xs text-yellow-400 font-bold mb-4">ଲେଖକ: ଲିଡ୍ ଡେଭେଲପର୍ ଶଶିକାନ୍ତ ମହାନ୍ତି (B.Tech IT, IIIT Bhubaneswar)</p>
                <div class="space-y-4">
                    <p><strong>୧. ସାଇବର ଅପରାଧର ପରିଚୟ:</strong> ଅନଲାଇନ୍ ଠକେଇରୁ ବଞ୍ଚନ୍ତୁ ଏବଂ ତୁରନ୍ତ ୧୯୩୦ ରେ କଲ୍ କରନ୍ତୁ କିମ୍ବା CyberShield ରେ ଅଭିଯୋଗ ଦାଖଲ କରନ୍ତୁ।</p>
                </div>
            </div>
        </div>
    </section>

    <!-- USER FEEDBACK FORM -->
    <section class="py-8 px-4 md:px-12 max-w-7xl mx-auto w-full">
        <div class="bg-gradient-to-r from-blue-900/60 to-purple-900/60 border-2 border-blue-500/50 p-6 md:p-8 rounded-3xl shadow-2xl space-y-4">
            <div class="flex items-center gap-3">
                <div class="w-10 h-10 bg-yellow-400 text-blue-950 rounded-xl flex items-center justify-center text-xl font-black"><i class="fa-solid fa-comment-dots"></i></div>
                <div>
                    <h3 class="text-lg md:text-xl font-black text-white">Send Feedback to CyberShield Team</h3>
                    <p class="text-xs text-gray-300">Share your thoughts or suggest platform enhancements</p>
                </div>
            </div>

            {% if feedback_sent %}
            <div class="bg-emerald-500/20 border border-emerald-500 text-emerald-300 p-3 rounded-xl text-xs font-bold text-center">
                ✅ Thank you! Your feedback has been sent directly to Nodal Admins & Developer.
            </div>
            {% endif %}

            <form action="/submit-feedback" method="POST" class="grid grid-cols-1 md:grid-cols-3 gap-3 text-xs">
                <input type="text" name="name" required placeholder="Your Full Name" class="p-3 bg-gray-900 border border-gray-700 rounded-xl text-white outline-none">
                <input type="text" name="contact" required placeholder="Email or Phone Number" class="p-3 bg-gray-900 border border-gray-700 rounded-xl text-white outline-none">
                <div class="md:col-span-3 flex gap-2">
                    <input type="text" name="message" required placeholder="Write your feedback or query here..." class="w-full p-3 bg-gray-900 border border-gray-700 rounded-xl text-white outline-none">
                    <button type="submit" class="bg-yellow-400 hover:bg-yellow-500 text-blue-950 font-black px-6 py-3 rounded-xl transition shadow flex-shrink-0">
                        Submit Feedback
                    </button>
                </div>
            </form>
        </div>
    </section>

    <!-- LIVE OPERATIONAL STATS -->
    <section class="py-8 px-4 md:px-12 max-w-7xl mx-auto w-full">
        <h2 class="text-2xl md:text-3xl font-black text-center text-white mb-6">CyberShield Live Operational Stats</h2>
        <div class="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-6">
            <div class="bg-blue-950/80 border border-blue-800/80 p-6 rounded-3xl flex justify-between items-center shadow-2xl">
                <div>
                    <span class="text-[11px] font-black uppercase text-blue-400 block mb-2">COMPLAINTS REGISTERED</span>
                    <span class="text-4xl font-black text-white">{{ stats.total }}</span>
                </div>
                <i class="fa-solid fa-folder-open text-blue-400 text-3xl"></i>
            </div>
            <div class="bg-emerald-950/80 border border-emerald-800/80 p-6 rounded-3xl flex justify-between items-center shadow-2xl">
                <div>
                    <span class="text-[11px] font-black uppercase text-emerald-400 block mb-2">REPORT RESOLVED</span>
                    <span class="text-4xl font-black text-white">{{ stats.resolved }}</span>
                </div>
                <i class="fa-solid fa-circle-check text-emerald-400 text-3xl"></i>
            </div>
            <div class="bg-amber-950/80 border border-amber-800/80 p-6 rounded-3xl flex justify-between items-center shadow-2xl">
                <div>
                    <span class="text-[11px] font-black uppercase text-amber-400 block mb-2">PENDING ACTIONS</span>
                    <span class="text-4xl font-black text-white">{{ stats.pending }}</span>
                </div>
                <i class="fa-solid fa-clock-rotate-left text-amber-400 text-3xl"></i>
            </div>
            <div class="bg-purple-950/80 border border-purple-800/80 p-6 rounded-3xl flex justify-between items-center shadow-2xl">
                <div>
                    <span class="text-[11px] font-black uppercase text-purple-400 block mb-2">AVG RESPONSE TIME</span>
                    <span class="text-3xl font-black text-yellow-300">{{ stats.avg_response }}</span>
                </div>
                <i class="fa-solid fa-bolt text-yellow-300 text-3xl"></i>
            </div>
        </div>
    </section>

    <!-- FREQUENTLY ASKED QUESTIONS (FAQ) SECTION (Limited to 5 initially with Show More) -->
    <section class="py-10 px-4 md:px-12 max-w-7xl mx-auto w-full space-y-6">
        <div class="text-center space-y-2">
            <span class="bg-yellow-400 text-blue-950 text-[10px] font-black px-3 py-1 rounded-full uppercase tracking-wider inline-block">
                ❓ FREQUENTLY ASKED QUESTIONS
            </span>
            <h2 class="text-2xl md:text-4xl font-black text-white tracking-tight">
                <span class="lang-section active" data-lang="en">Cyber Security & Portal FAQ Knowledge Base</span>
                <span class="lang-section" data-lang="or">ସାଇବର ସୁରକ୍ଷା ଏବଂ ପୋର୍ଟାଲ୍ ସମ୍ବନ୍ଧୀୟ ପ୍ରଶ୍ନୋତ୍ତର (FAQ)</span>
            </h2>
            <p class="text-xs text-gray-400">
                <span class="lang-section active" data-lang="en">Comprehensive guide covering Cyber Crime, Laws, Portals, and Financial Safety</span>
                <span class="lang-section" data-lang="or">ସାଇବର ଅପରାଧ, ଆଇନ୍, ପୋର୍ଟାଲ୍ ଏବଂ ଆର୍ଥିକ ସୁରକ୍ଷା ବିଷୟରେ ସମ୍ପୂର୍ଣ୍ଣ ସୂଚନା</span>
            </p>
        </div>

        <div class="bg-gray-900/90 border-2 border-yellow-400/70 p-6 md:p-8 rounded-3xl shadow-2xl space-y-6">

            <div class="space-y-3" id="faq-container">
                <!-- FAQ 1 -->
                <details class="group bg-gray-950 p-4 rounded-2xl border border-gray-800 text-xs cursor-pointer faq-item">
                    <summary class="font-bold text-gray-200 flex justify-between items-center list-none">
                        <span><span class="lang-section active" data-lang="en">1. What is Cyber Crime?</span><span class="lang-section" data-lang="or">୧. ସାଇବର ଅପରାଧ କ'ଣ?</span></span>
                        <span class="transition group-open:rotate-180 text-yellow-400">▼</span>
                    </summary>
                    <div class="mt-3 text-gray-400 pt-2 border-t border-gray-900 leading-relaxed">
                        <span class="lang-section active" data-lang="en">Any illegal act carried out using computers, smartphones, or the internet.</span>
                        <span class="lang-section" data-lang="or">କମ୍ପ୍ୟୁଟର୍, ସ୍ମାର୍ଟଫୋନ୍ କିମ୍ବା ଇଣ୍ଟରନେଟ୍ ବ୍ୟବହାର କରି କରାଯାଉଥିବା ଯେକୌଣସି ବେଆଇନ କାର୍ଯ୍ୟ।</span>
                    </div>
                </details>

                <!-- FAQ 2 -->
                <details class="group bg-gray-950 p-4 rounded-2xl border border-gray-800 text-xs cursor-pointer faq-item">
                    <summary class="font-bold text-gray-200 flex justify-between items-center list-none">
                        <span><span class="lang-section active" data-lang="en">2. What is the 1930 Helpline?</span><span class="lang-section" data-lang="or">୨. ୧୯୩୦ ହେଲ୍ପଲାଇନ୍ କ'ଣ?</span></span>
                        <span class="transition group-open:rotate-180 text-yellow-400">▼</span>
                    </summary>
                    <div class="mt-3 text-gray-400 pt-2 border-t border-gray-900 leading-relaxed">
                        <span class="lang-section active" data-lang="en">Official 24x7 National Cyber Crime Helpline for immediate financial fraud reporting.</span>
                        <span class="lang-section" data-lang="or">ଆର୍ଥିକ ଠକେଇର ତୁରନ୍ତ ରିପୋର୍ଟ ପାଇଁ ୨୪x୭ ଜାତୀୟ ସାଇବର ହେଲ୍ପଲାଇନ୍ ନମ୍ବର।</span>
                    </div>
                </details>

                <!-- FAQ 3 -->
                <details class="group bg-gray-950 p-4 rounded-2xl border border-gray-800 text-xs cursor-pointer faq-item">
                    <summary class="font-bold text-gray-200 flex justify-between items-center list-none">
                        <span><span class="lang-section active" data-lang="en">3. What is the "Golden Hour" in Cyber Crime?</span><span class="lang-section" data-lang="or">୩. ଗୋଲ୍ଡେନ୍ ଆୱାର୍ (Golden Hour) କ'ଣ?</span></span>
                        <span class="transition group-open:rotate-180 text-yellow-400">▼</span>
                    </summary>
                    <div class="mt-3 text-gray-400 pt-2 border-t border-gray-900 leading-relaxed">
                        <span class="lang-section active" data-lang="en">The first 1-2 hours after financial fraud, where money recovery chances are highest.</span>
                        <span class="lang-section" data-lang="or">ଠକେଇର ପ୍ରଥମ ୧-୨ ଘଣ୍ଟା, ଯେଉଁଥିରେ ଟଙ୍କା ଫେରସ୍ତ ମିଳିବାର ସମ୍ଭାବନା ସବୁଠାରୁ ଅଧିକ ଥାଏ।</span>
                    </div>
                </details>

                <!-- FAQ 4 -->
                <details class="group bg-gray-950 p-4 rounded-2xl border border-gray-800 text-xs cursor-pointer faq-item">
                    <summary class="font-bold text-gray-200 flex justify-between items-center list-none">
                        <span><span class="lang-section active" data-lang="en">4. What is Digital Arrest Scam?</span><span class="lang-section" data-lang="or">୪. ଡିଜିଟାଲ୍ ଆରେଷ୍ଟ୍ ସ୍କାମ୍ କ'ଣ?</span></span>
                        <span class="transition group-open:rotate-180 text-yellow-400">▼</span>
                    </summary>
                    <div class="mt-3 text-gray-400 pt-2 border-t border-gray-900 leading-relaxed">
                        <span class="lang-section active" data-lang="en">Fraudsters posing as CBI/Police over video calls to extort money. Agencies NEVER arrest online!</span>
                        <span class="lang-section" data-lang="or">ଠକମାନେ ପୋଲିସ/CBI ସାଜି ଭିଡିଓ କଲ୍‌ରେ ଟଙ୍କା ଆଦାୟ କରନ୍ତି। ପୋଲିସ କେବେବି ଅନଲାଇନ୍ ଗିରଫ କରେନାହିଁ!</span>
                    </div>
                </details>

                <!-- FAQ 5 -->
                <details class="group bg-gray-950 p-4 rounded-2xl border border-gray-800 text-xs cursor-pointer faq-item">
                    <summary class="font-bold text-gray-200 flex justify-between items-center list-none">
                        <span><span class="lang-section active" data-lang="en">5. What should I do immediately after losing money in UPI fraud?</span><span class="lang-section" data-lang="or">୫. ୟୁପିଆଇ ଠକେଇ ହେଲେ ପ୍ରଥମେ କ'ଣ କରିବି?</span></span>
                        <span class="transition group-open:rotate-180 text-yellow-400">▼</span>
                    </summary>
                    <div class="mt-3 text-gray-400 pt-2 border-t border-gray-900 leading-relaxed">
                        <span class="lang-section active" data-lang="en">Immediately call 1930, report on CyberShield, and freeze your bank debit card/UPI.</span>
                        <span class="lang-section" data-lang="or">ତୁରନ୍ତ ୧୯୩୦ କୁ କଲ୍ କରନ୍ତୁ, CyberShield ରେ ରିପୋର୍ଟ କରନ୍ତୁ ଏବଂ ବ୍ୟାଙ୍କ କାର୍ଡ/UPI ବ୍ଲକ୍ କରନ୍ତୁ।</span>
                    </div>
                </details>

                <!-- FAQ 6 -->
                <details class="group bg-gray-950 p-4 rounded-2xl border border-gray-800 text-xs cursor-pointer faq-item faq-hidden">
                    <summary class="font-bold text-gray-200 flex justify-between items-center list-none">
                        <span><span class="lang-section active" data-lang="en">6. Can anyone deduct money if I scan a QR code to receive money?</span><span class="lang-section" data-lang="or">୬. QR Code ସ୍କାନ୍ କଲେ ଟଙ୍କା କଟିପାରେ କି?</span></span>
                        <span class="transition group-open:rotate-180 text-yellow-400">▼</span>
                    </summary>
                    <div class="mt-3 text-gray-400 pt-2 border-t border-gray-900 leading-relaxed">
                        <span class="lang-section active" data-lang="en">YES! Scanning a QR code and entering PIN is ONLY for SENDING money, never receiving.</span>
                        <span class="lang-section" data-lang="or">ହଁ! QR code ସ୍କାନ୍ କରି PIN ଦେଲେ ଟଙ୍କା କଟେ, ମିଳେନାହିଁ।</span>
                    </div>
                </details>

                <!-- FAQ 7 -->
                <details class="group bg-gray-950 p-4 rounded-2xl border border-gray-800 text-xs cursor-pointer faq-item faq-hidden">
                    <summary class="font-bold text-gray-200 flex justify-between items-center list-none">
                        <span><span class="lang-section active" data-lang="en">7. Is sharing OTP safe with bank executives?</span><span class="lang-section" data-lang="or">୭. ବ୍ୟାଙ୍କ କର୍ମଚାରୀଙ୍କୁ OTP ଦେବା ସୁରକ୍ଷିତ କି?</span></span>
                        <span class="transition group-open:rotate-180 text-yellow-400">▼</span>
                    </summary>
                    <div class="mt-3 text-gray-400 pt-2 border-t border-gray-900 leading-relaxed">
                        <span class="lang-section active" data-lang="en">NO! Never share OTP, UPI PIN, or Password with ANYONE.</span>
                        <span class="lang-section" data-lang="or">ନା! କାହା ସହିତ ବି OTP, UPI PIN କିମ୍ବା Password ସେୟାର୍ କରନ୍ତୁ ନାହିଁ।</span>
                    </div>
                </details>

                <!-- FAQ 8 -->
                <details class="group bg-gray-950 p-4 rounded-2xl border border-gray-800 text-xs cursor-pointer faq-item faq-hidden">
                    <summary class="font-bold text-gray-200 flex justify-between items-center list-none">
                        <span><span class="lang-section active" data-lang="en">8. How to identify fake loan apps?</span><span class="lang-section" data-lang="or">୮. ଫେକ୍ ଲୋନ୍ ଆପ୍ କିପରି ଚିହ୍ନିବି?</span></span>
                        <span class="transition group-open:rotate-180 text-yellow-400">▼</span>
                    </summary>
                    <div class="mt-3 text-gray-400 pt-2 border-t border-gray-900 leading-relaxed">
                        <span class="lang-section active" data-lang="en">Fake apps demand high processing fees upfront and access personal photos/contacts.</span>
                        <span class="lang-section" data-lang="or">ଫେକ୍ ଆପ୍ ଗୁଡ଼ିକ ଆଗୁଆ ଟଙ୍କା ମାଗନ୍ତି ଏବଂ ଫୋନ୍ ଗ୍ୟାଲେରୀ/କଣ୍ଟାକ୍ଟ୍ସ ଆକ୍ସେସ୍ ନିଅନ୍ତି।</span>
                    </div>
                </details>

                <!-- FAQ 9 -->
                <details class="group bg-gray-950 p-4 rounded-2xl border border-gray-800 text-xs cursor-pointer faq-item faq-hidden">
                    <summary class="font-bold text-gray-200 flex justify-between items-center list-none">
                        <span><span class="lang-section active" data-lang="en">9. What is Part-time Job/Telegram Scam?</span><span class="lang-section" data-lang="or">୯. ଟେଲିଗ୍ରାମ୍ ପାର୍ଟ-ଟାଇମ୍ ଜବ୍ ସ୍କାମ୍ କ'ଣ?</span></span>
                        <span class="transition group-open:rotate-180 text-yellow-400">▼</span>
                    </summary>
                    <div class="mt-3 text-gray-400 pt-2 border-t border-gray-900 leading-relaxed">
                        <span class="lang-section active" data-lang="en">Fraudsters promise high daily returns for YouTube likes/ratings and steal funds.</span>
                        <span class="lang-section" data-lang="or">ୟୁଟ୍ୟୁବ୍ ଲାଇକ୍/ରେଟିଂ ବଦଳରେ ଅଧିକ ଟଙ୍କାର ପ୍ରଲୋଭନ ଦେଖାଇ ଠକେଇ କରାଯାଏ।</span>
                    </div>
                </details>

                <!-- FAQ 10 -->
                <details class="group bg-gray-950 p-4 rounded-2xl border border-gray-800 text-xs cursor-pointer faq-item faq-hidden">
                    <summary class="font-bold text-gray-200 flex justify-between items-center list-none">
                        <span><span class="lang-section active" data-lang="en">10. What is Morphing?</span><span class="lang-section" data-lang="or">୧୦. ମର୍ଫିଂ (Morphing) କ'ଣ?</span></span>
                        <span class="transition group-open:rotate-180 text-yellow-400">▼</span>
                    </summary>
                    <div class="mt-3 text-gray-400 pt-2 border-t border-gray-900 leading-relaxed">
                        <span class="lang-section active" data-lang="en">Editing someone's photo illegally onto explicit images/videos to blackmail.</span>
                        <span class="lang-section" data-lang="or">କାହାର ଫଟୋକୁ ବେଆଇନ ଭାବେ ଅଶ୍ଳୀଳ ଫଟୋ/ଭିଡିଓରେ ସମ୍ପାଦନା କରି ବ୍ଲାକମେଲ୍ କରିବା।</span>
                    </div>
                </details>
            </div>

            <!-- Show More Button -->
            <div class="text-center pt-4">
                <button id="load-more-btn" onclick="toggleMoreFaqs()" class="bg-yellow-400 hover:bg-yellow-300 text-blue-950 font-black px-6 py-2.5 rounded-xl shadow-lg transition transform hover:scale-105 text-xs uppercase tracking-wider">
                    <span class="lang-section active" data-lang="en">⬇️ Show More FAQs (+5 More)</span>
                    <span class="lang-section" data-lang="or">⬇️ ଅଧିକ ପ୍ରଶ୍ନ ଦେଖନ୍ତୁ (+୫ଟି ଅଧିକ)</span>
                </button>
            </div>

        </div>
    </section>

    <!-- Public district totals only; no citizen details -->
    <section class="mx-auto my-8 w-full max-w-7xl px-4 md:px-6" aria-labelledby="district-report-title"><div class="rounded-3xl border border-cyan-500/30 bg-slate-900/80 p-5 shadow-xl md:p-8"><div class="mb-5 flex flex-wrap items-end justify-between gap-3"><div><p class="text-xs font-black uppercase tracking-[.2em] text-cyan-300">Odisha overview</p><h3 id="district-report-title" class="mt-1 text-2xl font-black text-white">District-wise cyber reports</h3><p class="mt-1 text-sm text-slate-300">Aggregated reports registered in this demo portal.</p></div><span class="rounded-xl border border-amber-400/40 bg-amber-400/10 px-3 py-2 text-xs font-bold text-amber-200">Counts only · no personal details</span></div><div id="district-report-grid" class="grid grid-cols-2 gap-2 sm:grid-cols-3 md:grid-cols-4 lg:grid-cols-5">{% for item in district_counts %}<div class="district-report-card flex items-center justify-between gap-2 rounded-xl border border-slate-700 bg-slate-950/70 px-3 py-2.5" data-district="{{ item.district }}" data-count="{{ item.count }}"><span class="text-xs font-semibold text-slate-200">{{ item.district }}</span><span class="min-w-8 rounded-lg bg-cyan-500/15 px-2 py-1 text-center text-xs font-black text-cyan-200">{{ item.count }}</span></div>{% endfor %}</div><p class="mt-4 text-[11px] text-slate-400">These are local demo submissions, not official police or government statistics. For real cybercrime reporting, use cybercrime.gov.in or call 1930 for financial fraud.</p></div></section>

    <!-- CyberShield assistant: local help plus optional server-side Gemini AI -->
    <section id="cybershield-chat" class="mx-auto my-8 w-full max-w-7xl px-4 md:px-6" aria-labelledby="chat-title">
        <div class="overflow-hidden rounded-3xl border border-violet-400/40 bg-slate-900 shadow-2xl">
            <div class="border-b border-slate-700 bg-gradient-to-r from-violet-950 to-cyan-950 p-5 md:p-7">
                <p class="text-xs font-black uppercase tracking-[.2em] text-cyan-200">CyberShield Assistant</p>
                <h3 id="chat-title" class="mt-1 text-2xl font-black text-white">Ask me anything</h3>
                <p class="mt-2 text-sm text-slate-300">Ask in English, Odia, or Romanized Odia. General questions use AI when a server-side Gemini API key is configured.</p>
            </div>
            <div id="chat-messages" class="max-h-80 min-h-40 space-y-3 overflow-y-auto p-4 md:p-6" aria-live="polite" aria-label="Chat messages">
                <div class="max-w-3xl rounded-2xl rounded-tl-sm border border-cyan-700/50 bg-slate-950 p-4 text-sm text-slate-100">Namaskar! I can help explain this demo portal and basic cyber-safety steps. Ask a question below. / ନମସ୍କାର! ଏହି ଡେମୋ ପୋର୍ଟାଲ୍ ଓ ସାଇବର ସୁରକ୍ଷା ବିଷୟରେ ପଚାରନ୍ତୁ।</div>
            </div>
            <form id="chat-form" class="flex flex-col gap-2 border-t border-slate-700 p-4 sm:flex-row md:p-6">
                <label class="sr-only" for="chat-question">Your question</label>
                <input id="chat-question" name="question" maxlength="500" required autocomplete="off" placeholder="Type in English, Odia, or Romanized Odia…" class="min-w-0 flex-1 rounded-xl border border-slate-600 bg-slate-950 px-4 py-3 text-sm text-white outline-none focus:border-cyan-400">
                <button type="submit" class="rounded-xl bg-cyan-600 px-6 py-3 text-sm font-black text-white hover:bg-cyan-500">Ask / ପଚାରନ୍ତୁ</button>
            </form>
            <p class="px-4 pb-5 text-[11px] leading-relaxed text-amber-200 md:px-6">AI answers can be wrong or out of date. When AI is enabled, your question is sent to Google Gemini through this server; do not enter passwords, OTPs, UPI PINs, or private complaint details. For financial cyber fraud, call 1930 promptly; this demo does not file an official report.</p>
        </div>
    </section>
    <script>
    (function () {
        const form = document.getElementById('chat-form');
        const input = document.getElementById('chat-question');
        const messages = document.getElementById('chat-messages');
        if (!form || !input || !messages) return;
        const districtAliases = {
            'Angul':['angul','anugul','ଅନୁଗୁଳ'], 'Balangir':['balangir','bolangir','ବଲାଙ୍ଗୀର'],
            'Balasore':['balasore','baleswar','ବାଲେଶ୍ୱର'], 'Bargarh':['bargarh','ବରଗଡ଼'],
            'Bhadrak':['bhadrak','ଭଦ୍ରକ'], 'Boudh':['boudh','ବୌଦ୍ଧ'], 'Cuttack':['cuttack','କଟକ'],
            'Deogarh':['deogarh','ଦେବଗଡ଼'], 'Dhenkanal':['dhenkanal','ଢେଙ୍କାନାଳ'],
            'Gajapati':['gajapati','ଗଜପତି'], 'Ganjam':['ganjam','ଗଞ୍ଜାମ'],
            'Jagatsinghpur':['jagatsinghpur','ଜଗତସିଂହପୁର'], 'Jajpur':['jajpur','ଯାଜପୁର'],
            'Jharsuguda':['jharsuguda','ଝାରସୁଗୁଡ଼ା'], 'Kalahandi':['kalahandi','କଳାହାଣ୍ଡି'],
            'Kandhamal':['kandhamal','କନ୍ଧମାଳ'], 'Kendrapara':['kendrapara','କେନ୍ଦ୍ରାପଡ଼ା'],
            'Kendujhar':['kendujhar','keonjhar','କେନ୍ଦୁଝର'], 'Khordha':['khordha','khurda','ଖୋର୍ଦ୍ଧା'],
            'Koraput':['koraput','କୋରାପୁଟ'], 'Malkangiri':['malkangiri','ମାଲକାନଗିରି'],
            'Mayurbhanj':['mayurbhanj','ମୟୂରଭଞ୍ଜ'], 'Nabarangpur':['nabarangpur','ନବରଙ୍ଗପୁର'],
            'Nayagarh':['nayagarh','ନୟାଗଡ଼'], 'Nuapada':['nuapada','ନୂଆପଡ଼ା'],
            'Puri':['puri','ପୁରୀ'], 'Rayagada':['rayagada','ରାୟଗଡ଼ା'],
            'Sambalpur':['sambalpur','ସମ୍ବଲପୁର'], 'Subarnapur':['subarnapur','sonepur','ସୁବର୍ଣ୍ଣପୁର'],
            'Sundargarh':['sundargarh','ସୁନ୍ଦରଗଡ଼']
        };
        function replyFor(question) {
            const q = question.toLowerCase();
            const romanOdia = / (bhai|mote|mo|mu|kana|kahinki|kemiti|karibi|pariba|heichi|heba|hele|nahi|nahin|thik|deba|dekhauchi|kete|kahiba|achhi|achi|kn|ki|au|jaha|sabu|kouthi) /.test(' ' + q.replace(/[^a-z0-9]+/g, ' ') + ' ');
            const odia = romanOdia || Array.from(question).some(ch => { const cp = ch.codePointAt(0); return cp >= 0x0b00 && cp <= 0x0b7f; });
            const say = (en, or) => odia ? or : en;
            const asksDistrictCount = /count|complaint number|complaints|reports|district wise|district count|zilla wise|jilla|kete|number kete|ଅଭିଯୋଗ|ସଂଖ୍ୟା/.test(q);
            const district = asksDistrictCount ? Object.entries(districtAliases).find(([, aliases]) => aliases.some(a => q.includes(a.toLowerCase()))) : null;
            if (district) {
                const card = [...document.querySelectorAll('.district-report-card')].find(el => el.dataset.district === district[0]);
                if (!card) return say(`${district[0]} has no complaint entry in the current public district summary.`, `ବର୍ତ୍ତମାନର public district summaryରେ ${district[0]} ପାଇଁ ଅଭିଯୋଗ ଦେଖାଯାଇନାହିଁ।`);
                const count = card.dataset.count || '0';
                return say(`${district[0]} shows ${count} demo complaint(s) in the public summary. This is this portal's own demo data, not an official statistic.`, `${district[0]} ପାଇଁ public summaryରେ ${count}ଟି demo ଅଭିଯୋଗ ଦେଖାଯାଉଛି। ଏହା ଏହି portalର demo ତଥ୍ୟ; ସରକାରୀ ଆକଳନ ନୁହେଁ।`);
            }
            if (/bot|chatbot|anything|everything|sabu pachar|jaha bi|jaha pachar|puchibi|puchile|pacharibi|pacharile|sabu prashna|all question|any question|answer debe/.test(q)) return say('I am a local demo assistant, not a full generative AI. I can answer common questions about this portal, cyber scams, account safety, URL/UPI/QR, GPS, and public district demo counts. I do not send your chat to an AI service.', 'Mu local demo assistant, full generative AI nuhen. Ehi portal, cyber scam, account safety, URL/UPI/QR, GPS ebam public district demo count bisayare sadharana prashnara uttara deiparibi. Chat AI service ku patha jae nahi.');
            if (/phish|fake email|fake sms|suspicious message|social engineering|ଫିସିଂ/.test(q)) return say('Phishing is a fake message or website that tries to steal passwords, OTPs, or payment details. Do not click its links; open the official app/site yourself and report the message to the platform.', 'Phishing hela nakali message ba website dwara password, OTP ba payment details chori karibaku chesta. Link click karantu nahi; official app/site nije kholantu ebam platform ku message report karantu.');
            if (/hack|hacked|account chori|account neigala|account access|ଖାତା ହ୍ୟାକ/.test(q)) return say('If an account may be hacked, use the service’s official recovery page, change its password from a trusted device, enable two-step verification, sign out other sessions, and contact the provider. Never share a recovery code.', 'Account hack heithile official recovery page byabahara kari trusted device ru password badalantu, two-step verification on karantu, anya session sign out karantu ebam provider ku contact karantu. Recovery code kahaku diantu nahi.');
            if (/gps|location|address|bhadrak|bbsr|bhu?baneswar|ସ୍ଥାନ|ଠିକଣା/.test(q)) return say('Browser GPS is an estimate. Check the accuracy in metres, compare the map pin with your real place, and drag the pin or edit the address if needed. This portal cannot guarantee an exact street address.', 'Browser GPS eka estimate. Accuracy metre re dekhantu, map pin nijara sathik jagah saha milantu; darkar hele pin drag ba address edit karantu. Portal exact street address guarantee karipariba nahi.');
            if (/official|government|police|cybercrime.gov|sarkari|ସରକାରୀ|ପୋଲିସ/.test(q)) return say('CyberShield is a demo portal, not an official government or police service. For official cybercrime reporting, use cybercrime.gov.in; for financial fraud call 1930 immediately.', 'CyberShield eka demo portal, sarkari ba police service nuhen. Official cybercrime report pain cybercrime.gov.in byabahara karantu; financial fraud hele turanta 1930 ku call karantu.');
            if (/district wise|district count|zilla wise|jilla|ଜିଲ୍ଲା/.test(q)) return say('The district section shows only districts with demo complaints. Ask with a district name, for example “Bhadrak count”, to see its current number. These are not official statistics.', 'District section re kebala demo complaint thiba district dekhajae. District name saha pacharantu, jemiti “Bhadrak kete”; eha official statistic nuhen.');
            if (/what is cyber|cyber crime|cyber safety|cyber surakhya|cyber surakhita/.test(q)) return say('Cyber safety means protecting your accounts, devices, identity, and money online. Use unique passwords and two-step verification; verify links and recipients; never share OTPs or UPI PINs.', 'Cyber safety mane online re account, device, identity ebam paisa surakhita rakhiba. Alaga password o two-step verification byabahara karantu; link/payee janchantu; OTP ba UPI PIN kahaku diantu nahi.');
            if (/login|log in|register|registration|password reset|ପଞ୍ଜୀକରଣ|ଲଗଇନ/.test(q)) return say('For this demo, register or sign in from the home page. Complete your citizen profile before opening the complaint form. Use a password you do not use on another service.', 'Ehi demo pain home page ru register ba sign in karantu. Complaint form purbaru citizen profile pura karantu. Anya service re byabahara karuthiba password ethare diantu nahi.');
            if (/1930|money|money lost|payment fraud|financial fraud|ଟଙ୍କା|ଠକେଇ|ଠକି|fraud/.test(q)) return say('If money was taken, call 1930 immediately and contact your bank/payment app through its official channel. Preserve transaction details. This demo does not submit an official report.', 'ଟଙ୍କା ଠକେଇ ହୋଇଥିଲେ ତୁରନ୍ତ ୧୯୩୦କୁ କଲ୍ କରନ୍ତୁ ଏବଂ bank/payment appକୁ official channelରେ ଜଣାନ୍ତୁ। Transaction details ସୁରକ୍ଷିତ ରଖନ୍ତୁ। ଏହି demo official report ଦାଖଲ କରେନି।');
            if (/upi|pin|ପିନ୍|qr|କ୍ୟୁଆର/.test(q)) return say('A UPI/QR format check cannot verify the payee or prove a QR is safe. Verify the recipient name inside your payment app. Never share your UPI PIN or OTP.', 'UPI/QR format check ଦ୍ୱାରା payeeର ପରିଚୟ କିମ୍ବା QR ସୁରକ୍ଷିତ ବୋଲି ପ୍ରମାଣ ହୁଏନି। Payment appରେ recipient name ଯାଞ୍ଚ କରନ୍ତୁ। UPI PIN କିମ୍ବା OTP କାହାକୁ କହନ୍ତୁନି।');
            if (/url|link|website|ଲିଙ୍କ|ୱେବସାଇଟ|scan|scanner/.test(q)) return say('The URL checker looks for local warning clues only; it does not query a live threat database. A low score does not prove a site is safe. Do not open unexpected links or enter passwords/OTPs.', 'URL checker କେବଳ ସ୍ଥାନୀୟ warning clue ଯାଞ୍ଚ କରେ; live threat database ନୁହେଁ। କମ୍ score ମାନେ site ସୁରକ୍ଷିତ ବୋଲି ପ୍ରମାଣ ନୁହେଁ। ଅଜଣା link ଖୋଲନ୍ତୁନି କିମ୍ବା password/OTP ଦିଅନ୍ତୁନି।');
            if (/complaint|complain|report|ଅଭିଯୋଗ|ଦାଖଲ/.test(q)) return say('To use the demo complaint form, register or sign in, complete your citizen profile, then fill and submit the complaint form. It is not an official police/cybercrime filing channel.', 'Demo complaint form ପାଇଁ register କିମ୍ବା sign in କରନ୍ତୁ, citizen profile ପୂରଣ କରି complaint form submit କରନ୍ତୁ। ଏହା ସରକାରୀ police/cybercrime filing channel ନୁହେଁ।');
            if (/status|case id|ସ୍ଥିତି/.test(q)) return say('Use the complaint-status option on the home page and enter your complaint/case ID. Do not share the ID or personal details in this public chat.', 'Home pageର complaint-status option ବ୍ୟବହାର କରି complaint/case ID ଦିଅନ୍ତୁ। ଏହି public chatରେ ID କିମ୍ବା ବ୍ୟକ୍ତିଗତ ତଥ୍ୟ ଲେଖନ୍ତୁନି।');
            if (/password|otp|ପାସୱାର୍ଡ/.test(q)) return say('Never share passwords or OTPs in chat. If you entered them on a suspicious page, change your password using the official app/site and contact the service provider.', 'Chatରେ password କିମ୍ବା OTP କେବେ ଦିଅନ୍ତୁନି। ସନ୍ଦେହଜନକ pageରେ ଦେଇଥିଲେ official app/siteରୁ password ବଦଳାନ୍ତୁ ଏବଂ service providerକୁ ଜଣାନ୍ତୁ।');
            if (/hello|hi|help|କେମିତି|କଣ|କ’ଣ|ନମସ୍କାର/.test(q)) return say('I can help with this portal, district demo counts, complaint steps, URL/UPI/QR safety, and emergency guidance. What would you like to know?', 'ଏହି portal, district demo count, complaint ପଦକ୍ଷେପ, URL/UPI/QR safety ଓ emergency ସହାୟତା ବିଷୟରେ ପଚାରନ୍ତୁ। କଣ ଜାଣିବାକୁ ଚାହୁଁଛନ୍ତି?');
            return say('General AI is not connected yet, so I can only answer the portal and cyber-safety topics listed above. Connect the server-side Gemini key to answer other questions. Please do not share personal or financial details here.', 'ସାଧାରଣ AI ଏଯାଏଁ ଯୋଡ଼ା ହୋଇନାହିଁ; ଏବେ ମୁଁ ଉପରେ ଥିବା portal ଓ cyber-safety ବିଷୟରେ ଉତ୍ତର ଦେଇପାରିବି। ଅନ୍ୟ ପ୍ରଶ୍ନ ପାଇଁ serverରେ Gemini key ଯୋଡ଼ନ୍ତୁ। ଏଠାରେ ବ୍ୟକ୍ତିଗତ କିମ୍ବା ଆର୍ଥିକ ତଥ୍ୟ ଲେଖନ୍ତୁନି।');
        }
        form.addEventListener('submit', async event => {
            event.preventDefault();
            const question = input.value.trim();
            if (!question) return;
            const user = document.createElement('div'); user.className='ml-auto max-w-3xl rounded-2xl rounded-tr-sm bg-violet-700 p-3 text-sm text-white'; user.textContent=question;
            const bot = document.createElement('div'); bot.className='max-w-3xl rounded-2xl rounded-tl-sm border border-cyan-700/50 bg-slate-950 p-4 text-sm text-slate-100';
            messages.append(user);
            bot.textContent='Thinking…';
            messages.append(bot);
            messages.scrollTop=messages.scrollHeight;
            input.value=''; input.disabled=true;
            try {
                const response = await fetch('/api/assistant', {method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({question})});
                const data = await response.json();
                if (response.ok && data.answer) bot.textContent=data.answer;
                else if (response.status === 503 && data.answer) bot.textContent=replyFor(question);
                else bot.textContent=replyFor(question);
            } catch (_) {
                bot.textContent=replyFor(question);
            } finally {
                input.disabled=false; input.focus(); messages.scrollTop=messages.scrollHeight;
            }
        });
    })();
    </script>

    <!-- DEVELOPER CARD -->
    <section class="py-10 px-4 md:px-12 max-w-7xl mx-auto w-full">
        <div class="bg-blue-950/60 border-2 border-blue-800/80 p-6 md:p-8 rounded-3xl flex flex-col md:flex-row justify-between items-center gap-6 shadow-2xl relative overflow-hidden">
            <div class="space-y-3">
                <span class="bg-yellow-400 text-blue-950 px-3 py-1 rounded-full text-[10px] font-black uppercase tracking-wider inline-block">
                    🎓 HACKATHON LEAD DEVELOPER
                </span>
                <h2 class="text-2xl md:text-4xl font-black text-white tracking-tight">SASHIKANTA MOHANTY</h2>
                <p class="text-xs md:text-sm text-yellow-300 font-bold">B.Tech Information Technology (1st Year) • IIIT Bhubaneswar</p>
                <p class="text-xs text-gray-400 font-medium"><i class="fa-solid fa-location-dot text-red-500 mr-1"></i> Bhadrak, Odisha</p>
            </div>
            
            <div class="flex flex-wrap items-center gap-3 w-full md:w-auto justify-start">
                <a href="mailto:sashikantamohanty797@gmail.com" class="bg-blue-600 hover:bg-blue-700 text-white font-bold px-4 py-2.5 rounded-xl text-xs flex items-center gap-2 shadow-lg transition transform hover:scale-105">
                    <i class="fa-solid fa-envelope"></i> Email Me
                </a>
                <a href="https://linkedin.com/in/sashikanta-mohanty" target="_blank" class="bg-blue-800 hover:bg-blue-900 text-white font-bold px-4 py-2.5 rounded-xl text-xs flex items-center gap-2 shadow-lg transition transform hover:scale-105">
                    <i class="fa-brands fa-linkedin"></i> LinkedIn
                </a>
                <a href="https://www.instagram.com/mdx_sashi_iiitb?obrf=OGljZzZ2aDNhNDdw" target="_blank" class="bg-gradient-to-r from-pink-500 via-red-500 to-yellow-500 hover:brightness-110 text-white font-bold px-4 py-2.5 rounded-xl text-xs flex items-center gap-2 shadow-lg transition transform hover:scale-105">
                    <i class="fa-brands fa-instagram"></i> Instagram
                </a>
            </div>
        </div>
    </section>

    <footer class="bg-gray-950 text-gray-300 py-10 px-4 md:px-12 border-t-2 border-gray-800 text-xs">
        <div class="max-w-7xl mx-auto grid grid-cols-1 md:grid-cols-3 gap-8 mb-8">
            <div class="space-y-3">
                <h4 class="text-sm font-black text-white uppercase tracking-wide border-b border-gray-700 pb-2">HELP &amp; SUPPORT</h4>
                <ul class="space-y-2 font-medium">
                    <li><a href="/register" class="hover:text-yellow-400 transition">Register a Complaint</a></li>
                    <li><a href="/track-status-login" class="hover:text-yellow-400 transition">Check Complaint Status</a></li>
                    <li><a href="mailto:admin.sashikantamohanty797@gmail.com" class="hover:text-yellow-400 transition">Contact Us &amp; Support</a></li>
                </ul>
            </div>
            <div class="space-y-3">
                <h4 class="text-sm font-black text-white uppercase tracking-wide border-b border-gray-700 pb-2">INFORMATION &amp; POLICIES</h4>
                <ul class="space-y-2 font-medium">
                    <li><a href="/disclaimer-page" class="hover:text-yellow-400 transition">Disclaimer</a></li>
                    <li><a href="/website-policies" class="hover:text-yellow-400 transition">Website Policies &amp; Terms</a></li>
                    <li><a href="/privacy-policy" class="hover:text-yellow-400 transition">Privacy Policy</a></li>
                </ul>
            </div>
            <div class="space-y-3">
                <h4 class="text-sm font-black text-white uppercase tracking-wide border-b border-gray-700 pb-2">CONTACT US - LEAD DEVELOPER</h4>
                <p class="font-black text-white text-sm"><i class="fa-solid fa-user text-yellow-400 mr-2"></i>Sashikanta Mohanty</p>
                <p class="text-gray-400">Father: Pradeep Kumar Mohanty | Mother: Arati Mohanty</p>
                <p class="text-gray-400"><i class="fa-solid fa-graduation-cap text-yellow-400 mr-2"></i>B.Tech 1st Year, IIIT Bhubaneswar (IT Branch)</p>
                <p class="text-gray-300"><i class="fa-solid fa-envelope text-yellow-400 mr-2"></i><a href="mailto:sashikantamohanty797@gmail.com" class="hover:text-yellow-400">sashikantamohanty797@gmail.com</a></p>
                <p class="text-gray-400"><i class="fa-solid fa-location-dot text-yellow-400 mr-2"></i>Odisha, Bhadrak - 756115</p>
            </div>
        </div>
        <div class="max-w-7xl mx-auto pt-6 border-t border-gray-800 flex flex-col md:flex-row justify-between items-center gap-4">
            <div class="flex flex-wrap items-center justify-center gap-3 text-base">
                <span class="text-white font-bold text-xs mr-2">Follow Us:</span>
                <a aria-label="Facebook" href="https://facebook.com" target="_blank" rel="noopener noreferrer" class="w-9 h-9 bg-blue-600 text-white rounded-lg flex items-center justify-center hover:scale-110 transition shadow"><i class="fa-brands fa-facebook-f"></i></a>
                <a aria-label="X" href="https://x.com" target="_blank" rel="noopener noreferrer" class="w-9 h-9 bg-black text-white rounded-lg flex items-center justify-center hover:scale-110 transition shadow border border-gray-700"><i class="fa-brands fa-x-twitter"></i></a>
                <a aria-label="YouTube" href="https://youtube.com" target="_blank" rel="noopener noreferrer" class="w-9 h-9 bg-red-600 text-white rounded-lg flex items-center justify-center hover:scale-110 transition shadow"><i class="fa-brands fa-youtube"></i></a>
                <a aria-label="LinkedIn" href="https://linkedin.com/in/sashikanta-mohanty" target="_blank" rel="noopener noreferrer" class="w-9 h-9 bg-blue-700 text-white rounded-lg flex items-center justify-center hover:scale-110 transition shadow"><i class="fa-brands fa-linkedin-in"></i></a>
                <a aria-label="Instagram" href="https://instagram.com/mdx_sashikanta_iiitbh" target="_blank" rel="noopener noreferrer" class="w-9 h-9 bg-pink-600 text-white rounded-lg flex items-center justify-center hover:scale-110 transition shadow"><i class="fa-brands fa-instagram"></i></a>
                <a aria-label="Telegram" href="https://telegram.org" target="_blank" rel="noopener noreferrer" class="w-9 h-9 bg-sky-500 text-white rounded-lg flex items-center justify-center hover:scale-110 transition shadow"><i class="fa-brands fa-telegram"></i></a>
                <a aria-label="WhatsApp" href="https://whatsapp.com" target="_blank" rel="noopener noreferrer" class="w-9 h-9 bg-emerald-600 text-white rounded-lg flex items-center justify-center hover:scale-110 transition shadow"><i class="fa-brands fa-whatsapp"></i></a>
            </div>
            <div class="text-center md:text-right text-gray-400">
                <p>© 2026 CyberShield Portal • Built with Python Flask &amp; Tailwind CSS by Sashikanta Mohanty (IIIT Bhubaneswar).</p>
            </div>
        </div>
    </footer>

    <script>
        function switchLang(lang) {
            document.querySelectorAll('.lang-section').forEach(el => {
                if(el.getAttribute('data-lang') === lang) { el.classList.add('active'); } else { el.classList.remove('active'); }
            });
            if(lang === 'en') {
                document.getElementById('btn-en').className = "bg-yellow-400 text-blue-950 font-black px-2.5 py-1 rounded-lg shadow transition transform hover:scale-105";
                document.getElementById('btn-or').className = "bg-gray-800 text-white font-bold px-2.5 py-1 rounded-lg hover:bg-gray-700 transition transform hover:scale-105";
            } else {
                document.getElementById('btn-or').className = "bg-yellow-400 text-blue-950 font-black px-2.5 py-1 rounded-lg shadow transition transform hover:scale-105";
                document.getElementById('btn-en').className = "bg-gray-800 text-white font-bold px-2.5 py-1 rounded-lg hover:bg-gray-700 transition transform hover:scale-105";
            }
        }

        function toggleMoreFaqs() {
            const hiddenFaqs = document.querySelectorAll('.faq-hidden');
            let shownCount = 0;
            hiddenFaqs.forEach((el, index) => {
                if (index < 5) {
                    el.classList.remove('faq-hidden');
                }
            });
            if (document.querySelectorAll('.faq-hidden').length === 0) {
                document.getElementById('load-more-btn').style.display = 'none';
            }
        }

        const canvas = document.getElementById('matrixCanvas');
        if (canvas) {
            const ctx = canvas.getContext('2d');
            function resizeCanvas() { canvas.width = canvas.parentElement.offsetWidth; canvas.height = canvas.parentElement.offsetHeight; }
            resizeCanvas();
            window.addEventListener('resize', resizeCanvas);
            const chars = '01ABCDEFGHIJKLMNOPQRSTUVWXYZ#$@&*-/\\<>[]{}';
            const fontSize = 14;
            let columns = Math.floor(canvas.width / fontSize);
            let drops = Array(columns).fill(1);
            function drawMatrix() {
                ctx.fillStyle = 'rgba(3, 7, 18, 0.08)'; ctx.fillRect(0, 0, canvas.width, canvas.height);
                ctx.fillStyle = '#3b82f6'; ctx.font = fontSize + 'px monospace';
                for (let i = 0; i < drops.length; i++) {
                    let text = chars.charAt(Math.floor(Math.random() * chars.length));
                    ctx.fillText(text, i * fontSize, drops[i] * fontSize);
                    if (drops[i] * fontSize > canvas.height && Math.random() > 0.975) { drops[i] = 0; }
                    drops[i]++;
                }
            }
            setInterval(drawMatrix, 50);
        }

        document.addEventListener("DOMContentLoaded", function() {
            const sliders = document.querySelectorAll('.auto-slider');
            sliders.forEach(slider => {
                const images = slider.querySelectorAll('.slide-img');
                let currentIndex = 0;
                setInterval(() => {
                    images[currentIndex].classList.remove('active-slide');
                    currentIndex = (currentIndex + 1) % images.length;
                    images[currentIndex].classList.add('active-slide');
                }, 2000);
            });
        });
    </script>
</body>
</html>
'''

# --- AUTO POLICE FIR DRAFT GENERATOR PAGES ---
FIR_GENERATOR_FORM_PAGE = '''
<!DOCTYPE html>
<html lang="or">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Auto Police FIR Draft Generator - CyberShield</title>
    <script src="https://cdn.tailwindcss.com"></script>
    <link href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css" rel="stylesheet">
    <style>
        .lang-or { display: block; }
        .lang-en { display: none; }
    </style>
</head>
<body class="bg-slate-950 text-gray-100 min-h-screen p-4 md:p-8 font-sans">
    <div class="max-w-4xl mx-auto space-y-6">
        
        <div class="flex flex-wrap justify-between items-center bg-gray-900 p-4 rounded-2xl border border-yellow-400/60 shadow-xl gap-3">
            <a href="/" class="bg-blue-600 hover:bg-blue-700 text-white px-4 py-2 rounded-xl text-xs font-bold transition flex items-center gap-2">
                <i class="fa-solid fa-house"></i> Home
            </a>
            <div class="text-center">
                <h1 class="text-lg md:text-xl font-black text-yellow-400 uppercase">📄 AUTO POLICE FIR DRAFT GENERATOR</h1>
                <p class="text-[10px] text-gray-300 font-bold">ଅଟୋମେଟିକ୍ ଆଇନଗତ FIR ଚିଠି / Legal Complaint Draft Generator</p>
            </div>
            <div class="flex gap-2 text-xs">
                <button onclick="toggleFIRLang('or')" id="btn-fir-or" class="bg-yellow-400 text-blue-950 font-black px-3 py-1 rounded-lg shadow">ଓଡ଼ିଆ</button>
                <button onclick="toggleFIRLang('en')" id="btn-fir-en" class="bg-gray-800 text-white font-bold px-3 py-1 rounded-lg">English</button>
            </div>
        </div>

        <div class="bg-gray-900 border-2 border-yellow-400 p-6 md:p-8 rounded-3xl shadow-2xl space-y-6">
            <form action="/generate-fir-pdf" method="POST" target="_blank" class="space-y-6 text-xs">
                
                <div class="bg-gray-950 p-5 rounded-2xl border border-gray-800 space-y-3">
                    <h2 class="text-sm font-black text-yellow-400 border-b border-gray-800 pb-2 uppercase flex items-center gap-2">
                        <i class="fa-solid fa-building-shield"></i> 
                        <span class="lang-or">୧. ଥାନା ଏବଂ ପୋଲିସ ଅଫିସରଙ୍କ ବିବରଣୀ (To Address)</span>
                        <span class="lang-en">1. Police Station & Officer Details (To Address)</span>
                    </h2>
                    <div class="grid grid-cols-1 md:grid-cols-2 gap-4">
                        <div>
                            <label class="block font-bold text-gray-300 mb-1">Designation / ପଦବୀ *</label>
                            <select name="officer_title" class="w-full p-3 bg-gray-900 border border-gray-700 rounded-xl text-white font-bold outline-none">
                                <option value="The Inspector-in-Charge (IIC)">The Inspector-in-Charge (IIC)</option>
                                <option value="The Officer-in-Charge (OIC)">The Officer-in-Charge (OIC)</option>
                                <option value="The Cyber Nodal Officer">The Cyber Nodal Officer</option>
                            </select>
                        </div>
                        <div>
                            <label class="block font-bold text-gray-300 mb-1">Police Station Name / ଥାନାର ନାମ *</label>
                            <input type="text" name="ps_name" required placeholder="e.g. Cyber Crime PS / Bhadrak Town PS" class="w-full p-3 bg-gray-900 border border-gray-700 rounded-xl text-white outline-none font-bold">
                        </div>
                        <div class="md:col-span-2">
                            <label class="block font-bold text-gray-300 mb-1">District Name / ଜିଲ୍ଲା *</label>
                            <input type="text" name="ps_district" required placeholder="e.g. Bhadrak, Odisha" class="w-full p-3 bg-gray-900 border border-gray-700 rounded-xl text-white outline-none font-bold">
                        </div>
                    </div>
                </div>

                <div class="bg-gray-950 p-5 rounded-2xl border border-gray-800 space-y-3">
                    <h2 class="text-sm font-black text-yellow-400 border-b border-gray-800 pb-2 uppercase flex items-center gap-2">
                        <i class="fa-solid fa-id-card"></i> 
                        <span class="lang-or">୨. ଅଭିଯୋଗକାରୀଙ୍କ ବିବରଣୀ (Complainant Details)</span>
                        <span class="lang-en">2. Complainant Details</span>
                    </h2>
                    <div class="grid grid-cols-1 md:grid-cols-2 gap-4">
                        <div>
                            <label class="block font-bold text-gray-300 mb-1">Full Name / ପୂରା ନାମ *</label>
                            <input type="text" name="comp_name" required placeholder="Enter full legal name" class="w-full p-3 bg-gray-900 border border-gray-700 rounded-xl text-white outline-none font-bold">
                        </div>
                        <div>
                            <label class="block font-bold text-gray-300 mb-1">Father's / Husband's Name / ବାପା/ସ୍ୱାମୀଙ୍କ ନାମ *</label>
                            <input type="text" name="comp_guardian" required placeholder="Enter father or husband name" class="w-full p-3 bg-gray-900 border border-gray-700 rounded-xl text-white outline-none">
                        </div>
                        <div class="md:col-span-2">
                            <label class="block font-bold text-gray-300 mb-1">Full Address / ପୂରା ଠିକଣା (Village/Town, Block, District, Pin) *</label>
                            <textarea name="comp_address" rows="2" required placeholder="Enter complete address" class="w-full p-3 bg-gray-900 border border-gray-700 rounded-xl text-white outline-none"></textarea>
                        </div>
                        <div>
                            <label class="block font-bold text-gray-300 mb-1">Mobile Number / ମୋବାଇଲ୍ ନମ୍ବର *</label>
                            <input type="text" name="comp_phone" required placeholder="10-digit mobile" class="w-full p-3 bg-gray-900 border border-gray-700 rounded-xl text-white outline-none font-bold">
                        </div>
                        <div>
                            <label class="block font-bold text-gray-300 mb-1">Email ID (Optional)</label>
                            <input type="email" name="comp_email" placeholder="Optional email address" class="w-full p-3 bg-gray-900 border border-gray-700 rounded-xl text-white outline-none">
                        </div>
                    </div>
                </div>

                <div class="bg-gray-950 p-5 rounded-2xl border border-gray-800 space-y-3">
                    <h2 class="text-sm font-black text-yellow-400 border-b border-gray-800 pb-2 uppercase flex items-center gap-2">
                        <i class="fa-solid fa-triangle-exclamation"></i> 
                        <span class="lang-or">୩. ଘଟଣାର ପୂରା ବିବରଣୀ (Incident Details)</span>
                        <span class="lang-en">3. Incident Particulars</span>
                    </h2>
                    <div class="grid grid-cols-1 md:grid-cols-2 gap-4">
                        <div>
                            <label class="block font-bold text-gray-300 mb-1">Incident Date & Time / ଘଟଣାର ତାରିଖ ଓ ସମୟ *</label>
                            <input type="text" name="incident_datetime" required placeholder="e.g. 15th October 2026 at 02:30 PM" class="w-full p-3 bg-gray-900 border border-gray-700 rounded-xl text-white outline-none">
                        </div>
                        <div>
                            <label class="block font-bold text-gray-300 mb-1">Nature of Cyber Crime / ଅପରାଧର ପ୍ରକାର *</label>
                            <select name="crime_nature" class="w-full p-3 bg-gray-900 border border-gray-700 rounded-xl text-white font-bold outline-none">
                                <option value="UPI Financial Fraud & Phishing Scam">UPI Financial Fraud & Phishing Scam</option>
                                <option value="Digital Arrest / Identity Impersonation">Digital Arrest / Identity Impersonation</option>
                                <option value="Fake Job Offer / Scholarship Scam">Fake Job Offer / Scholarship Scam</option>
                                <option value="Social Media Blackmail & Cyberstalking">Social Media Blackmail & Cyberstalking</option>
                                <option value="Unauthorized Bank Withdrawal / OTP Fraud">Unauthorized Bank Withdrawal / OTP Fraud</option>
                            </select>
                        </div>
                        <div class="md:col-span-2">
                            <label class="block font-bold text-gray-300 mb-1">Detailed Description / ଘଟଣା କିପରି ଘଟିଲା (Detailed Explanation) *</label>
                            <textarea name="incident_desc" rows="4" required placeholder="Explain step-by-step how the fraud took place..." class="w-full p-3 bg-gray-900 border border-gray-700 rounded-xl text-white outline-none leading-relaxed"></textarea>
                        </div>
                    </div>
                </div>

                <div class="bg-gray-950 p-5 rounded-2xl border border-gray-800 space-y-3">
                    <h2 class="text-sm font-black text-yellow-400 border-b border-gray-800 pb-2 uppercase flex items-center gap-2">
                        <i class="fa-solid fa-indian-rupee-sign"></i> 
                        <span class="lang-or">୪. ଠକେଇ ଟଙ୍କା ଏବଂ ପ୍ରମାଣ (Financial & Scammer Details)</span>
                        <span class="lang-en">4. Financial Loss & Evidence Details</span>
                    </h2>
                    <div class="grid grid-cols-1 md:grid-cols-2 gap-4">
                        <div>
                            <label class="block font-bold text-gray-300 mb-1">Fraud Amount (in Rs.) / ଠକେଇ ହୋଇଥିବା ଟଙ୍କା *</label>
                            <input type="text" name="fraud_amount" required placeholder="e.g. ₹25,000/-" class="w-full p-3 bg-gray-900 border border-gray-700 rounded-xl text-white font-black text-amber-400 outline-none">
                        </div>
                        <div>
                            <label class="block font-bold text-gray-300 mb-1">Transaction ID / UTR Number *</label>
                            <input type="text" name="txn_id" required placeholder="e.g. UTR / Txn No. 4291827491" class="w-full p-3 bg-gray-900 border border-gray-700 rounded-xl text-white outline-none font-mono">
                        </div>
                        <div>
                            <label class="block font-bold text-gray-300 mb-1">Victim Bank & Account Details *</label>
                            <input type="text" name="victim_bank" required placeholder="e.g. SBI A/c No: XXXXXX1234" class="w-full p-3 bg-gray-900 border border-gray-700 rounded-xl text-white outline-none">
                        </div>
                        <div>
                            <label class="block font-bold text-gray-300 mb-1">Scammer Mobile / UPI / Link *</label>
                            <input type="text" name="scammer_info" required placeholder="e.g. Scammer Mob: 98xxxxxx, UPI: fraud@ybl" class="w-full p-3 bg-gray-900 border border-gray-700 rounded-xl text-white outline-none">
                        </div>
                    </div>
                </div>

                <button type="submit" class="w-full bg-gradient-to-r from-amber-500 to-yellow-400 hover:brightness-110 text-blue-950 font-black py-4 rounded-2xl text-sm uppercase tracking-wider shadow-2xl transition transform hover:scale-[1.01] flex items-center justify-center gap-2 border-2 border-yellow-300">
                    <i class="fa-solid fa-file-pdf text-base"></i> Generate FIR-style Draft (Print / Save as PDF) →
                </button>
            </form>
        </div>
    </div>

    <script>
        function toggleFIRLang(lang) {
            if(lang === 'or') {
                document.querySelectorAll('.lang-or').forEach(e => e.style.display = 'block');
                document.querySelectorAll('.lang-en').forEach(e => e.style.display = 'none');
                document.getElementById('btn-fir-or').className = "bg-yellow-400 text-blue-950 font-black px-3 py-1 rounded-lg shadow";
                document.getElementById('btn-fir-en').className = "bg-gray-800 text-white font-bold px-3 py-1 rounded-lg";
            } else {
                document.querySelectorAll('.lang-en').forEach(e => e.style.display = 'block');
                document.querySelectorAll('.lang-or').forEach(e => e.style.display = 'none');
                document.getElementById('btn-fir-en').className = "bg-yellow-400 text-blue-950 font-black px-3 py-1 rounded-lg shadow";
                document.getElementById('btn-fir-or').className = "bg-gray-800 text-white font-bold px-3 py-1 rounded-lg";
            }
        }
    </script>
</body>
</html>
'''

FIR_PDF_TEMPLATE = '''
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Formal FIR Draft Application</title>
    <script src="https://cdn.tailwindcss.com"></script>
    <style>
        @media print {
            .no-print { display: none !important; }
            body { background: #ffffff !important; padding: 0 !important; color: #000000 !important; }
            .print-card { border: none !important; shadow: none !important; margin: 0 !important; padding: 20px !important; }
        }
    </style>
</head>
<body class="bg-gray-200 text-gray-950 p-4 md:p-10 font-serif min-h-screen flex flex-col justify-center items-center">

    <div class="max-w-4xl w-full mb-4 flex justify-between items-center no-print">
        <a href="/fir-generator" class="bg-blue-900 text-white px-4 py-2 rounded-xl text-xs font-bold font-sans">
            ← Edit Form Details
        </a>
        <button onclick="window.print()" class="bg-emerald-700 hover:bg-emerald-800 text-white px-6 py-2.5 rounded-xl font-bold text-xs uppercase shadow-xl font-sans flex items-center gap-2">
            🖨️ Print / Save as PDF FIR Draft
        </button>
    </div>

    <div class="print-card max-w-4xl w-full bg-white p-10 md:p-14 border-2 border-gray-400 shadow-2xl space-y-6 text-sm leading-relaxed text-black">
        
        <div class="text-right text-xs font-bold text-gray-700">
            Date: {{ now_date }}<br>
            Place: {{ data['ps_district'] }}
        </div>

        <div class="space-y-1 font-bold">
            <p>To,</p>
            <p>{{ data['officer_title'] }},</p>
            <p>{{ data['ps_name'] }},</p>
            <p>{{ data['ps_district'] }}.</p>
        </div>

        <div class="bg-gray-100 p-3 border-l-4 border-black font-black my-4 text-xs md:text-sm">
            SUBJECT: COMPLAINT REGARDING {{ data['crime_nature']|upper }} INVOLVING FINANCIAL FRAUD OF {{ data['fraud_amount'] }} UNDER SECTION 66D IT ACT 2000 AND APPLICABLE BNS PROVISIONS.
        </div>

        <div class="space-y-4 text-justify">
            <p>Respected Sir/Madam,</p>

            <p>
                I, <strong>{{ data['comp_name'] }}</strong>, Son/Daughter/Wife of <strong>{{ data['comp_guardian'] }}</strong>, 
                residing at {{ data['comp_address'] }} (Contact Mobile: <strong>{{ data['comp_phone'] }}</strong>{% if data['comp_email'] %}, Email: {{ data['comp_email'] }}{% endif %}), 
                beg to report a cyber crime incident that occurred with me as detailed below:
            </p>

            <p>
                <strong>Incident Particulars:</strong> On {{ data['incident_datetime'] }}, I fell victim to a cyber financial fraud. 
                {{ data['incident_desc'] }}
            </p>

            <p>
                <strong>Financial Loss Details:</strong>
                <ul class="list-disc pl-6 space-y-1">
                    <li>Total Defrauded Amount: <strong>{{ data['fraud_amount'] }}</strong></li>
                    <li>Transaction ID / UTR Number: <code>{{ data['txn_id'] }}</code></li>
                    <li>My Affected Bank Account: {{ data['victim_bank'] }}</li>
                    <li>Scammer Mobile / UPI / Channel Details: <strong>{{ data['scammer_info'] }}</strong></li>
                </ul>
            </p>

            <p>
                <strong>PRAYER / REQUEST:</strong><br>
                In view of the above stated facts, I request your good office to kindly register a formal FIR (First Information Report) 
                against the perpetrator(s), initiate an immediate investigation, direct the concerned banks to freeze the fraudulent destination accounts, 
                and take necessary legal action to recover my stolen funds at the earliest.
            </p>
        </div>

        <div class="pt-4 border-t border-gray-300 space-y-1 text-xs">
            <p class="font-bold">ENCLOSURES ATTACHED (ସଂଲଗ୍ନ ପ୍ରମାଣପତ୍ର):</p>
            <ol class="list-decimal pl-5 space-y-0.5">
                <li>Bank Account Statement highlighting the fraudulent transaction(s).</li>
                <li>Screenshots of WhatsApp Chats / Call Logs / Fraudulent Links.</li>
                <li>Copy of Identity Proof / ID Proof.</li>
            </ol>
        </div>

        <div class="pt-10 flex justify-between items-end">
            <div class="text-xs space-y-1">
                <p><strong>Complainant:</strong> {{ data['comp_name'] }}</p>
                <p><strong>Mobile:</strong> {{ data['comp_phone'] }}</p>
            </div>
            <div class="text-center space-y-8">
                <div class="w-48 border-b border-black"></div>
                <p class="font-bold text-xs">Signature of Complainant / ଆବେଦନକାରୀଙ୍କ ଦସ୍ତଖତ</p>
            </div>
        </div>

    </div>
</body>
</html>
'''

CONGRATS_CERTIFICATE_PAGE = '''
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Cyber Fraud Registration Certificate</title>
    <script src="https://cdn.tailwindcss.com"></script>
    <link href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css" rel="stylesheet">
    <style>
        @media print {
            .no-print { display: none !important; }
            body { background-color: #ffffff !important; padding: 0 !important; }
            .cert-card { border: none !important; shadow: none !important; }
        }
    </style>
</head>
<body class="bg-gray-100 text-gray-950 p-4 md:p-8 font-sans min-h-screen flex flex-col justify-center items-center">

    <div class="max-w-4xl w-full mb-6 flex flex-wrap justify-between items-center gap-2 no-print">
        <a href="/dashboard" class="bg-blue-600 hover:bg-blue-700 text-white px-5 py-2.5 rounded-xl font-bold text-xs shadow flex items-center gap-2">
            <i class="fa-solid fa-house"></i> Return to Dashboard
        </a>
        <a href="/profile-saved" class="bg-violet-600 hover:bg-violet-700 text-white px-5 py-2.5 rounded-xl font-bold text-xs shadow flex items-center gap-2">
            <i class="fa-solid fa-id-card"></i> View Saved Profile
        </a>
        <button onclick="window.print()" class="bg-emerald-600 hover:bg-emerald-700 text-white px-6 py-2.5 rounded-xl font-black text-xs uppercase tracking-wider shadow-xl flex items-center gap-2 border-2 border-emerald-400">
            <i class="fa-solid fa-print text-sm"></i> Download / Print Certificate (PDF)
        </button>
    </div>

    <div class="cert-card max-w-4xl w-full bg-white p-8 md:p-12 rounded-3xl border-4 border-blue-900 shadow-2xl space-y-8 relative overflow-hidden">
        
        <div class="absolute top-6 right-6 border-4 border-emerald-600 text-emerald-700 p-3 rounded-2xl rotate-12 opacity-90 text-center font-black uppercase text-[11px] tracking-widest bg-emerald-50">
            <i class="fa-solid fa-certificate text-2xl block mb-1"></i>
            DEMO RECEIPT · NOT OFFICIAL
        </div>

        <div class="text-center space-y-2 border-b-4 border-blue-900 pb-6">
            <div class="flex items-center justify-center gap-3">
                <div class="w-16 h-16 bg-blue-900 text-yellow-400 rounded-2xl flex items-center justify-center text-3xl font-black shadow-lg">🛡️</div>
                <div class="text-left">
                    <h1 class="text-3xl md:text-5xl font-black text-blue-950 tracking-tight uppercase">CYBER FRAUD</h1>
                    <p class="text-xs font-black text-red-600 tracking-widest uppercase">INDEPENDENT CYBERSHIELD DEMO • NOT A GOVERNMENT RECEIPT</p>
                </div>
            </div>
            <h2 class="text-lg md:text-2xl font-black text-gray-800 uppercase tracking-wide pt-4">CYBERSHIELD DEMO COMPLAINT RECEIPT — NOT OFFICIAL</h2>
            <p class="text-xs text-gray-500 font-bold">Generated by CyberShield AI Intelligence System</p>
        </div>

        <div class="bg-emerald-50 border-2 border-emerald-500 p-4 rounded-2xl text-center text-emerald-900 font-extrabold text-sm shadow-inner">
            🎉 Your complaint form was received by the CyberShield demo portal.
        </div>

        <div class="grid grid-cols-1 md:grid-cols-2 gap-6 text-xs text-gray-900">
            <div class="bg-gray-50 p-5 rounded-2xl border border-gray-300 space-y-2">
                <h3 class="font-black text-blue-900 border-b border-gray-300 pb-2 uppercase text-sm"><i class="fa-solid fa-user-check"></i> Citizen Profile Details</h3>
                <p><strong>Complainant Name:</strong> {{ complaint[2] }}</p>
                <p><strong>Father's Name:</strong> {{ complaint[3] }}</p>
                <p><strong>Mother's Name:</strong> {{ complaint[5] }}</p>
                <p><strong>Date of Birth:</strong> {{ complaint[7] }}</p>
                <p><strong>Registered Mobile:</strong> {{ complaint[1] }}</p>
                <p><strong>Active Contact Mobile:</strong> {{ complaint[11] }}</p>
            </div>

            <div class="bg-gray-50 p-5 rounded-2xl border border-gray-300 space-y-2">
                <h3 class="font-black text-blue-900 border-b border-gray-300 pb-2 uppercase text-sm"><i class="fa-solid fa-location-dot"></i> Regional & GPS Location</h3>
                <p><strong>District:</strong> {{ complaint[8] }}</p>
                <p><strong>Block:</strong> {{ complaint[9] }}</p>
                <p><strong>Panchayat / Village:</strong> {{ complaint[10] }}</p>
                <p><strong>Permanent Address:</strong> {{ complaint[12] }}</p>
                <p><strong>GPS Coordinates:</strong> {{ complaint[14] }}, {{ complaint[15] }}</p>
            </div>
        </div>

        <div class="bg-blue-50 p-6 rounded-2xl border-2 border-blue-200 text-xs space-y-3">
            <h3 class="font-black text-blue-950 uppercase text-sm border-b border-blue-200 pb-2 flex justify-between">
                <span><i class="fa-solid fa-file-invoice"></i> Cyber Crime Incident Particulars</span>
                <span class="text-red-700">Case ID: #{{ complaint[0] }}</span>
            </h3>
            <p><strong>Incident Category / Title:</strong> <span class="font-bold text-blue-900">{{ complaint[16] }}</span></p>
            <p><strong>Detailed Crime Report:</strong> {{ complaint[17] }}</p>
            {% if complaint|length > 24 and complaint[24] %}<div class="rounded-xl border border-cyan-300 bg-cyan-50 p-3 space-y-2"><p class="font-bold text-cyan-950">🎙️ Voice complaint</p><audio controls preload="none" class="w-full" src="/uploads/{{ complaint[24] }}">Your browser does not support audio playback.</audio></div>{% endif %}
            <p><strong>Filing Date & Time:</strong> {{ complaint[20] }}</p>
            <p><strong>Initial Status:</strong> <span class="bg-yellow-400 text-blue-950 font-black px-2 py-0.5 rounded text-[11px]">{{ complaint[18] }}</span></p>
            <p class="mt-4 rounded-xl border border-blue-200 bg-blue-50 p-3 text-sm"><strong>Email confirmation:</strong> {% if email_status == 'sent' %}Sent to {{ complaint[22] }}.{% elif email_status == 'failed' %}Could not be delivered right now. Your demo complaint was still saved.{% else %}Email sending is not configured yet. Your demo complaint was still saved.{% endif %}</p>
            <p class="text-xs text-amber-800">This is a project demo receipt, not an official police complaint or FIR filing.</p>
        </div>

        <div class="pt-6 border-t-2 border-gray-300 flex flex-col md:flex-row justify-between items-center text-xs text-gray-600 gap-4">
            <div class="space-y-1 text-center md:text-left">
                <p class="font-extrabold text-blue-950">CYBERSHIELD NATIONAL PORTAL</p>
                <p class="text-[10px]">Lead Developer: Sashikanta Mohanty (IIIT Bhubaneswar)</p>
            </div>
            <div class="text-center space-y-1">
                <div class="font-bold text-blue-900 font-serif italic text-base">Sashikanta Mohanty</div>
                <div class="border-t border-gray-400 pt-1 text-[10px] font-black uppercase text-gray-700">Senior Nodal Officer Signature</div>
            </div>
        </div>

    </div>
</body>
</html>
'''

TRACK_STATUS_LOGIN_PAGE = '''
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8"><title>Track Complaint Status</title><script src="https://cdn.tailwindcss.com"></script>
    <link href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css" rel="stylesheet">
</head>
<body class="bg-slate-900 text-gray-100 min-h-screen flex flex-col justify-between p-4 font-sans">
    <div class="max-w-md mx-auto w-full pt-4 flex justify-between items-center">
        <a href="/" class="bg-gray-800 hover:bg-gray-700 text-white px-4 py-2 rounded-xl text-xs font-bold border border-gray-700">
            <i class="fa-solid fa-house"></i> Home
        </a>
        <span class="bg-emerald-600 text-white text-xs font-black px-3 py-1 rounded-full uppercase">🔍 Citizen Case Vault</span>
    </div>

    <div class="max-w-md mx-auto w-full bg-white text-gray-900 p-8 rounded-3xl my-auto shadow-2xl border border-emerald-500/40 space-y-6">
        <div class="text-center space-y-1">
            <div class="w-12 h-12 bg-emerald-100 text-emerald-700 rounded-2xl flex items-center justify-center text-2xl font-black mx-auto">
                <i class="fa-solid fa-file-shield"></i>
            </div>
            <h2 class="text-2xl font-black text-blue-950">Check Complaint Status</h2>
            <p class="text-xs text-gray-500">Enter registered mobile and password to track filed complaints</p>
        </div>

        {% if error %}<div class="bg-red-100 border border-red-400 text-red-700 p-3 rounded-xl text-xs font-bold text-center">{{ error }}</div>{% endif %}

        <form action="/track-status-login-action" method="POST" class="space-y-4 text-xs">
            <div>
                <label class="block font-bold text-gray-700 mb-1">Registered Mobile *</label>
                <input type="text" name="mobile" required placeholder="Enter mobile" class="w-full p-3 bg-gray-50 rounded-xl border border-gray-300 font-bold outline-none">
            </div>
            <div>
                <label class="block font-bold text-gray-700 mb-1">Account Password *</label>
                <input type="password" name="password" required placeholder="Enter password" class="w-full p-3 bg-gray-50 rounded-xl border border-gray-300 font-bold outline-none">
            </div>
            <button type="submit" class="w-full bg-emerald-600 hover:bg-emerald-700 text-white py-3.5 rounded-xl font-black shadow-xl uppercase">Track My Status →</button>
        </form>
    </div>
</body>
</html>
'''

CITIZEN_STATUS_VIEW_PAGE = '''
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8"><title>My Complaint Status & Remarks</title><script src="https://cdn.tailwindcss.com"></script>
    <link href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css" rel="stylesheet">
</head>
<body class="bg-gray-950 text-gray-100 p-4 md:p-8 font-sans min-h-screen">
    <div class="max-w-5xl mx-auto space-y-6">
        
        <div class="bg-gray-900 p-6 rounded-3xl border border-emerald-500/50 flex flex-col md:flex-row justify-between items-center gap-4 shadow-2xl">
            <div class="flex items-center gap-3">
                <div class="w-12 h-12 bg-emerald-600 text-white rounded-2xl flex items-center justify-center text-2xl font-black">
                    <i class="fa-solid fa-clipboard-check"></i>
                </div>
                <div>
                    <h2 class="text-xl font-black text-white">Citizen Complaint Status Center</h2>
                    <p class="text-xs text-emerald-400 font-bold">Mobile: {{ mobile }}</p>
                </div>
            </div>
            <div class="flex gap-2">
                <a href="/dashboard" class="bg-blue-600 text-white px-4 py-2 rounded-xl text-xs font-bold">New Complaint +</a>
                <a href="/logout" class="bg-red-600 text-white px-4 py-2 rounded-xl text-xs font-bold">Logout</a>
            </div>
        </div>

        <div class="grid grid-cols-1 md:grid-cols-3 gap-6">
            <div class="space-y-4">
                <h3 class="text-sm font-black text-yellow-400 uppercase tracking-wider"><i class="fa-solid fa-list-check"></i> Filed Complaints</h3>
                {% if user_complaints %}
                    {% for c in user_complaints %}
                        <a href="/track-status-view?cid={{ c[0] }}" class="block p-4 rounded-2xl border transition shadow-md {% if active_cid == c[0] %}bg-emerald-950 border-emerald-400 text-white{% else %}bg-gray-900 border-gray-800 text-gray-300 hover:border-gray-600{% endif %}">
                            <div class="flex justify-between items-center font-bold text-xs mb-1">
                                <span>Case #{{ c[0] }}</span>
                                <span class="bg-emerald-600 text-white px-2 py-0.5 rounded text-[10px]">{{ c[18] }}</span>
                            </div>
                            <p class="font-black text-xs text-white truncate">{{ c[16] }}</p>
                            <p class="text-[10px] text-gray-400 mt-1"><i class="fa-regular fa-clock"></i> {{ c[20] }}</p>
                        </a>
                    {% endfor %}
                {% else %}
                    <p class="text-xs text-gray-500 italic bg-gray-900 p-4 rounded-2xl">No complaints filed under this account.</p>
                {% endif %}
            </div>

            <div class="md:col-span-2 bg-gray-900 p-6 rounded-3xl border-2 border-emerald-500/50 flex flex-col justify-between h-[520px]">
                {% if active_complaint %}
                <div>
                    <div class="border-b border-gray-800 pb-3 flex justify-between items-center">
                        <div>
                            <span class="bg-yellow-400 text-blue-950 text-[10px] font-black px-2.5 py-0.5 rounded-full uppercase">Case ID #{{ active_complaint[0] }}</span>
                            <h4 class="text-sm font-black text-white mt-1">{{ active_complaint[16] }}</h4>
                            <p class="text-[11px] text-emerald-400 font-bold">Status: {{ active_complaint[18] }}</p>
                        </div>
                        <a href="/complaint-certificate/{{ active_complaint[0] }}" class="bg-white text-blue-950 font-black px-3 py-1.5 rounded-xl text-xs shadow hover:bg-gray-100 flex items-center gap-1">
                            📄 Download Receipt
                        </a>
                    </div>
                </div>

                <div class="flex-1 overflow-y-auto my-3 p-3 bg-gray-950 rounded-2xl border border-gray-800 space-y-3 text-xs">
                    {% if remarks %}
                        {% for r in remarks %}
                            <div class="flex flex-col {% if r[2] == 'citizen' %}items-end{% else %}items-start{% endif %}">
                                <div class="max-w-xs md:max-w-md p-3 rounded-2xl shadow-md space-y-1 {% if r[2] == 'citizen' %}bg-emerald-600 text-white rounded-br-none{% else %}bg-blue-700 text-white rounded-bl-none border border-blue-500{% endif %}">
                                    <span class="text-[9px] font-black opacity-80 block">{{ r[3] }}</span>
                                    {% if r[4] %}<p class="font-medium leading-relaxed">{{ r[4] }}</p>{% endif %}
                                    {% if r[5] %}
                                        <a href="/uploads/{{ r[5] }}" target="_blank" class="block mt-1 bg-black/30 p-2 rounded-lg text-[10px] font-bold text-yellow-300">📁 Attached Media / Photo</a>
                                    {% endif %}
                                    <span class="text-[8px] opacity-60 block text-right mt-1">{{ r[6] }}</span>
                                </div>
                            </div>
                        {% endfor %}
                    {% else %}
                        <p class="text-xs text-gray-500 italic text-center py-16">No remark messages exchanged with Admin for this case yet.</p>
                    {% endif %}
                </div>

                <div>
                    {% if is_blocked %}
                        <div class="bg-red-950 border border-red-600 p-3 rounded-2xl text-center text-xs space-y-1">
                            <p class="text-red-400 font-black">🔒 Citizen Chat Locked (5-Min Time Limit Reached)</p>
                            <p class="text-gray-300 text-[11px]">You can send messages again after <strong class="text-yellow-300">{{ remaining_cooldown }}</strong> seconds.</p>
                        </div>
                    {% else %}
                        <form action="/send-complaint-remark" method="POST" enctype="multipart/form-data" class="space-y-2">
                            <input type="hidden" name="complaint_id" value="{{ active_complaint[0] }}">
                            <input type="hidden" name="sender_type" value="citizen">
                            <input type="hidden" name="sender_name" value="Citizen (Complainant)">
                            
                            <div class="flex gap-2">
                                <input type="text" name="message" placeholder="Type remark/problem for Admin..." class="w-full p-2.5 bg-gray-950 border border-gray-700 rounded-xl text-white text-xs outline-none font-medium">
                                <button type="submit" class="bg-emerald-600 hover:bg-emerald-500 text-white font-black px-5 rounded-xl text-xs uppercase flex-shrink-0">Send →</button>
                            </div>
                            <div class="flex justify-between items-center text-[10px] text-gray-400">
                                <span>Attach Photo/Doc: <input type="file" name="attachment" class="text-[10px]"></span>
                                <span class="text-yellow-400 font-bold">⚠️ Active Window: 5 Mins Max limit</span>
                            </div>
                        </form>
                    {% endif %}
                </div>

                {% else %}
                <div class="flex flex-col items-center justify-center h-full text-center space-y-2 text-gray-500">
                    <i class="fa-solid fa-comments text-4xl text-emerald-500"></i>
                    <p class="text-xs font-bold">Select a complaint from left to track status & chat with Admin.</p>
                </div>
                {% endif %}
            </div>
        </div>

    </div>
</body>
</html>
'''

HEAD_ADMIN_DASHBOARD = '''
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Head Admin Panel - CyberShield</title>
    <script src="https://cdn.tailwindcss.com"></script>
    <link href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css" rel="stylesheet">
    <style>
        @keyframes fadeIn { from { opacity: 0; transform: translateY(15px); } to { opacity: 1; transform: translateY(0); } }
        .tab-content { display: none; }
        .tab-content.active { display: block; animation: fadeIn 0.4s ease-out forwards; }
        .tab-btn.active { background-color: #dc2626; color: #ffffff; border-color: #ef4444; box-shadow: 0 0 15px rgba(220, 38, 38, 0.5); }
    </style>
</head>
<body class="bg-gray-950 text-gray-100 p-4 md:p-8 font-sans min-h-screen flex flex-col justify-between">
    <div class="max-w-7xl mx-auto w-full space-y-6">
        
        <div class="bg-gradient-to-r from-red-900 via-gray-900 to-gray-950 text-white p-6 rounded-3xl border-2 border-red-600 flex flex-col md:flex-row justify-between items-center gap-4 shadow-2xl">
            <div class="flex items-center gap-4">
                <div class="w-14 h-14 bg-red-600 rounded-2xl flex items-center justify-center text-3xl font-black shadow-lg text-white border-2 border-white">
                    <i class="fa-solid fa-user-shield"></i>
                </div>
                <div>
                    <span class="bg-white text-red-700 text-[10px] font-black px-3 py-1 rounded-full uppercase tracking-widest shadow">👑 HEAD OFFICER CONTROL</span>
                    <h2 class="text-2xl font-black mt-1 text-white tracking-tight">{{ admin_prof[2] }}</h2>
                </div>
            </div>
            <a href="/logout" class="bg-red-600 hover:bg-red-700 text-white px-6 py-2.5 rounded-xl text-xs font-black shadow-lg transition transform hover:scale-105 border border-red-400">
                <i class="fa-solid fa-right-from-bracket mr-1"></i> LOGOUT
            </a>
        </div>

        <div class="grid grid-cols-2 md:grid-cols-3 lg:grid-cols-5 gap-2 bg-gray-900 p-2 rounded-2xl border border-gray-800 shadow-xl">
            <button onclick="switchAdminTab('tab-complaints')" id="btn-tab-complaints" class="tab-btn active bg-gray-800 hover:bg-gray-700 text-gray-300 font-black py-3 px-3 rounded-xl text-xs transition border border-transparent flex items-center justify-center gap-1.5">
                <i class="fa-solid fa-list-check"></i> 1. Complaints
            </button>
            <button onclick="switchAdminTab('tab-feedbacks')" id="btn-tab-feedbacks" class="tab-btn bg-gray-800 hover:bg-gray-700 text-gray-300 font-black py-3 px-3 rounded-xl text-xs transition border border-transparent flex items-center justify-center gap-1.5">
                <i class="fa-solid fa-comments"></i> 2. Feedbacks
            </button>
            <button onclick="switchAdminTab('tab-subadmins')" id="btn-tab-subadmins" class="tab-btn bg-gray-800 hover:bg-gray-700 text-gray-300 font-black py-3 px-3 rounded-xl text-xs transition border border-transparent flex items-center justify-center gap-1.5">
                <i class="fa-solid fa-user-plus"></i> 3. Gen Sub-Admin
            </button>
            <button onclick="switchAdminTab('tab-notices')" id="btn-tab-notices" class="tab-btn bg-gray-800 hover:bg-gray-700 text-gray-300 font-black py-3 px-3 rounded-xl text-xs transition border border-transparent flex items-center justify-center gap-1.5">
                <i class="fa-solid fa-bullhorn"></i> 4. Notices
            </button>
            <button onclick="switchAdminTab('tab-chat')" id="btn-tab-chat" class="tab-btn bg-gray-800 hover:bg-gray-700 text-gray-300 font-black py-3 px-3 rounded-xl text-xs transition border border-transparent flex items-center justify-center gap-1.5">
                <i class="fa-solid fa-paper-plane text-yellow-400"></i> 5. Sub-Admin Chat
            </button>
        </div>

        <div id="tab-complaints" class="tab-content active space-y-4">
            <div class="bg-white text-gray-950 p-6 md:p-8 rounded-3xl border-2 border-red-500 shadow-2xl space-y-4">
                <div class="flex justify-between items-center border-b-2 border-red-100 pb-4">
                    <h3 class="text-xl font-black text-red-700 flex items-center gap-2"><i class="fa-solid fa-box-archive"></i> Section 1: All Registered Complaints Vault</h3>
                    <span class="bg-red-100 text-red-700 px-3 py-1 rounded-full text-xs font-extrabold">Total: {{ cases|length }}</span>
                </div>

                {% if cases %}
                    <div class="space-y-4">
                    {% for item in cases %}
                        {% set c = item[0] %}
                        <div class="bg-slate-50 p-5 rounded-2xl border-2 border-red-200 text-xs text-gray-900 space-y-3 shadow-md hover:border-red-400 transition">
                            <div class="flex flex-col sm:flex-row justify-between font-black text-red-700 border-b border-red-200 pb-2 gap-1 text-sm">
                                <span>Case #{{ c[0] }} • Complainant: {{ c[2] }}</span>
                                <span class="bg-red-600 text-white px-2.5 py-0.5 rounded-lg text-xs">Status: {{ c[18] }}</span>
                            </div>
                            <p class="text-gray-900 font-bold text-sm">{{ c[16] }}</p>
                            <p class="text-gray-700 leading-relaxed">{{ c[17] }}</p>

                            <div class="bg-white p-3 rounded-xl border border-red-100 space-y-1 font-semibold text-gray-600">
                                <p>📞 Contact: <strong class="text-red-700">{{ c[11] }}</strong> | District: {{ c[8] }}, Block: {{ c[9] }}</p>
                                <p>📍 Present Address: {{ c[13] }}</p>
                            </div>

                            <div class="bg-amber-50 p-3 rounded-xl border border-amber-300 flex justify-between items-center">
                                <span class="font-extrabold text-amber-900">💬 Citizen Complaint Remarks Window</span>
                                <a href="/admin-complaint-remark/{{ c[0] }}" class="bg-amber-500 hover:bg-amber-600 text-blue-950 font-black px-4 py-1.5 rounded-lg shadow text-xs">
                                    Open Citizen Remark Chat →
                                </a>
                            </div>

                            {% if c[14] and c[15] %}
                            <div class="pt-1 space-y-1">
                                <span class="text-red-700 font-extrabold block">🗺️ Live Satellite GPS Map Location:</span>
                                <a href="https://www.google.com/maps?q={{ c[14] }},{{ c[15] }}" target="_blank" class="inline-block relative overflow-hidden rounded-2xl border-2 border-red-500 shadow-md">
                                    <img src="https://static-maps.yandex.ru/1.x/?lang=en-US&ll={{ c[15] }},{{ c[14] }}&z=15&l=sat,skl&pt={{ c[15] }},{{ c[14] }},pm2rdm" alt="Map Spot" class="w-64 h-36 object-cover">
                                </a>
                            </div>
                            {% endif %}

                            {% if c[19] %}
                            <div class="pt-1 flex items-center gap-2">
                                <span class="text-red-700 font-extrabold">📷 Evidence:</span>
                                <a href="/uploads/{{ c[19] }}" target="_blank" class="bg-red-600 hover:bg-red-700 text-white px-3 py-1 rounded-lg text-xs font-bold">View File 📁</a>
                            </div>
                            {% endif %}
                            {% if c|length > 24 and c[24] %}
                            <div class="pt-2 rounded-xl border border-cyan-300 bg-cyan-50 p-3 space-y-2"><p class="font-extrabold text-cyan-950">🎙️ Citizen voice complaint</p><audio controls preload="none" class="w-full" src="/uploads/{{ c[24] }}">Your browser does not support audio playback.</audio></div>
                            {% endif %}
                            
                            <form action="/update-status/{{ c[0] }}" method="POST" class="flex gap-2 pt-2 border-t border-red-100">
                                <select name="status" class="p-2 bg-white rounded-xl border border-red-300 font-bold text-gray-900 outline-none">
                                    <option value="Pending">Pending</option>
                                    <option value="Working...">Working...</option>
                                    <option value="Resolved">Resolved</option>
                                    <option value="Congratulations! (Case Solved)">Congratulations! (Case Solved)</option>
                                </select>
                                <button type="submit" class="bg-red-600 hover:bg-red-700 text-white px-5 py-2 rounded-xl font-black uppercase text-xs shadow">Update Status</button>
                            </form>
                        </div>
                    {% endfor %}
                    </div>
                {% else %}
                    <p class="text-gray-500 italic text-center py-8">No complaints registered in vault.</p>
                {% endif %}
            </div>
        </div>

        <div id="tab-feedbacks" class="tab-content space-y-4">
            <div class="bg-white text-gray-950 p-6 md:p-8 rounded-3xl border-2 border-red-500 shadow-2xl space-y-4">
                <div class="flex justify-between items-center border-b-2 border-red-100 pb-4">
                    <h3 class="text-xl font-black text-red-700 flex items-center gap-2"><i class="fa-solid fa-comments"></i> Section 2: Received User Feedbacks Vault</h3>
                    <span class="bg-red-100 text-red-700 px-3 py-1 rounded-full text-xs font-extrabold">Total: {{ feedbacks|length }}</span>
                </div>

                {% if feedbacks %}
                    <div class="grid grid-cols-1 md:grid-cols-2 gap-4">
                    {% for f in feedbacks %}
                        <div class="bg-slate-50 p-5 rounded-2xl border border-red-200 text-xs space-y-2 shadow-sm">
                            <div class="flex justify-between font-black text-red-700 text-sm">
                                <span><i class="fa-solid fa-user-circle mr-1"></i> {{ f[1] }}</span>
                                <span class="text-gray-400 text-[10px] font-normal">{{ f[4] }}</span>
                            </div>
                            <p class="text-gray-700 font-bold">Contact: <span class="text-red-600">{{ f[2] }}</span></p>
                            <p class="text-gray-900 bg-white p-3 rounded-xl border border-gray-200 mt-2 font-medium leading-relaxed">{{ f[3] }}</p>
                        </div>
                    {% endfor %}
                    </div>
                {% else %}
                    <p class="text-gray-500 italic text-center py-8">No user feedbacks received yet.</p>
                {% endif %}
            </div>
        </div>

        <div id="tab-subadmins" class="tab-content space-y-4">
            <div class="bg-white text-gray-950 p-6 md:p-8 rounded-3xl border-2 border-red-500 shadow-2xl space-y-6">
                <div class="border-b-2 border-red-100 pb-4">
                    <h3 class="text-xl font-black text-red-700 flex items-center gap-2"><i class="fa-solid fa-user-shield"></i> Section 3: Generate Sub-Admin Credentials</h3>
                    <p class="text-xs text-gray-500 mt-1">Create new Sub-Admin logins for field nodal officers</p>
                </div>

                <form action="/create-sub-admin" method="POST" class="grid grid-cols-1 md:grid-cols-3 gap-4 text-xs">
                    <div>
                        <label class="block font-bold text-gray-700 mb-1">Sub-Admin ID *</label>
                        <input type="text" name="sub_id" required placeholder="Assign Sub-Admin ID" class="w-full p-3 bg-slate-50 rounded-xl border border-gray-300 font-bold outline-none">
                    </div>
                    <div>
                        <label class="block font-bold text-gray-700 mb-1">Password *</label>
                        <input type="text" name="sub_pass" required placeholder="Assign Password" class="w-full p-3 bg-slate-50 rounded-xl border border-gray-300 font-bold outline-none">
                    </div>
                    <div>
                        <label class="block font-bold text-gray-700 mb-1">Officer Name *</label>
                        <input type="text" name="sub_name" required placeholder="Full Officer Name" class="w-full p-3 bg-slate-50 rounded-xl border border-gray-300 font-bold outline-none">
                    </div>
                    <div class="md:col-span-3">
                        <button type="submit" class="w-full bg-red-600 hover:bg-red-700 text-white font-black py-4 rounded-xl shadow-xl uppercase tracking-wider transition">
                            Generate Sub-Admin Account →
                        </button>
                    </div>
                </form>
            </div>
        </div>

        <div id="tab-notices" class="tab-content space-y-4">
            <div class="bg-white text-gray-950 p-6 md:p-8 rounded-3xl border-2 border-red-500 shadow-2xl space-y-6">
                <div class="border-b-2 border-red-100 pb-4">
                    <h3 class="text-xl font-black text-red-700 flex items-center gap-2"><i class="fa-solid fa-bullhorn"></i> Section 4: Live Notice Board & Banner Updates</h3>
                    <p class="text-xs text-gray-500 mt-1">Control scrolling marquee text and front page awareness photo banners</p>
                </div>

                <div class="bg-slate-50 p-5 rounded-2xl border border-red-200 space-y-3">
                    <h4 class="font-black text-red-700 text-sm">1. Marquee Notice Text Update</h4>
                    <form action="/update-notice" method="POST" class="flex flex-col sm:flex-row gap-2 text-xs">
                        <input type="text" name="notice_text" value="{{ notice_text }}" required class="w-full p-3 bg-white rounded-xl border border-gray-300 font-bold outline-none">
                        <button type="submit" class="bg-red-600 hover:bg-red-700 text-white font-black px-6 py-3 rounded-xl shadow flex-shrink-0 uppercase">Update Notice</button>
                    </form>
                </div>

                <div class="space-y-4">
                    <h4 class="font-black text-red-700 text-sm">2. Cyber Awareness Photo Banners (Up to 2 Photos)</h4>
                    <div class="grid grid-cols-1 md:grid-cols-2 gap-4 text-xs">
                        <div class="bg-slate-50 p-4 rounded-2xl border border-red-200 space-y-3">
                            <p class="font-extrabold text-gray-800">Photo Banner Slot #1</p>
                            <form action="/upload-notice-photo/1" method="POST" enctype="multipart/form-data" class="space-y-2">
                                <input type="file" name="notice_photo" required class="p-2 bg-white rounded-xl border border-gray-300 w-full">
                                <button type="submit" class="w-full bg-red-600 hover:bg-red-700 text-white font-black py-2.5 rounded-xl shadow">Upload Photo #1</button>
                            </form>
                            {% if notice_photo1 %}
                            <div class="flex justify-between items-center pt-2 border-t border-gray-200">
                                <img src="/uploads/{{ notice_photo1 }}" class="w-20 h-12 object-cover rounded border border-red-500">
                                <a href="/delete-notice-photo/1" class="bg-red-600 text-white font-bold px-3 py-1 rounded-lg text-[10px]">Delete Slot #1 🗑️</a>
                            </div>
                            {% endif %}
                        </div>

                        <div class="bg-slate-50 p-4 rounded-2xl border border-red-200 space-y-3">
                            <p class="font-extrabold text-gray-800">Photo Banner Slot #2</p>
                            <form action="/upload-notice-photo/2" method="POST" enctype="multipart/form-data" class="space-y-2">
                                <input type="file" name="notice_photo" required class="p-2 bg-white rounded-xl border border-gray-300 w-full">
                                <button type="submit" class="w-full bg-red-600 hover:bg-red-700 text-white font-black py-2.5 rounded-xl shadow">Upload Photo #2</button>
                            </form>
                            {% if notice_photo2 %}
                            <div class="flex justify-between items-center pt-2 border-t border-gray-200">
                                <img src="/uploads/{{ notice_photo2 }}" class="w-20 h-12 object-cover rounded border border-red-500">
                                <a href="/delete-notice-photo/2" class="bg-red-600 text-white font-bold px-3 py-1 rounded-lg text-[10px]">Delete Slot #2 🗑️</a>
                            </div>
                            {% endif %}
                        </div>
                    </div>
                </div>
            </div>
        </div>

        <div id="tab-chat" class="tab-content space-y-4">
            <div class="bg-white text-gray-950 p-6 md:p-8 rounded-3xl border-2 border-red-500 shadow-2xl space-y-6">
                <div class="border-b-2 border-red-100 pb-4 flex justify-between items-center">
                    <div>
                        <h3 class="text-xl font-black text-red-700 flex items-center gap-2"><i class="fa-solid fa-headset"></i> Section 5: Sub-Admin Helpdesk Messenger</h3>
                        <p class="text-xs text-gray-500 mt-1">Directly chat and reply to Sub-Admins with text, photos, recordings, and files</p>
                    </div>
                </div>

                <div class="grid grid-cols-1 md:grid-cols-3 gap-6">
                    <div class="bg-slate-50 p-4 rounded-2xl border border-red-200 space-y-2">
                        <h4 class="font-black text-red-700 text-xs uppercase mb-3"><i class="fa-solid fa-users"></i> Select Sub-Admin Officer</h4>
                        {% if sub_admins %}
                            <div class="space-y-2">
                            {% for sa in sub_admins %}
                                <a href="/admin-dashboard?target_sub={{ sa[1] }}#tab-chat" class="block p-3 rounded-xl border border-gray-200 hover:border-red-500 transition {% if target_sub == sa[1] %}bg-red-600 text-white font-bold{% else %}bg-white text-gray-800{% endif %}">
                                    <div class="font-bold text-xs">{{ sa[3] }}</div>
                                    <div class="text-[10px] opacity-80">ID: {{ sa[1] }}</div>
                                </a>
                            {% endfor %}
                            </div>
                        {% else %}
                            <p class="text-xs text-gray-500 italic">No Sub-Admins generated yet.</p>
                        {% endif %}
                    </div>

                    <div class="md:col-span-2 bg-slate-900 text-white p-5 rounded-2xl border-2 border-red-600 flex flex-col justify-between h-[480px]">
                        {% if target_sub %}
                        <div class="border-b border-gray-800 pb-2 mb-3 flex justify-between items-center">
                            <span class="font-black text-red-400 text-sm">💬 Chatting with Sub-Admin ID: {{ target_sub }}</span>
                            <a href="/admin-dashboard" class="text-xs text-gray-400 hover:text-white">Refresh 🔄</a>
                        </div>

                        <div class="flex-1 overflow-y-auto space-y-3 p-2 bg-slate-950 rounded-xl mb-3 text-xs border border-gray-800">
                            {% if chat_msgs %}
                                {% for m in chat_msgs %}
                                    <div class="flex flex-col {% if m[2] == 'head_admin' %}items-end{% else %}items-start{% endif %}">
                                        <div class="max-w-xs md:max-w-md p-3 rounded-2xl shadow-md space-y-1 {% if m[2] == 'head_admin' %}bg-red-600 text-white rounded-br-none{% else %}bg-gray-800 text-gray-100 rounded-bl-none border border-gray-700{% endif %}">
                                            <span class="text-[9px] font-black opacity-75 block mb-0.5">{% if m[2] == 'head_admin' %}Head Officer{% else %}Sub-Admin {{ m[1] }}{% endif %}</span>
                                            
                                            {% if m[3] %}
                                            <p class="leading-relaxed font-medium">{{ m[3] }}</p>
                                            {% endif %}

                                            {% if m[4] %}
                                                {% if m[5] == 'image' %}
                                                    <img src="/uploads/{{ m[4] }}" class="w-48 h-auto rounded-lg border border-white/20 my-1">
                                                {% elif m[5] == 'video' %}
                                                    <video controls class="w-56 h-auto rounded-lg my-1"><source src="/uploads/{{ m[4] }}"></video>
                                                {% elif m[5] == 'audio' %}
                                                    <audio controls class="w-full my-1"><source src="/uploads/{{ m[4] }}"></audio>
                                                {% else %}
                                                    <a href="/uploads/{{ m[4] }}" target="_blank" class="bg-black/30 hover:bg-black/50 p-2 rounded-lg text-[10px] font-bold flex items-center gap-1 my-1 text-yellow-300">
                                                        📄 View Document Attachment
                                                    </a>
                                                {% endif %}
                                            {% endif %}
                                            
                                            <span class="text-[8px] opacity-60 block text-right mt-1">{{ m[6] }}</span>
                                        </div>
                                    </div>
                                {% endfor %}
                            {% else %}
                                <p class="text-gray-500 italic text-center py-12">No messages exchanged yet.</p>
                            {% endif %}
                        </div>

                        <form action="/send-admin-chat" method="POST" enctype="multipart/form-data" class="space-y-2">
                            <input type="hidden" name="sub_admin_id" value="{{ target_sub }}">
                            <input type="hidden" name="sender_role" value="head_admin">
                            <div class="flex gap-2">
                                <input type="text" name="message_text" placeholder="Type reply message..." class="w-full p-2.5 bg-gray-900 border border-gray-700 rounded-xl text-white text-xs outline-none">
                                <button type="submit" class="bg-red-600 hover:bg-red-700 text-white font-black px-5 rounded-xl text-xs uppercase flex-shrink-0">Send →</button>
                            </div>
                            <div class="flex items-center gap-2">
                                <label class="text-[10px] text-gray-400 font-bold">Attach File/Media:</label>
                                <input type="file" name="attachment" class="text-[10px] text-gray-300 bg-gray-900 rounded-lg border border-gray-800 p-1 flex-1">
                            </div>
                        </form>
                        {% else %}
                        <div class="flex flex-col items-center justify-center h-full text-center space-y-2 text-gray-400">
                            <i class="fa-solid fa-comments text-4xl text-red-500"></i>
                            <p class="text-xs font-bold">Please select a Sub-Admin officer from left panel to open live messenger chat.</p>
                        </div>
                        {% endif %}
                    </div>
                </div>
            </div>
        </div>

    </div>

    <script>
        function switchAdminTab(tabId) {
            document.querySelectorAll('.tab-content').forEach(el => el.classList.remove('active'));
            document.querySelectorAll('.tab-btn').forEach(el => el.classList.remove('active'));
            document.getElementById(tabId).classList.add('active');
            document.getElementById('btn-' + tabId).classList.add('active');
        }
        
        if(window.location.hash === '#tab-chat' || window.location.search.includes('target_sub')) {
            switchAdminTab('tab-chat');
        }
    </script>
</body>
</html>
'''

SUB_ADMIN_DASHBOARD = '''
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Sub-Admin Dashboard - CyberShield</title>
    <script src="https://cdn.tailwindcss.com"></script>
    <link href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css" rel="stylesheet">
    <style>
        @keyframes fadeIn { from { opacity: 0; transform: translateY(15px); } to { opacity: 1; transform: translateY(0); } }
        .tab-content { display: none; }
        .tab-content.active { display: block; animation: fadeIn 0.4s ease-out forwards; }
        .tab-btn.active { background-color: #9333ea; color: #ffffff; border-color: #a855f7; box-shadow: 0 0 15px rgba(147, 51, 234, 0.5); }
    </style>
</head>
<body class="bg-gray-950 text-gray-100 p-4 md:p-8 font-sans min-h-screen flex flex-col justify-between">
    <div class="max-w-6xl mx-auto w-full space-y-6">
        
        <div class="bg-gradient-to-r from-purple-950 via-gray-900 to-gray-950 text-white p-6 rounded-3xl border-2 border-purple-600 flex justify-between items-center shadow-2xl">
            <div class="flex items-center gap-4">
                <div class="w-14 h-14 bg-purple-600 rounded-2xl flex items-center justify-center text-3xl font-black shadow-lg text-white border-2 border-white">
                    <i class="fa-solid fa-user-shield"></i>
                </div>
                <div>
                    <span class="bg-amber-400 text-purple-950 text-[10px] font-black px-3 py-1 rounded-full uppercase tracking-widest shadow">🛡️ SUB-ADMIN OFFICER</span>
                    <h2 class="text-2xl font-black mt-1 text-white tracking-tight">{{ sub_admin_name }}</h2>
                </div>
            </div>
            <a href="/logout" class="bg-red-600 hover:bg-red-700 text-white px-5 py-2.5 rounded-xl text-xs font-black shadow-lg transition transform hover:scale-105 border border-red-400">
                <i class="fa-solid fa-right-from-bracket mr-1"></i> LOGOUT
            </a>
        </div>

        <div class="grid grid-cols-1 md:grid-cols-3 gap-3 bg-gray-900 p-2 rounded-2xl border border-gray-800 shadow-xl">
            <button onclick="switchSubTab('tab-sub-complaints')" id="btn-tab-sub-complaints" class="tab-btn active bg-gray-800 hover:bg-gray-700 text-gray-300 font-black py-3.5 px-4 rounded-xl text-xs transition border border-transparent flex items-center justify-center gap-2">
                <i class="fa-solid fa-list-check text-sm"></i> 1. All Complaints Vault
            </button>
            <button onclick="switchSubTab('tab-sub-feedbacks')" id="btn-tab-sub-feedbacks" class="tab-btn bg-gray-800 hover:bg-gray-700 text-gray-300 font-black py-3.5 px-4 rounded-xl text-xs transition border border-transparent flex items-center justify-center gap-2">
                <i class="fa-solid fa-comments text-sm"></i> 2. Citizen Feedbacks
            </button>
            <button onclick="switchSubTab('tab-sub-help')" id="btn-tab-sub-help" class="tab-btn bg-gray-800 hover:bg-gray-700 text-gray-300 font-black py-3.5 px-4 rounded-xl text-xs transition border border-transparent flex items-center justify-center gap-2">
                <i class="fa-solid fa-headset text-sm text-yellow-400"></i> 3. Direct Head Admin Help
            </button>
        </div>

        <div id="tab-sub-complaints" class="tab-content active space-y-4">
            <div class="bg-white text-gray-950 p-6 md:p-8 rounded-3xl border-2 border-purple-500 shadow-2xl space-y-4">
                <div class="flex justify-between items-center border-b-2 border-purple-100 pb-4">
                    <h3 class="text-xl font-black text-purple-900 flex items-center gap-2"><i class="fa-solid fa-box-archive"></i> Section 1: Shared Citizen Complaints Queue</h3>
                    <span class="bg-purple-100 text-purple-900 px-3 py-1 rounded-full text-xs font-extrabold">Total: {{ cases|length }}</span>
                </div>

                {% if cases %}
                    <div class="space-y-4">
                    {% for item in cases %}
                        {% set c = item[0] %}
                        <div class="bg-slate-50 p-5 rounded-2xl border-2 border-purple-200 text-xs text-gray-900 space-y-3 shadow-md">
                            <div class="flex justify-between font-black text-purple-900 border-b border-purple-200 pb-2 text-sm">
                                <span>Case #{{ c[0] }} • Complainant: {{ c[2] }}</span>
                                <span class="bg-purple-700 text-white px-2.5 py-0.5 rounded-lg text-xs">Status: {{ c[18] }}</span>
                            </div>
                            <p class="text-gray-900 font-bold text-sm">{{ c[16] }}</p>
                            <p class="text-gray-700 leading-relaxed">{{ c[17] }}</p>

                            {% if c[19] %}
                            <div class="bg-purple-50 p-3 rounded-xl border border-purple-200 flex items-center justify-between">
                                <span class="font-extrabold text-purple-900">📷 Submitted Evidence Photo / Document:</span>
                                <a href="/uploads/{{ c[19] }}" target="_blank" class="bg-purple-700 hover:bg-purple-800 text-white font-black px-4 py-1.5 rounded-lg shadow text-xs flex items-center gap-1">
                                    View Evidence File 📁
                                </a>
                            </div>
                            {% endif %}
                            {% if c|length > 24 and c[24] %}
                            <div class="bg-cyan-50 p-3 rounded-xl border border-cyan-300 space-y-2"><p class="font-extrabold text-cyan-950">🎙️ Citizen voice complaint</p><audio controls preload="none" class="w-full" src="/uploads/{{ c[24] }}">Your browser does not support audio playback.</audio></div>
                            {% endif %}

                            <div class="bg-purple-50 p-3 rounded-xl border border-purple-300 flex justify-between items-center">
                                <span class="font-extrabold text-purple-900">💬 Citizen Complaint Remarks Window</span>
                                <a href="/subadmin-complaint-remark/{{ c[0] }}" class="bg-purple-700 hover:bg-purple-800 text-white font-black px-4 py-1.5 rounded-lg shadow text-xs">
                                    Open Citizen Remark Chat →
                                </a>
                            </div>

                            <form action="/update-status/{{ c[0] }}" method="POST" class="flex gap-2 pt-2 border-t border-purple-100">
                                <select name="status" class="p-2 bg-white rounded-xl border border-purple-300 font-bold text-gray-900 outline-none">
                                    <option value="Pending">Pending</option>
                                    <option value="Working...">Working...</option>
                                    <option value="Resolved">Resolved</option>
                                    <option value="Congratulations! (Case Solved)">Congratulations! (Case Solved)</option>
                                </select>
                                <button type="submit" class="bg-purple-700 hover:bg-purple-800 text-white px-5 py-2 rounded-xl font-black uppercase text-xs shadow">Update Status</button>
                            </form>
                        </div>
                    {% endfor %}
                    </div>
                {% else %}
                    <p class="text-gray-500 italic text-center py-8">No complaints available in queue.</p>
                {% endif %}
            </div>
        </div>

        <div id="tab-sub-feedbacks" class="tab-content space-y-4">
            <div class="bg-white text-gray-950 p-6 md:p-8 rounded-3xl border-2 border-purple-500 shadow-2xl space-y-4">
                <div class="flex justify-between items-center border-b-2 border-purple-100 pb-4">
                    <h3 class="text-xl font-black text-purple-900 flex items-center gap-2"><i class="fa-solid fa-comments"></i> Section 2: Citizen Feedbacks Queue</h3>
                    <span class="bg-purple-100 text-purple-900 px-3 py-1 rounded-full text-xs font-extrabold">Total: {{ feedbacks|length }}</span>
                </div>

                {% if feedbacks %}
                    <div class="grid grid-cols-1 md:grid-cols-2 gap-4">
                    {% for f in feedbacks %}
                        <div class="bg-slate-50 p-5 rounded-2xl border border-purple-200 text-xs space-y-2 shadow-sm">
                            <div class="flex justify-between font-black text-purple-900 text-sm">
                                <span><i class="fa-solid fa-user-circle mr-1"></i> {{ f[1] }}</span>
                                <span class="text-gray-400 text-[10px] font-normal">{{ f[4] }}</span>
                            </div>
                            <p class="text-gray-700 font-bold">Contact: <span class="text-purple-700">{{ f[2] }}</span></p>
                            <p class="text-gray-900 bg-white p-3 rounded-xl border border-gray-200 mt-2 font-medium leading-relaxed">{{ f[3] }}</p>
                        </div>
                    {% endfor %}
                    </div>
                {% else %}
                    <p class="text-gray-500 italic text-center py-8">No user feedbacks received yet.</p>
                {% endif %}
            </div>
        </div>

        <div id="tab-sub-help" class="tab-content space-y-4">
            <div class="bg-white text-gray-950 p-6 md:p-8 rounded-3xl border-2 border-purple-500 shadow-2xl space-y-6">
                <div class="border-b-2 border-purple-100 pb-4">
                    <h3 class="text-xl font-black text-purple-900 flex items-center gap-2"><i class="fa-solid fa-paper-plane"></i> Section 3: Direct Live Chat with Head Admin</h3>
                    <p class="text-xs text-gray-500 mt-1">Send messages, photos, videos, voice recordings, PDFs or document files directly to Head Officer</p>
                </div>

                <div class="bg-slate-900 text-white p-5 rounded-2xl border-2 border-purple-600 flex flex-col justify-between h-[480px]">
                    <div class="border-b border-gray-800 pb-2 mb-3 flex justify-between items-center">
                        <span class="font-black text-yellow-400 text-sm">💬 Head Admin Direct Helpdesk</span>
                        <a href="/sub-admin-dashboard#tab-sub-help" class="text-xs text-gray-400 hover:text-white">Refresh 🔄</a>
                    </div>

                    <div class="flex-1 overflow-y-auto space-y-3 p-2 bg-slate-950 rounded-xl mb-3 text-xs border border-gray-800">
                        {% if chat_msgs %}
                            {% for m in chat_msgs %}
                                <div class="flex flex-col {% if m[2] == 'sub_admin' %}items-end{% else %}items-start{% endif %}">
                                    <div class="max-w-xs md:max-w-md p-3 rounded-2xl shadow-md space-y-1 {% if m[2] == 'sub_admin' %}bg-purple-600 text-white rounded-br-none{% else %}bg-red-600 text-white rounded-bl-none border border-red-500{% endif %}">
                                        <span class="text-[9px] font-black opacity-75 block mb-0.5">{% if m[2] == 'sub_admin' %}Me (Sub-Admin){% else %}👑 Head Officer{% endif %}</span>
                                        
                                        {% if m[3] %}
                                        <p class="leading-relaxed font-medium">{{ m[3] }}</p>
                                        {% endif %}

                                        {% if m[4] %}
                                            {% if m[5] == 'image' %}
                                                <img src="/uploads/{{ m[4] }}" class="w-48 h-auto rounded-lg border border-white/20 my-1">
                                            {% elif m[5] == 'video' %}
                                                <video controls class="w-56 h-auto rounded-lg my-1"><source src="/uploads/{{ m[4] }}"></video>
                                            {% elif m[5] == 'audio' %}
                                                <audio controls class="w-full my-1"><source src="/uploads/{{ m[4] }}"></audio>
                                            {% else %}
                                                <a href="/uploads/{{ m[4] }}" target="_blank" class="bg-black/30 hover:bg-black/50 p-2 rounded-lg text-[10px] font-bold flex items-center gap-1 my-1 text-yellow-300">
                                                    📄 View Document Attachment
                                                </a>
                                            {% endif %}
                                        {% endif %}
                                        
                                        <span class="text-[8px] opacity-60 block text-right mt-1">{{ m[6] }}</span>
                                    </div>
                                </div>
                            {% endfor %}
                        {% else %}
                            <p class="text-gray-500 italic text-center py-12">No previous messages exchanged with Head Admin.</p>
                        {% endif %}
                    </div>

                    <form action="/send-admin-chat" method="POST" enctype="multipart/form-data" class="space-y-2">
                        <input type="hidden" name="sub_admin_id" value="{{ sub_admin_id }}">
                        <input type="hidden" name="sender_role" value="sub_admin">
                        <div class="flex gap-2">
                            <input type="text" name="message_text" placeholder="Type message for Head Admin..." class="w-full p-2.5 bg-gray-900 border border-gray-700 rounded-xl text-white text-xs outline-none">
                            <button type="submit" class="bg-purple-600 hover:bg-purple-700 text-white font-black px-5 rounded-xl text-xs uppercase flex-shrink-0">Send →</button>
                        </div>
                        <div class="flex items-center gap-2">
                            <label class="text-[10px] text-gray-400 font-bold">Attach Photo/Video/Audio/PDF:</label>
                            <input type="file" name="attachment" class="text-[10px] text-gray-300 bg-gray-900 rounded-lg border border-gray-800 p-1 flex-1">
                        </div>
                    </form>
                </div>
            </div>
        </div>

    </div>

    <script>
        function switchSubTab(tabId) {
            document.querySelectorAll('.tab-content').forEach(el => el.classList.remove('active'));
            document.querySelectorAll('.tab-btn').forEach(el => el.classList.remove('active'));
            document.getElementById(tabId).classList.add('active');
            document.getElementById('btn-' + tabId).classList.add('active');
        }
        
        if(window.location.hash === '#tab-sub-help') {
            switchSubTab('tab-sub-help');
        }
    </script>
</body>
</html>
'''

OFFICER_REMARK_CHAT_PAGE = '''
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8"><title>Officer Citizen Chat Remark Desk</title><script src="https://cdn.tailwindcss.com"></script>
    <link href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css" rel="stylesheet">
</head>
<body class="bg-gray-950 text-gray-100 p-4 md:p-8 font-sans min-h-screen">
    <div class="max-w-4xl mx-auto space-y-6">
        <div class="bg-gray-900 p-6 rounded-3xl border-2 border-red-500/80 flex justify-between items-center shadow-2xl">
            <div>
                <span class="bg-red-600 text-white text-[10px] font-black px-3 py-1 rounded-full uppercase">🛡️ Officer Remark Desk</span>
                <h2 class="text-xl font-black text-white mt-1">Case #{{ complaint[0] }} - {{ complaint[16] }}</h2>
                <p class="text-xs text-gray-400">Complainant: <strong class="text-yellow-300">{{ complaint[2] }}</strong> (Mob: {{ complaint[11] }})</p>
            </div>
            <a href="{{ return_url }}" class="bg-gray-800 hover:bg-gray-700 text-white px-4 py-2 rounded-xl text-xs font-bold border border-gray-700">
                ← Back to Dashboard
            </a>
        </div>

        <div class="bg-gray-900 p-6 rounded-3xl border border-gray-800 flex flex-col justify-between h-[500px]">
            <div class="flex-1 overflow-y-auto mb-4 p-3 bg-gray-950 rounded-2xl border border-gray-800 space-y-3 text-xs">
                {% if remarks %}
                    {% for r in remarks %}
                        <div class="flex flex-col {% if r[2] != 'citizen' %}items-end{% else %}items-start{% endif %}">
                            <div class="max-w-xs md:max-w-md p-3 rounded-2xl shadow-md space-y-1 {% if r[2] != 'citizen' %}bg-red-600 text-white rounded-br-none{% else %}bg-emerald-700 text-white rounded-bl-none border border-emerald-500{% endif %}">
                                <span class="text-[9px] font-black opacity-80 block">{{ r[3] }}</span>
                                {% if r[4] %}<p class="font-medium leading-relaxed">{{ r[4] }}</p>{% endif %}
                                {% if r[5] %}
                                    <a href="/uploads/{{ r[5] }}" target="_blank" class="block mt-1 bg-black/30 p-2 rounded-lg text-[10px] font-bold text-yellow-300">📁 Attached Media / File</a>
                                {% endif %}
                                <span class="text-[8px] opacity-60 block text-right mt-1">{{ r[6] }}</span>
                            </div>
                        </div>
                    {% endfor %}
                {% else %}
                    <p class="text-xs text-gray-500 italic text-center py-20">No remarks exchanged for this case yet.</p>
                {% endif %}
            </div>

            <form action="/send-complaint-remark" method="POST" enctype="multipart/form-data" class="space-y-2">
                <input type="hidden" name="complaint_id" value="{{ complaint[0] }}">
                <input type="hidden" name="sender_type" value="{{ role_type }}">
                <input type="hidden" name="sender_name" value="{{ role_name }}">
                <input type="hidden" name="redirect_back" value="{{ redirect_back }}">
                
                <div class="flex gap-2">
                    <input type="text" name="message" placeholder="Type official remark/reply for citizen..." class="w-full p-2.5 bg-gray-950 border border-gray-700 rounded-xl text-white text-xs outline-none font-medium">
                    <button type="submit" class="bg-red-600 hover:bg-red-700 text-white font-black px-6 rounded-xl text-xs uppercase flex-shrink-0">Send Unlimited →</button>
                </div>
                <div class="flex items-center gap-2">
                    <label class="text-[10px] text-gray-400 font-bold">Attach Photo/Document:</label>
                    <input type="file" name="attachment" class="text-[10px] text-gray-300 bg-gray-950 rounded-lg border border-gray-800 p-1 flex-1">
                </div>
            </form>
        </div>
    </div>
</body>
</html>
'''

LIVE_CHECKER_PAGE = '''
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Live URL & UPI Security Verification - CyberShield</title>
    <script src="https://cdn.tailwindcss.com"></script>
    <script src="https://cdn.jsdelivr.net/npm/jsqr@1.4.0/dist/jsQR.js"></script>
    <link href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css" rel="stylesheet">
</head>
<body class="bg-slate-950 text-gray-100 min-h-screen p-4 md:p-8 font-sans">
    <div class="max-w-4xl mx-auto space-y-6">
        <div class="flex justify-between items-center">
            <a href="/" class="bg-blue-600 hover:bg-blue-700 text-white px-4 py-2 rounded-xl text-xs font-bold transition flex items-center gap-2">
                <i class="fa-solid fa-house"></i> Back to Home
            </a>
            <span class="bg-yellow-400 text-blue-950 font-black px-3 py-1 rounded-full text-xs uppercase">
                🛡️ Local Heuristic Demo Scanner
            </span>
        </div>

        <div class="bg-gray-900 border-2 border-yellow-400/80 p-6 md:p-8 rounded-3xl shadow-2xl space-y-6">
            <div class="text-center space-y-2">
                <h2 class="text-2xl md:text-4xl font-black text-white">Local URL & UPI Risk Clue Checker</h2>
                <p class="text-xs text-gray-400">Advanced local heuristic demo: analyzes URL structure and risk clues without sending the URL to an external database.</p>
            </div>

            <div class="rounded-2xl border border-cyan-800 bg-cyan-950/30 p-5 text-center space-y-3">
                <h3 class="font-black text-cyan-200">📷 Scan a QR with your phone camera</h3>
                <p class="text-xs text-slate-300">The QR image is decoded in this browser. Its URL is analyzed locally; the image and URL are not uploaded.</p>
                <button type="button" id="start_qr_scan" class="rounded-xl bg-cyan-600 hover:bg-cyan-500 px-5 py-3 text-sm font-black text-white">Open Camera & Scan QR</button>
                <button type="button" id="stop_qr_scan" class="hidden rounded-xl bg-slate-700 hover:bg-slate-600 px-5 py-3 text-sm font-bold text-white">Stop Camera</button>
                <div id="qr_camera_wrap" class="hidden mx-auto max-w-md overflow-hidden rounded-xl border border-cyan-500/50"><video id="qr_camera" class="w-full" autoplay playsinline></video></div>
                <div id="qr_result" class="hidden break-all rounded-xl border border-slate-700 bg-slate-950 p-4 text-left text-xs"></div>
                <p class="text-[11px] text-amber-200">A QR scan can decode its contents, but cannot prove that a payment recipient or website is genuine. Verify the payee name in your payment app before paying.</p>
            </div>

            <div class="grid grid-cols-1 md:grid-cols-2 gap-6">
                <div class="bg-gray-950 p-5 rounded-2xl border border-gray-800 space-y-4">
                    <h3 class="text-base font-black text-yellow-300 flex items-center gap-2"><i class="fa-solid fa-link"></i> Check Suspicious Link / URL</h3>
                    <input type="text" id="check_url_input" placeholder="e.g. http://fake-lottery-claim.com" class="w-full p-3 bg-gray-900 rounded-xl border border-gray-700 text-xs text-white outline-none">
                    <button type="button" id="scan_url_button" onclick="window.analyzeUrl()" class="w-full bg-blue-600 hover:bg-blue-700 text-white py-3 rounded-xl font-bold text-xs uppercase">Scan Website URL →</button>
                    <div id="url_result" class="hidden p-3 rounded-xl text-xs font-bold"></div>
                </div>

                <div class="bg-gray-950 p-5 rounded-2xl border border-gray-800 space-y-4">
                    <h3 class="text-base font-black text-emerald-400 flex items-center gap-2"><i class="fa-solid fa-qrcode"></i> Check UPI VPA ID</h3>
                    <input type="text" id="check_upi_input" placeholder="e.g. fraudster@ybl" class="w-full p-3 bg-gray-900 rounded-xl border border-gray-700 text-xs text-white outline-none">
                    <button type="button" onclick="window.analyzeUpi()" class="w-full bg-emerald-600 hover:bg-emerald-700 text-white py-3 rounded-xl font-bold text-xs uppercase">Verify UPI ID →</button>
                    <div id="upi_result" class="hidden p-3 rounded-xl text-xs font-bold"></div>
                </div>
            </div>

            <section id="recovery_guide" class="hidden rounded-2xl border border-emerald-500/40 bg-emerald-950/30 p-5 text-sm text-slate-100" aria-live="polite">
                <p class="text-xs font-black uppercase tracking-widest text-emerald-300">Odia Scam Recovery Guide</p>
                <h3 id="recovery_title" class="mt-1 text-lg font-black text-white">Next steps</h3>
                <p id="recovery_intro" class="mt-2 text-xs text-slate-300"></p>
                <ol id="recovery_steps" class="mt-3 list-decimal space-y-2 pl-5 text-xs leading-relaxed"></ol>
                <div class="mt-4 flex flex-wrap gap-2">
                    <a href="tel:1930" class="rounded-xl bg-rose-600 px-4 py-2.5 text-xs font-black text-white hover:bg-rose-500">Call 1930 (financial cyber fraud)</a>
                    <a href="https://cybercrime.gov.in/" target="_blank" rel="noopener noreferrer" class="rounded-xl bg-blue-600 px-4 py-2.5 text-xs font-black text-white hover:bg-blue-500">Official cybercrime portal</a>
                </div>
                <p class="mt-3 border-t border-emerald-900 pt-3 text-[11px] text-amber-200">This checklist is general guidance. The scanner uses local clues only; it cannot confirm whether a link or payee is safe.</p>
            </section>
        </div>
    </div>

    <script>
        function showRecoveryGuide(kind, score = null) {
            const panel = document.getElementById('recovery_guide');
            const title = document.getElementById('recovery_title');
            const intro = document.getElementById('recovery_intro');
            const list = document.getElementById('recovery_steps');
            const scenarios = {
                url: {title: 'ଲିଙ୍କ୍‌ଟି ସନ୍ଦେହଜନକ ଲାଗିଲେ କ’ଣ କରିବେ', intro: 'ଏହି checker URLର local structural clues ବିଶ୍ଳେଷଣ କରେ। ଏହା live reputation database ନୁହେଁ, ତେଣୁ କମ୍ score ମିଳିଲେ ମଧ୍ୟ ସୁରକ୍ଷିତ ବୋଲି guarantee ନାହିଁ।', steps: ['ଅଜଣା ଲିଙ୍କ୍‌ରେ click କରନ୍ତୁନି; OTP, UPI PIN, password କିମ୍ବା bank details ଦିଅନ୍ତୁନି।', 'ଯଦି login details ଦେଇଦେଇଛନ୍ତି, official app/site ଖୋଲି password ବଦଳାନ୍ତୁ ଏବଂ bankକୁ ଜଣାନ୍ତୁ।', 'Message, sender details, URL ଓ transaction proofର screenshot ନିଜ ପାଖରେ ସୁରକ୍ଷିତ ରଖନ୍ତୁ; publicରେ sensitive details share କରନ୍ତୁନି।', 'ଟଙ୍କା କଟିଥିଲେ ତୁରନ୍ତ ୧୯୩୦କୁ call କରନ୍ତୁ ଏବଂ official portalରେ report କରନ୍ତୁ।']},
                upi: {title: 'UPI କିମ୍ବା QR payment ପାଇଁ ସୁରକ୍ଷିତ next steps', intro: 'UPI IDର format ଦେଖି recipientର ଅସଲ ପରିଚୟ କିମ୍ବା fraud history ନିଶ୍ଚିତ ହୁଏନି।', steps: ['Payment confirm ପୂର୍ବରୁ ନିଜ UPI appରେ ଦେଖାଯାଉଥିବା payee nameକୁ ଯାଞ୍ଚ କରନ୍ତୁ।', 'ଟଙ୍କା receive କରିବା ପାଇଁ UPI PIN ଦେବାକୁ ପଡ଼େନି; ଅଜଣା collect request approve କରନ୍ତୁନି।', 'Payment କରିଦେଇଥିଲେ transaction ID, time, amount ଓ screenshot ସୁରକ୍ଷିତ ରଖନ୍ତୁ।', 'ଅନଧିକୃତ ଟଙ୍କା କଟିଲେ ତୁରନ୍ତ ୧୯୩୦କୁ call କରନ୍ତୁ ଏବଂ bank/payment appକୁ official channelରେ report କରନ୍ତୁ।']},
                qr: {title: 'QR code ପାଇଁ ସୁରକ୍ଷିତ next steps', intro: 'QR scan କେବଳ content ପଢ଼େ; ଏହା payee କିମ୍ବା websiteକୁ genuine ବୋଲି ପ୍ରମାଣ କରେନି।', steps: ['QR ଭିତରେ ଥିବା linkକୁ ଖୋଲିବା ପୂର୍ବରୁ domain ଯାଞ୍ଚ କରନ୍ତୁ; payment ପୂର୍ବରୁ appରେ payee name ମେଳାନ୍ତୁ।', 'କାହାରି କଥାରେ OTP, UPI PIN, password ଦିଅନ୍ତୁନି; receive କରିବା ପାଇଁ PIN ଦରକାର ନାହିଁ।', 'Payment ହୋଇଗଲେ transaction reference ଓ messageର screenshot ରଖନ୍ତୁ।', 'ଠକେଇରେ ଟଙ୍କା ଯାଇଥିଲେ ତୁରନ୍ତ ୧୯୩୦କୁ call କରନ୍ତୁ ଏବଂ official portalରେ report କରନ୍ତୁ।']}
            };
            const data = scenarios[kind] || scenarios.url;
            title.textContent = data.title;
            intro.textContent = data.intro + (score !== null ? ' Heuristic score: ' + score + '/100; ଏହା ନିଶ୍ଚିତ scam verdict ନୁହେଁ।' : '');
            list.replaceChildren(...data.steps.map(step => { const li = document.createElement('li'); li.textContent = step; return li; }));
            panel.classList.remove('hidden');
            panel.scrollIntoView({behavior:'smooth', block:'nearest'});
        }

        window.analyzeUrl = function () {
            const input = document.getElementById('check_url_input');
            const result = document.getElementById('url_result');
            const raw = input.value.trim();
            result.classList.remove('hidden');
            while (result.firstChild) result.removeChild(result.firstChild);

            const add = (tag, text, className) => {
                const node = document.createElement(tag);
                node.textContent = text;
                if (className) node.className = className;
                result.appendChild(node);
                return node;
            };
            const showError = message => {
                result.className = 'p-4 rounded-xl text-xs font-bold bg-red-950 text-red-200 border border-red-500';
                add('p', message);
            };
            if (!raw) {
                showError('Enter a URL to scan.');
                input.focus();
                return;
            }
            if (raw.length > 2048 || /[\\u0000-\\u001f\\u007f\\\\]/.test(raw)) {
                showError('URL is too long or contains invalid control characters.');
                return;
            }
            if (/^(javascript|data|vbscript|file):/i.test(raw)) {
                showError('This link type is blocked. Only web URLs using HTTP or HTTPS can be checked.');
                return;
            }

            let url;
            try {
                url = new URL(/^https?:[/][/]/i.test(raw) ? raw : 'https://' + raw);
            } catch (_error) {
                showError('This does not look like a valid web URL. Check the spelling and try again.');
                return;
            }
            if (!['http:', 'https:'].includes(url.protocol) || !url.hostname || !url.hostname.includes('.')) {
                showError('Enter a complete public website domain, such as example.com.');
                return;
            }

            const host = url.hostname.toLowerCase().replace(/\.$/, '');
            const labels = host.split('.');
            const findings = [];
            let score = 0;
            const flag = (points, title, detail) => {
                score += points;
                findings.push({points, title, detail});
            };
            const ipv4 = host.match(/^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/);
            const isValidIPv4 = ipv4 && ipv4.slice(1).every(part => Number(part) <= 255);
            const knownShorteners = new Set(['bit.ly','t.co','tinyurl.com','goo.gl','ow.ly','is.gd','buff.ly','rebrand.ly','cutt.ly','tiny.cc','shorturl.at','lnkd.in']);
            const lureWords = ['account','bank','bonus','claim','confirm','crypto','gift','invoice','login','lottery','password','payment','prize','refund','reward','secure','signin','support','urgent','verify','wallet'];
            const brands = ['amazon','apple','facebook','google','instagram','microsoft','netflix','paypal','telegram','whatsapp'];
            const redirectKeys = /^(url|u|redirect|redirect_url|next|continue|return|returnurl|dest|destination|target|link|out|view)$/i;
            const levenshtein = (a, b) => {
                let prev = Array.from({length:b.length + 1}, (_, i) => i);
                for (let i = 1; i <= a.length; i++) {
                    const cur = [i];
                    for (let j = 1; j <= b.length; j++) cur[j] = Math.min(cur[j - 1] + 1, prev[j] + 1, prev[j - 1] + (a[i - 1] === b[j - 1] ? 0 : 1));
                    prev = cur;
                }
                return prev[b.length];
            };

            if (url.protocol === 'http:') flag(12, 'Unencrypted connection', 'The link uses HTTP, so traffic is not protected by HTTPS.');
            if (url.username || url.password) flag(24, 'Credentials embedded before the host', 'A URL such as trusted.example@other.example can disguise the real destination host.');
            if (isValidIPv4 || (host.startsWith('[') && host.endsWith(']'))) flag(18, 'Link uses a raw IP address', 'Public websites usually use a recognizable domain; verify the destination carefully.');
            if (host === 'localhost' || host.endsWith('.local') || host.endsWith('.internal') || host.endsWith('.test')) flag(20, 'Local or reserved hostname', 'This is not a normal public website domain.');
            if (labels.length >= 5) flag(12, 'Many subdomain levels', 'The long subdomain chain may hide the actual registered domain.');
            if (host.length > 45) flag(8, 'Unusually long hostname', 'Long hostnames can make deceptive names harder to notice.');
            if (labels.some(label => label.length > 30)) flag(8, 'Unusually long domain label', 'One part of the hostname is unusually long.');
            if (labels.some(label => label.startsWith('xn--'))) flag(18, 'Internationalized / punycode domain', 'Some lookalike characters may resemble ordinary letters. Inspect the domain carefully.');
            const hasScriptRange = (text, start, end) => Array.from(text).some(ch => { const cp = ch.codePointAt(0); return cp >= start && cp <= end; });
            const hasLatin = /[a-z]/i.test(host), hasCyrillic = hasScriptRange(host, 0x0400, 0x04ff), hasGreek = hasScriptRange(host, 0x0370, 0x03ff);
            if ((hasCyrillic || hasGreek) && hasLatin) flag(22, 'Mixed-script hostname', 'The hostname combines writing systems; some characters may visually imitate Latin letters.');
            else if (Array.from(host).some(ch => ch.codePointAt(0) > 0x7f) && !labels.some(label => label.startsWith('xn--'))) flag(12, 'Unicode hostname', 'International characters can be legitimate, but inspect the displayed domain carefully.');
            if (knownShorteners.has(host)) flag(12, 'Shortened link', 'The final destination is hidden until the link is expanded safely.');
            if (url.port && !['80','443'].includes(url.port)) flag(10, 'Non-standard web port', 'The link uses a port that ordinary public websites rarely need.');
            if (/(%[0-9a-f]{2}){3,}/i.test(raw) || /%25[0-9a-f]{2}/i.test(raw)) flag(10, 'Encoded URL content', 'Repeated or nested URL encoding can hide the intended destination.');
            if (url.href.length > 180) flag(7, 'Very long full URL', 'A long path or query makes the destination harder to inspect.');
            if (hasScriptRange(raw, 0x0590, 0x08ff) || hasScriptRange(raw, 0x2000, 0x206f)) flag(18, 'Non-Latin or direction-control characters', 'Special characters can make a link appear different from its true address.');
            const words = (host + url.pathname + url.search).toLowerCase().match(/[a-z]{4,}/g) || [];
            const matchedLures = [...new Set(words.filter(word => lureWords.some(lure => word.includes(lure))))];
            if (matchedLures.length) flag(Math.min(18, 6 + matchedLures.length * 3), 'Common scam lure wording', 'Found: ' + matchedLures.slice(0, 5).join(', ') + '. These words alone do not prove fraud.');
            if (Array.from(url.searchParams.keys()).some(key => redirectKeys.test(key))) flag(10, 'Possible redirect parameter', 'The link may send you onward to another destination after opening.');
            const twoPartPublicSuffixes = new Set(['co.uk','org.uk','ac.uk','gov.uk','com.au','net.au','org.au','co.nz','com.br','com.cn','com.sg','co.in','firm.in','net.in','org.in','gen.in','ind.in','co.jp','co.za','com.mx']);
            const lastTwoLabels = labels.slice(-2).join('.');
            const suffixLabelCount = twoPartPublicSuffixes.has(lastTwoLabels) ? 2 : 1;
            const registrableApprox = labels[Math.max(0, labels.length - suffixLabelCount - 1)] || '';
            const effectiveDomain = labels.slice(-Math.min(labels.length, suffixLabelCount + 1)).join('.');
            const brandMatch = brands.find(brand => {
                const compact = registrableApprox.replace(/[^a-z0-9]/g, '');
                return compact && compact !== brand && (compact.includes(brand) || (compact.length >= 5 && levenshtein(compact, brand) === 1));
            });
            if (brandMatch) flag(26, 'Possible brand lookalike', 'The registered-domain-like part resembles ' + brandMatch + ', but is not that exact brand name.');
            const brandInSubdomainOrPath = brands.find(brand => (labels.slice(0, -suffixLabelCount - 1).join('.') + url.pathname).toLowerCase().includes(brand) && !registrableApprox.toLowerCase().includes(brand));
            if (brandInSubdomainOrPath) flag(22, 'Brand name outside the registered domain', brandInSubdomainOrPath + ' appears in a subdomain or path, while the registered-domain-like part is ' + effectiveDomain + '.');
            const suspiciousTlds = new Set(['zip','mov','top','click','work','loan','gq','tk','ml','cf','rest','cfd','icu']);
            if (suspiciousTlds.has(labels[labels.length - 1])) flag(10, 'TLD often used in suspicious links', 'This ending can be used by legitimate sites too; treat it as one clue, not proof.');
            const domainChars = registrableApprox.toLowerCase().replace(/[^a-z0-9]/g, '');
            if (domainChars.length >= 13) {
                const counts = new Map();
                for (const ch of domainChars) counts.set(ch, (counts.get(ch) || 0) + 1);
                const entropy = [...counts.values()].reduce((sum, count) => { const p = count / domainChars.length; return sum - p * Math.log2(p); }, 0);
                if (entropy >= 3.65) flag(10, 'Random-looking registered domain', 'The domain label has unusually varied characters; this can occur in generated domains but is not conclusive.');
            }
            const digitCount = (registrableApprox.match(/\d/g) || []).length;
            if (registrableApprox.length >= 7 && digitCount / registrableApprox.length >= 0.35) flag(10, 'Many digits in domain name', 'Number-heavy domains can be disposable or deceptive; verify the exact owner and spelling.');
            if ((registrableApprox.match(/-/g) || []).length >= 2) flag(8, 'Several hyphens in domain name', 'Multiple hyphens can make an imitation domain harder to read.');
            if (labels.some(label => label.includes('-') && /\d/.test(label))) flag(7, 'Hyphen and digits in hostname', 'This combination can appear in throwaway or deceptive domains.');
            if (url.searchParams.size >= 8) flag(8, 'Unusually many URL parameters', 'A large set of query parameters can hide tracking or redirect behavior.');
            if (/\/https?:\/\//i.test(url.pathname) || /(?:redirect|continue|return|next)=https?%3a/i.test(raw)) flag(12, 'Nested URL or encoded redirect', 'A second URL appears inside this address; check the final destination before trusting it.');
            const pathExt = url.pathname.match(/\.(exe|apk|dmg|scr|bat|cmd|msi|zip|rar|iso)$/i);
            if (pathExt) flag(20, 'Downloadable or executable file path', 'Unexpected downloads can contain harmful files; do not open them casually.');

            score = Math.min(100, score);
            const level = score >= 60 ? 'High risk clues' : score >= 30 ? 'Some risk clues' : score > 0 ? 'A few risk clues' : 'No obvious heuristic flags';
            result.className = 'p-4 rounded-xl text-xs bg-slate-900 text-slate-100 border ' + (score >= 60 ? 'border-red-500' : score >= 30 ? 'border-amber-400' : 'border-cyan-700');
            add('p', level + ' · Heuristic score ' + score + '/100', 'text-base font-black ' + (score >= 60 ? 'text-red-300' : score >= 30 ? 'text-amber-300' : 'text-cyan-200'));
            add('p', 'Checked host: ' + host, 'mt-1 break-all text-slate-300');
            const meter = document.createElement('div');
            meter.className = 'mt-3 h-2 overflow-hidden rounded-full bg-slate-700';
            const fill = document.createElement('div');
            fill.className = 'h-full rounded-full ' + (score >= 60 ? 'bg-red-500' : score >= 30 ? 'bg-amber-400' : 'bg-cyan-400');
            fill.style.width = score + '%';
            meter.appendChild(fill);
            result.appendChild(meter);
            if (findings.length) {
                const list = document.createElement('ul');
                list.className = 'mt-3 space-y-2';
                findings.forEach(item => {
                    const li = document.createElement('li');
                    li.className = 'rounded-lg bg-black/20 p-2';
                    const title = document.createElement('strong');
                    title.textContent = item.title + ' (+' + item.points + ')';
                    const detail = document.createElement('span');
                    detail.className = 'block mt-1 font-normal text-slate-300';
                    detail.textContent = item.detail;
                    li.append(title, detail);
                    list.appendChild(li);
                });
                result.appendChild(list);
            } else {
                add('p', 'No common suspicious pattern was found by these local checks.', 'mt-3');
            }
            add('p', 'Advanced local heuristic only; it does not query a live threat database. A low score does not prove the site is safe. Never enter passwords, OTPs, or payment details from an unexpected link.', 'mt-3 border-t border-slate-700 pt-3 font-normal text-amber-200');
            showRecoveryGuide('url', score);
        }

        window.analyzeUpi = function () {
            let val = document.getElementById('check_upi_input').value.trim();
            let res = document.getElementById('upi_result');
            res.classList.remove('hidden');
            if(!val) { res.className = 'p-3 rounded-xl text-xs font-bold bg-amber-900/80 text-amber-200 border border-amber-500'; res.textContent = 'Enter a UPI ID to check its format.'; document.getElementById('check_upi_input').focus(); return; }
            const valid = /^[a-zA-Z0-9._-]{2,256}@[a-zA-Z0-9]{2,64}$/.test(val);
            res.className = 'p-3 rounded-xl text-xs font-bold ' + (valid ? 'bg-slate-800 text-slate-200 border border-slate-600' : 'bg-amber-900/80 text-amber-200 border border-amber-500');
            res.textContent = valid ? 'Format looks plausible, but this demo cannot verify the account holder or fraud history. Confirm the recipient in your payment app before paying.' : '⚠️ This does not look like a standard UPI ID format. Do not pay until you verify it.';
            showRecoveryGuide('upi');
        };


        // Camera QR scan uses browser APIs and local jsQR decoding; it never submits the image.
        (function () {
            const startBtn = document.getElementById('start_qr_scan');
            const stopBtn = document.getElementById('stop_qr_scan');
            const video = document.getElementById('qr_camera');
            const wrap = document.getElementById('qr_camera_wrap');
            const out = document.getElementById('qr_result');
            let stream = null, active = false, busy = false, detector = null;
            const stopCamera = () => {
                active = false;
                if (stream) stream.getTracks().forEach(track => track.stop());
                stream = null; video.srcObject = null; wrap.classList.add('hidden');
                stopBtn.classList.add('hidden'); startBtn.classList.remove('hidden');
            };
            stopBtn.addEventListener('click', stopCamera);
            startBtn.addEventListener('click', async () => {
                out.classList.remove('hidden'); out.textContent = 'Requesting camera permission…';
                if (!navigator.mediaDevices || !navigator.mediaDevices.getUserMedia) {
                    out.textContent = 'Camera scanning needs a supported browser and HTTPS (or localhost). You can still paste the QR contents into the checker.'; return;
                }
                try {
                    stream = await navigator.mediaDevices.getUserMedia({video:{facingMode:{ideal:'environment'}},audio:false});
                    video.srcObject = stream; await video.play();
                    wrap.classList.remove('hidden'); startBtn.classList.add('hidden'); stopBtn.classList.remove('hidden');
                    detector = ('BarcodeDetector' in window) ? new BarcodeDetector({formats:['qr_code']}) : null;
                    active = true; out.textContent = 'Point the camera at the QR code. Keep the whole code inside the frame.';
                    scanFrame();
                } catch (err) {
                    stopCamera(); out.classList.remove('hidden');
                    out.textContent = err && err.name === 'NotAllowedError' ? 'Camera permission was denied. Allow camera access in the browser and try again.' : 'Could not open the camera. Check that it is not being used by another app.';
                }
            });
            async function scanFrame() {
                if (!active) return;
                if (video.readyState >= 2 && !busy) {
                    busy = true;
                    try {
                        let payload = '';
                        if (detector) {
                            const codes = await detector.detect(video);
                            if (codes.length) payload = codes[0].rawValue || '';
                        } else if (window.jsQR) {
                            const canvas = document.createElement('canvas');
                            canvas.width = video.videoWidth; canvas.height = video.videoHeight;
                            const ctx = canvas.getContext('2d', {willReadFrequently:true});
                            ctx.drawImage(video, 0, 0, canvas.width, canvas.height);
                            const code = window.jsQR(ctx.getImageData(0, 0, canvas.width, canvas.height).data, canvas.width, canvas.height, {inversionAttempts:'attemptBoth'});
                            if (code) payload = code.data;
                        } else {
                            out.textContent = 'QR decoder could not load. Check internet access or paste the QR content manually.';
                        }
                        if (payload) { handleQrPayload(payload); stopCamera(); return; }
                    } catch (_e) { /* keep scanning the next camera frame */ }
                    busy = false;
                }
                if (active) requestAnimationFrame(scanFrame);
            }
            function handleQrPayload(payload) {
                out.classList.remove('hidden');
                out.textContent = 'QR content decoded: ' + payload;
                if (/^upi:\/\/pay(?:\?|$)/i.test(payload)) {
                    try {
                        const u = new URL(payload);
                        const pa = u.searchParams.get('pa') || '';
                        const pn = u.searchParams.get('pn') || '';
                        if (pa) {
                            document.getElementById('check_upi_input').value = pa;
                            window.analyzeUpi();
                            out.textContent = 'UPI QR decoded. Payee label: ' + (pn || '(not provided)') + '. VPA: ' + pa + '. The format check cannot confirm the recipient identity; confirm the payee inside your payment app before paying.';
                        }
                    } catch (_e) { /* show the decoded string without interpreting it */ }
                } else if (/^(https?:\/\/|www\.)/i.test(payload) || /^[a-z0-9.-]+\.[a-z]{2,}(?:\/|$)/i.test(payload)) {
                    document.getElementById('check_url_input').value = payload;
                    window.analyzeUrl();
                    out.textContent = 'QR link decoded and analyzed locally. Do not open it just because it was inside a QR code.';
                } else {
                    out.textContent = 'QR content decoded, but it is not a recognized web link or UPI payment link. Do not follow or share sensitive information based only on this code. Content: ' + payload;
                    showRecoveryGuide('qr');
                }
            }
        })();

        document.getElementById('check_url_input').addEventListener('keydown', e => { if (e.key === 'Enter') { e.preventDefault(); window.analyzeUrl(); } });
        document.getElementById('check_upi_input').addEventListener('keydown', e => { if (e.key === 'Enter') { e.preventDefault(); window.analyzeUpi(); } });
    </script>
</body>
</html>
'''

REGISTER_PAGE = '''
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Citizen Registration - CyberShield</title>
    <script src="https://cdn.tailwindcss.com"></script>
    <link href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css" rel="stylesheet">
</head>
<body class="bg-slate-100 text-gray-900 min-h-screen flex flex-col justify-between p-4">
    <div class="max-w-md mx-auto w-full pt-4 flex justify-between items-center">
        <a href="/" class="bg-white hover:bg-gray-50 text-blue-700 px-4 py-2 rounded-xl text-xs font-bold border shadow-md">
            <i class="fa-solid fa-house"></i> Home
        </a>
        <span class="bg-blue-600 text-white text-xs font-black px-3 py-1 rounded-full uppercase">🔒 Encrypted Registration</span>
    </div>

    <div class="max-w-md mx-auto w-full bg-white p-8 rounded-3xl my-auto shadow-2xl border border-blue-100 space-y-6">
        <div class="text-center space-y-1">
            <h2 class="text-2xl font-black text-blue-950">Citizen Registration</h2>
            <p class="text-xs text-gray-500">Create credentials to access cyber complaint filing</p>
        </div>

        {% if error %}
        <div class="bg-red-50 border border-red-200 text-red-600 p-3 rounded-xl text-xs font-bold text-center">
            {{ error }}
        </div>
        {% endif %}

        <form action="/register-action" method="POST" class="space-y-4 text-xs">
            <div>
                <label class="block font-bold text-gray-700 mb-1">Mobile Number *</label>
                <input type="text" name="mobile" required placeholder="Enter 10-digit mobile" class="w-full p-3 bg-gray-50 rounded-xl border border-gray-300 font-bold outline-none">
            </div>
            <div>
                <label class="block font-bold text-gray-700 mb-1">Password *</label>
                <input type="password" name="password" required placeholder="Create secure password" class="w-full p-3 bg-gray-50 rounded-xl border border-gray-300 font-bold outline-none">
            </div>
            <div class="bg-blue-50 p-4 rounded-2xl border border-blue-200 text-center space-y-2">
                <span class="text-blue-900 font-bold block">Security Captcha: {{ captcha_num1 }} + {{ captcha_num2 }} = ?</span>
                <input type="text" name="captcha_ans" required placeholder="Enter sum" class="w-full p-2.5 bg-white rounded-xl border border-blue-300 text-center font-black outline-none">
            </div>
            <button type="submit" class="w-full bg-blue-600 hover:bg-blue-700 text-white py-3.5 rounded-xl font-black shadow-xl uppercase">Register Account →</button>
        </form>
    </div>
</body>
</html>
'''

LOGIN_PAGE = '''
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Citizen Secure Login - CyberShield</title>
    <script src="https://cdn.tailwindcss.com"></script>
    <link href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css" rel="stylesheet">
</head>
<body class="bg-slate-100 text-gray-900 min-h-screen flex flex-col justify-between p-4">
    <div class="max-w-md mx-auto w-full pt-4 flex justify-between items-center">
        <a href="/" class="bg-white hover:bg-gray-50 text-blue-700 px-4 py-2 rounded-xl text-xs font-bold border shadow-md">
            <i class="fa-solid fa-house"></i> Home
        </a>
        <span class="bg-emerald-600 text-white text-xs font-black px-3 py-1 rounded-full uppercase">🔐 OTP Verification</span>
    </div>

    <div class="max-w-md mx-auto w-full bg-white p-8 rounded-3xl my-auto shadow-2xl border border-blue-100 space-y-6">
        <div class="text-center space-y-1">
            <h2 class="text-2xl font-black text-blue-950">Citizen Secure Login</h2>
            {% if selected_category %}
            <div class="bg-amber-50 border border-amber-300 p-2 rounded-xl text-[11px] text-amber-800 font-bold mt-2">📌 Target Category: {{ selected_category }}</div>
            {% endif %}
        </div>

        {% if error %}
        <div class="bg-red-50 border border-red-200 text-red-600 p-3 rounded-xl text-xs font-bold text-center">{{ error }}</div>
        {% endif %}

        {% if otp_sent %}
        <div class="bg-blue-50 p-4 rounded-2xl text-center border border-blue-200 space-y-1">
            <p class="text-xs font-bold text-blue-700">Simulated SMS Demo OTP:</p>
            <p class="text-amber-700 font-bold">DEMO ONLY — no SMS is sent. This code is shown for hackathon testing.</p><div class="text-3xl font-black text-blue-900 tracking-widest font-mono">{{ generated_otp }}</div>
        </div>
        <form action="/verify-otp-login" method="POST" class="space-y-4 text-xs">
            <input type="text" name="entered_otp" required maxlength="4" placeholder="••••" class="w-full p-3.5 bg-gray-50 rounded-xl border border-gray-300 text-center text-2xl font-black outline-none">
            <button type="submit" class="w-full bg-emerald-600 hover:bg-emerald-700 text-white py-3.5 rounded-xl font-black shadow-xl uppercase">Verify OTP →</button>
        </form>
        {% else %}
        <form action="/send-otp-login" method="POST" class="space-y-4 text-xs">
            <input type="text" name="mobile" required placeholder="Registered mobile number" class="w-full p-3 bg-gray-50 rounded-xl border border-gray-300 text-gray-900 font-bold outline-none">
            <input type="password" name="password" required placeholder="Account password" class="w-full p-3 bg-gray-50 rounded-xl border border-gray-300 text-gray-900 font-bold outline-none">
            <button type="submit" class="w-full bg-blue-600 hover:bg-blue-700 text-white py-3.5 rounded-xl font-black shadow-xl uppercase">Request OTP →</button>
        </form>
        {% endif %}
    </div>
</body>
</html>
'''

PROFILE_SETUP_PAGE = '''
<!DOCTYPE html>
<html lang="en">
<head><meta charset="UTF-8"><title>Profile Setup</title><script src="https://cdn.tailwindcss.com"></script></head>
<body class="bg-slate-100 text-gray-950 flex justify-center items-center min-h-screen p-4">
    <div class="bg-white p-8 rounded-3xl w-full max-w-xl shadow-2xl space-y-4 border border-blue-100">
        <h2 class="text-2xl font-black text-blue-950 text-center">Initial Citizen Verification</h2>
        <form action="/save-profile" method="POST" class="space-y-3 text-xs">
            <input type="text" name="fullname" required placeholder="Full Name" class="w-full p-3 bg-gray-50 rounded-xl border border-gray-300 font-bold">
            <input type="text" name="phone" required placeholder="Alternate Phone Number" class="w-full p-3 bg-gray-50 rounded-xl border border-gray-300 font-bold">
            <div class="grid grid-cols-1 sm:grid-cols-3 gap-2">
                <select name="district" required class="p-3 bg-gray-50 rounded-xl border border-gray-300 font-bold"><option value="" disabled selected>Select district</option>{% for district_name in districts %}<option value="{{ district_name }}">{{ district_name }}{% if district_name == 'Kendujhar' %} (Keonjhar){% elif district_name == 'Subarnapur' %} (Sonepur){% endif %}</option>{% endfor %}</select>
                <input type="text" name="block" required placeholder="Block" class="p-3 bg-gray-50 rounded-xl border border-gray-300 font-bold">
                <input type="text" name="panchayat" required placeholder="Panchayat / Village" class="p-3 bg-gray-50 rounded-xl border border-gray-300 font-bold">
            </div>
            <input type="text" name="pincode" required maxlength="6" placeholder="Pin Code" class="w-full p-3 bg-gray-50 rounded-xl border border-gray-300 font-bold">
            <button type="submit" class="w-full bg-blue-600 text-white py-3.5 rounded-xl font-black uppercase">Save Profile →</button>
        </form>
    </div>
</body>
</html>
'''

PROFILE_SAVED_PAGE = '''
<!DOCTYPE html>
<html lang="en">
<head><meta charset="UTF-8"><meta name="viewport" content="width=device-width, initial-scale=1.0"><title>Profile Saved | CyberShield</title><script src="https://cdn.tailwindcss.com"></script></head>
<body class="min-h-screen bg-slate-950 text-slate-100 flex items-center justify-center p-4">
<div class="w-full max-w-2xl rounded-3xl border border-emerald-500/30 bg-slate-900 p-7 md:p-10 shadow-2xl">
  <div class="text-center mb-8"><div class="mx-auto mb-4 grid h-16 w-16 place-items-center rounded-full bg-emerald-500/15 text-4xl">✓</div>
    <p class="text-xs uppercase tracking-[.25em] text-emerald-300 font-black">Registration complete</p>
    <h1 class="mt-2 text-3xl font-black text-white">Congratulations, {{ profile[2] }}!</h1>
    <p class="mt-2 text-sm text-slate-400">Your citizen profile has been saved. No complaint has been filed.</p>
  </div>
  <section class="rounded-2xl border border-slate-700 bg-slate-950/70 p-5">
    <h2 class="mb-4 text-sm font-black uppercase tracking-wide text-cyan-300">Saved citizen details</h2>
    <dl class="grid grid-cols-1 sm:grid-cols-2 gap-3 text-sm">
      <div class="rounded-xl bg-slate-900 p-3"><dt class="text-xs text-slate-400">Full name</dt><dd class="mt-1 font-semibold">{{ profile[2] }}</dd></div>
      <div class="rounded-xl bg-slate-900 p-3"><dt class="text-xs text-slate-400">Registered mobile</dt><dd class="mt-1 font-semibold">{{ profile[1] }}</dd></div>
      <div class="rounded-xl bg-slate-900 p-3"><dt class="text-xs text-slate-400">Alternate phone</dt><dd class="mt-1 font-semibold">{{ profile[7] }}</dd></div>
      <div class="rounded-xl bg-slate-900 p-3"><dt class="text-xs text-slate-400">District</dt><dd class="mt-1 font-semibold">{{ profile[3] }}</dd></div>
      <div class="rounded-xl bg-slate-900 p-3"><dt class="text-xs text-slate-400">Block</dt><dd class="mt-1 font-semibold">{{ profile[4] }}</dd></div>
      <div class="rounded-xl bg-slate-900 p-3"><dt class="text-xs text-slate-400">Panchayat / Village</dt><dd class="mt-1 font-semibold">{{ profile[5] }}</dd></div>
      <div class="rounded-xl bg-slate-900 p-3"><dt class="text-xs text-slate-400">PIN code</dt><dd class="mt-1 font-semibold">{{ profile[6] }}</dd></div>
    </dl>
  </section>
  <a href="/" class="mt-6 block w-full rounded-xl bg-gradient-to-r from-emerald-600 to-cyan-600 px-5 py-3.5 text-center font-black text-white shadow-lg transition hover:-translate-y-0.5 hover:brightness-110">Go to Home</a>
</div>
</body></html>
'''

DASHBOARD_PAGE = '''
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8"><title>Citizen Dashboard</title><script src="https://cdn.tailwindcss.com"></script>
    <link href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css" rel="stylesheet">
    <link rel="stylesheet" href="https://unpkg.com/leaflet@1.9.4/dist/leaflet.css" />
    <script src="https://unpkg.com/leaflet@1.9.4/dist/leaflet.js"></script>
</head>
<body class="bg-gray-100 text-gray-900 p-4 md:p-6 font-sans">
    <div class="max-w-5xl mx-auto space-y-6">
        <div class="bg-blue-900 text-white p-6 rounded-3xl flex justify-between items-center shadow-xl">
            <div>
                <h2 class="text-xl font-black">Citizen Operations Dashboard</h2>
                <p class="text-xs text-blue-200">Registered Mobile: <strong class="text-yellow-300">{{ mobile }}</strong></p>
            </div>
            <div class="flex gap-2">
                <a href="/track-status-view" class="bg-emerald-600 hover:bg-emerald-500 text-white px-4 py-2 rounded-xl text-xs font-bold transition">Check Status & Remarks 🔍</a>
                <a href="/logout" class="bg-red-600 hover:bg-red-700 text-white px-4 py-2 rounded-xl text-xs font-bold transition">Logout</a>
            </div>
        </div>

        <div class="bg-white p-6 md:p-8 rounded-3xl border border-gray-200 shadow-2xl space-y-6">
            <h3 class="text-lg font-black text-gray-900">Cyber Incident Demo Form</h3>
            <form id="complaint-draft-form" action="/submit-complaint" method="POST" enctype="multipart/form-data" class="space-y-4 text-xs">
                <div class="rounded-xl border border-amber-300 bg-amber-50 p-3 text-amber-950"><p class="font-bold">Draft auto-saves in this browser</p><p class="mt-1">Use only on a trusted device. Evidence files and voice recordings are not saved in the draft.</p><div class="mt-2 flex items-center gap-3"><span id="draft-save-status" class="text-[11px]">Draft not saved yet.</span><button type="button" id="clear-complaint-draft" class="rounded-lg border border-amber-500 px-3 py-1.5 font-bold hover:bg-amber-100">Clear saved draft</button></div></div>
                <div>
                    <label class="block text-gray-700 font-bold mb-1">Complainant Full Name *</label>
                    <input type="text" name="complainant_name" value="{{ profile[2] }}" required class="w-full p-3 bg-gray-50 border border-gray-300 rounded-xl font-bold">
                </div>

                <div class="grid grid-cols-1 md:grid-cols-2 gap-4">
                    <input type="text" name="father_name" required placeholder="Father's Name" class="p-3 bg-gray-50 border border-gray-300 rounded-xl">
                    <input type="text" name="mother_name" required placeholder="Mother's Name" class="p-3 bg-gray-50 border border-gray-300 rounded-xl">
                </div>

                <div class="grid grid-cols-1 md:grid-cols-2 gap-4">
                    <input type="date" name="dob" required class="p-3 bg-gray-50 border border-gray-300 rounded-xl">
                    <select id="form_district" name="district" required class="p-3 bg-gray-50 border border-gray-300 rounded-xl">{% for district_name in districts %}<option value="{{ district_name }}" {% if profile_district == district_name %}selected{% endif %}>{{ district_name }}{% if district_name == 'Kendujhar' %} (Keonjhar){% elif district_name == 'Subarnapur' %} (Sonepur){% endif %}</option>{% endfor %}</select>
                </div>

                <div class="grid grid-cols-1 md:grid-cols-3 gap-4">
                    <input type="text" id="form_block" name="block" value="{{ profile[4] }}" required class="p-3 bg-gray-50 border border-gray-300 rounded-xl">
                    <input type="text" id="form_panchayat" name="panchayat" value="{{ profile[5] }}" required class="p-3 bg-gray-50 border border-gray-300 rounded-xl">
                    <input type="text" name="active_mobile" value="{{ mobile }}" required class="p-3 bg-gray-50 border border-gray-300 rounded-xl font-bold">
                    <input type="email" name="contact_email" required maxlength="254" autocomplete="email" placeholder="Your email address for complaint confirmation" class="p-3 bg-gray-50 border border-gray-300 rounded-xl font-bold">
                </div>

                <textarea name="permanent_address" rows="2" required placeholder="Permanent Address..." class="w-full p-3 bg-gray-50 border border-gray-300 rounded-xl"></textarea>

                <div class="bg-blue-50 p-4 rounded-2xl border border-blue-200 space-y-3">
                    <div class="flex justify-between items-center">
                        <label class="block text-blue-950 font-black text-sm">Present Location Real GPS Auto Detect</label>
                        <button type="button" onclick="autoDetectRealGPSLocation()" class="bg-blue-600 hover:bg-blue-700 text-white font-bold px-4 py-2 rounded-xl text-xs shadow-lg transition">
                            Auto-Detect Real GPS 📍
                        </button>
                    </div>
                    <textarea id="present_address" name="present_address" rows="2" required placeholder="Press button to detect exact real location..." class="w-full p-3 bg-white border border-gray-300 rounded-xl font-bold text-xs"></textarea>
                    <input type="hidden" id="gps_lat" name="gps_lat">
                    <input type="hidden" id="gps_lon" name="gps_lon">

                    <p class="text-[11px] text-gray-600">GPS is an estimate. Check the accuracy below, drag the map pin to the right place if needed, and edit the address manually.</p>
                    <div id="map_card_box" class="hidden bg-white p-3 rounded-xl border border-blue-300 text-center space-y-2">
                        <p class="text-xs font-bold text-gray-700">📍 Your estimated location — drag the pin to correct it:</p>
                        <p id="gps_accuracy_status" class="rounded-lg bg-slate-100 p-2 text-xs font-bold text-slate-700" aria-live="polite"></p>
                        <div id="live_leaflet_map" class="w-full h-48 rounded-xl border-2 border-red-500"></div>
                        <p class="text-[11px] text-gray-600">The mapped address may be approximate. Confirm the place before submitting.</p>
                    </div>
                </div>

                <input type="text" name="title" value="{{ auto_title }}" required class="w-full p-3 bg-blue-50 border border-blue-400 font-bold rounded-xl text-blue-950">
                <textarea name="description" rows="3" placeholder="Type the incident details, or record them in your voice below..." class="w-full p-3 bg-gray-50 border border-gray-300 rounded-xl"></textarea>
                <section class="rounded-2xl border-2 border-cyan-300 bg-slate-950 p-4 text-white space-y-3" aria-labelledby="voice-title">
                    <div><h4 id="voice-title" class="font-black text-cyan-200 text-sm">🎙️ Voice Complaint (optional)</h4><p class="mt-1 text-xs text-slate-300">If typing is difficult, record the incident details here. You can listen before submitting. Maximum 3 minutes; recording is sent with this complaint for authorized Head Admin/Sub-Admin review.</p></div>
                    <input id="voice_recording" type="file" name="voice_recording" accept="audio/*" class="hidden">
                    <div class="flex flex-wrap gap-2">
                        <button id="start-voice-recording" type="button" class="rounded-xl bg-emerald-600 px-4 py-2.5 font-bold hover:bg-emerald-500">● Start recording</button>
                        <button id="stop-voice-recording" type="button" disabled class="rounded-xl bg-rose-700 px-4 py-2.5 font-bold disabled:opacity-40">■ Stop</button>
                        <button id="clear-voice-recording" type="button" class="rounded-xl border border-slate-500 px-4 py-2.5 font-bold hover:bg-slate-800">Remove recording</button>
                    </div>
                    <p id="voice-recording-status" class="text-xs text-cyan-100" aria-live="polite">Microphone permission is needed when you start recording.</p>
                    <audio id="voice-recording-preview" class="hidden w-full" controls></audio>
                    <p class="text-[11px] text-amber-200">Only record information relevant to this report. The audio is stored with the demo case and can be heard by authorized admins.</p>
                </section>
                <input type="file" name="evidence" class="w-full p-2 bg-gray-50 border border-gray-300 rounded-xl">

                <button type="submit" class="w-full bg-blue-700 hover:bg-blue-800 text-white py-4 rounded-xl font-black shadow-xl uppercase">Submit Complaint →</button>
            </form>
        </div>
    </div>

    <script>
        let realMap = null;
        let realMarker = null;

        async function setAddressFromCoordinates(lat, lon) {
            const addr = document.getElementById('present_address');
            const latField = document.getElementById('gps_lat');
            const lonField = document.getElementById('gps_lon');
            latField.value = Number(lat).toFixed(6);
            lonField.value = Number(lon).toFixed(6);
            try {
                const response = await fetch(`https://nominatim.openstreetmap.org/reverse?format=jsonv2&lat=${encodeURIComponent(lat)}&lon=${encodeURIComponent(lon)}`);
                if (!response.ok) throw new Error('Reverse geocoding unavailable');
                const data = await response.json();
                addr.value = (data && data.display_name ? data.display_name + ' · ' : 'Mapped address unavailable · ') + `GPS pin: ${Number(lat).toFixed(6)}, ${Number(lon).toFixed(6)}`;
            } catch (_error) {
                addr.value = `Address lookup unavailable · GPS pin: ${Number(lat).toFixed(6)}, ${Number(lon).toFixed(6)}. You can edit this address manually.`;
            }
        }

        function autoDetectRealGPSLocation() {
            let addr = document.getElementById('present_address');
            let latField = document.getElementById('gps_lat');
            let lonField = document.getElementById('gps_lon');
            let mapBox = document.getElementById('map_card_box');

            if ("geolocation" in navigator) {
                addr.value = "📍 Connecting to GPS Satellites for Real-Time Location...";
                
                const gpsOptions = {
                    enableHighAccuracy: true,
                    timeout: 15000,
                    maximumAge: 0
                };

                navigator.geolocation.getCurrentPosition(
                    async (pos) => {
                        const lat = pos.coords.latitude;
                        const lon = pos.coords.longitude;
                        const accuracy = Number.isFinite(pos.coords.accuracy) ? Math.round(pos.coords.accuracy) : null;
                        const accuracyStatus = document.getElementById('gps_accuracy_status');
                        latField.value = lat.toFixed(6);
                        lonField.value = lon.toFixed(6);
                        accuracyStatus.textContent = accuracy === null
                            ? 'GPS accuracy was not provided. Check the pin and address manually.'
                            : `Estimated accuracy: ±${accuracy.toLocaleString()} metres. This is an estimate, not a guarantee.`;
                        accuracyStatus.className = 'rounded-lg p-2 text-xs font-bold ' + (accuracy === null || accuracy > 1000 ? 'bg-rose-100 text-rose-800' : accuracy > 100 ? 'bg-amber-100 text-amber-900' : 'bg-emerald-100 text-emerald-900');

                        mapBox.classList.remove('hidden');
                        await setAddressFromCoordinates(lat, lon);

                        if (!realMap) {
                            realMap = L.map('live_leaflet_map').setView([lat, lon], 16);
                            L.tileLayer('https://{s}.tile.openstreetmap.org/{z}/{x}/{y}.png', {
                                maxZoom: 19,
                                attribution: '© OpenStreetMap'
                            }).addTo(realMap);
                            realMarker = L.marker([lat, lon], {draggable:true}).addTo(realMap)
                                .bindPopup('<b>Location pin — drag to adjust</b>').openPopup();
                            realMarker.on('dragend', async (event) => {
                                const point = event.target.getLatLng();
                                accuracyStatus.textContent = 'Pin adjusted manually. Updating the mapped address…';
                                await setAddressFromCoordinates(point.lat, point.lng);
                                accuracyStatus.textContent = 'Pin adjusted manually. GPS accuracy does not apply to this manual adjustment; please confirm the address.';
                                accuracyStatus.className = 'rounded-lg bg-blue-100 p-2 text-xs font-bold text-blue-900';
                            });
                        } else {
                            realMap.setView([lat, lon], 16);
                            realMarker.setLatLng([lat, lon]);
                            accuracyStatus.className = 'rounded-lg p-2 text-xs font-bold ' + (accuracy === null || accuracy > 1000 ? 'bg-rose-100 text-rose-800' : accuracy > 100 ? 'bg-amber-100 text-amber-900' : 'bg-emerald-100 text-emerald-900');
                        }
                        setTimeout(() => realMap.invalidateSize(), 100);
                    },
                    (err) => {
                        alert("⚠️ GPS Access Denied or Unavailable! Please enable Location Services / GPS in your Mobile/Browser settings.");
                        addr.value = "GPS access denied. Please type present address manually.";
                    },
                    gpsOptions
                );
            } else {
                alert("Geolocation is not supported by your browser.");
            }
        }
    </script>

<script>
(function(){
  const form=document.getElementById('complaint-draft-form');
  const input=document.getElementById('voice_recording');
  const start=document.getElementById('start-voice-recording');
  const stop=document.getElementById('stop-voice-recording');
  const clear=document.getElementById('clear-voice-recording');
  const status=document.getElementById('voice-recording-status');
  const preview=document.getElementById('voice-recording-preview');
  if(!form||!input)return;
  let recorder=null,stream=null,chunks=[],previewUrl=null,timer=null,seconds=0;
  const MAX_SECONDS=180, MAX_AUDIO_BYTES=6*1024*1024;
  const formatTime=n=>String(Math.floor(n/60)).padStart(2,'0')+':'+String(n%60).padStart(2,'0');
  function releaseStream(){if(stream){stream.getTracks().forEach(track=>track.stop());stream=null;}}
  function clearRecording(){
    if(recorder&&recorder.state!=='inactive'){recorder.onstop=null;recorder.stop();}
    clearInterval(timer);timer=null;releaseStream();recorder=null;chunks=[];input.value='';
    if(previewUrl){URL.revokeObjectURL(previewUrl);previewUrl=null;}
    preview.removeAttribute('src');preview.classList.add('hidden');start.disabled=false;stop.disabled=true;
    status.textContent='Recording removed. You can record again.';
  }
  if(!navigator.mediaDevices||!navigator.mediaDevices.getUserMedia||!window.MediaRecorder){
    start.disabled=true;status.textContent='Audio recording is not supported in this browser. Try a recent Chrome or Edge browser.';
  }
  start.addEventListener('click',async()=>{
    try{
      stream=await navigator.mediaDevices.getUserMedia({audio:true});
      const types=['audio/webm;codecs=opus','audio/ogg;codecs=opus','audio/mp4'];
      const mime=types.find(t=>MediaRecorder.isTypeSupported(t));
      recorder=mime?new MediaRecorder(stream,{mimeType:mime}):new MediaRecorder(stream);
      chunks=[];seconds=0;
      recorder.ondataavailable=e=>{if(e.data&&e.data.size)chunks.push(e.data);};
      recorder.onerror=()=>{status.textContent='Recording failed. Check microphone permission and try again.';releaseStream();start.disabled=false;stop.disabled=true;};
      recorder.onstop=()=>{
        clearInterval(timer);timer=null;releaseStream();stop.disabled=true;start.disabled=false;
        const blob=new Blob(chunks,{type:recorder.mimeType||'audio/webm'});
        if(!blob.size){status.textContent='No audio was captured. Please record again.';return;}
        if(blob.size>MAX_AUDIO_BYTES){input.value='';status.textContent='Recording exceeds 6 MB. Please make a shorter recording.';return;}
        const type=blob.type.toLowerCase();
        const ext=type.includes('ogg')?'ogg':(type.includes('mp4')?'m4a':'webm');
        const file=new File([blob],'voice-complaint.'+ext,{type:blob.type});
        try{const transfer=new DataTransfer();transfer.items.add(file);input.files=transfer.files;}
        catch(_e){status.textContent='This browser cannot attach the recording. Please use the file picker or a recent Chrome/Edge browser.';return;}
        if(previewUrl)URL.revokeObjectURL(previewUrl);
        previewUrl=URL.createObjectURL(blob);preview.src=previewUrl;preview.classList.remove('hidden');
        status.textContent='Recording ready ('+formatTime(seconds)+'). Listen to it, then submit the complaint.';
      };
      recorder.start();start.disabled=true;stop.disabled=false;
      status.textContent='Recording… '+formatTime(seconds)+' / 03:00';
      timer=setInterval(()=>{seconds++;status.textContent='Recording… '+formatTime(seconds)+' / 03:00';if(seconds>=MAX_SECONDS&&recorder&&recorder.state==='recording')recorder.stop();},1000);
    }catch(_e){releaseStream();status.textContent='Microphone permission denied or unavailable. Allow microphone access and try again.';}
  });
  stop.addEventListener('click',()=>{if(recorder&&recorder.state==='recording')recorder.stop();});
  clear.addEventListener('click',clearRecording);
  form.addEventListener('reset',()=>{if(recorder&&recorder.state!=='inactive')clearRecording();else{input.value='';if(previewUrl)URL.revokeObjectURL(previewUrl);previewUrl=null;preview.removeAttribute('src');preview.classList.add('hidden');}});
  form.addEventListener('submit',e=>{if(recorder&&recorder.state==='recording'){e.preventDefault();status.textContent='Stop the recording before submitting.';}});
  window.addEventListener('beforeunload',releaseStream);
})();
</script>

<script>
(function(){
  const form=document.getElementById('complaint-draft-form'); if(!form)return;
  const owner={{ mobile|tojson }};
  const key='cybershield:complaint-draft:v1:'+owner;
  const status=document.getElementById('draft-save-status'); let timer=null;
  const controls=Array.from(form.querySelectorAll('input[name],textarea[name],select[name]')).filter(x=>x.type!=='file'&&x.type!=='submit'&&x.type!=='button');
  function save(){
    const data={}; controls.forEach(el=>{if(el.type==='checkbox'||el.type==='radio'){if(el.checked)data[el.name]=el.value;}else data[el.name]=el.value;});
    try{localStorage.setItem(key,JSON.stringify({savedAt:Date.now(),data}));status.textContent='Draft saved on this device at '+new Date().toLocaleTimeString();}catch(e){status.textContent='Could not save draft in this browser.';}
  }
  try{const raw=localStorage.getItem(key);if(raw){const saved=JSON.parse(raw);if(saved&&saved.data){controls.forEach(el=>{if(!(el.name in saved.data))return;if(el.type==='checkbox'||el.type==='radio')el.checked=saved.data[el.name]===el.value;else if(!el.value)el.value=saved.data[el.name];});status.textContent='Saved draft restored from this browser.';}}}catch(e){status.textContent='Saved draft could not be read.';}
  form.addEventListener('input',()=>{clearTimeout(timer);timer=setTimeout(save,500);});
  form.addEventListener('change',()=>{clearTimeout(timer);timer=setTimeout(save,200);});
  document.getElementById('clear-complaint-draft').addEventListener('click',()=>{localStorage.removeItem(key);form.reset();status.textContent='Saved draft cleared.';});
  form.addEventListener('submit',()=>{localStorage.removeItem(key);});
})();
</script>

</body>
</html>
'''

SUB_ADMIN_LOGIN_PAGE = '''
<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Sub-Admin Secure Access</title><script src="https://cdn.tailwindcss.com"></script>
<style>*{box-sizing:border-box}body{margin:0;background:#030712;color:#e5e7eb;font-family:Inter,system-ui,sans-serif;overflow-x:hidden}.gridbg{position:fixed;inset:0;opacity:.18;background-image:linear-gradient(#22d3ee22 1px,transparent 1px),linear-gradient(90deg,#22d3ee22 1px,transparent 1px);background-size:42px 42px;mask-image:linear-gradient(to bottom,black,transparent)}.orb{position:fixed;width:320px;height:320px;border-radius:50%;filter:blur(90px);opacity:.18;animation:drift 9s ease-in-out infinite alternate}.orb.a{background:#06b6d4;top:-120px;left:-90px}.orb.b{background:#8b5cf6;right:-130px;bottom:-130px;animation-delay:-3s}@keyframes drift{to{transform:translate(55px,40px) scale(1.2)}}@keyframes rise{from{opacity:0;transform:translateY(18px) scale(.98)}to{opacity:1;transform:none}}@keyframes pulse{50%{box-shadow:0 0 28px #22d3ee44}}.card{animation:rise .65s ease-out both,pulse 4s ease-in-out 1s infinite;background:linear-gradient(145deg,#111827f5,#080f1df5);border:1px solid #164e63;box-shadow:0 24px 80px #0009,inset 0 1px #ffffff0a}.field{background:#030712;border:1px solid #253449;transition:.2s}.field:focus{border-color:#22d3ee;box-shadow:0 0 0 3px #22d3ee20;outline:0}.btn{background:linear-gradient(100deg,#0891b2,#2563eb);transition:.2s}.btn:hover{filter:brightness(1.15);transform:translateY(-1px)}.scan{height:2px;background:#22d3ee;box-shadow:0 0 12px #22d3ee;position:absolute;left:0;right:0;top:0;animation:scan 4s linear infinite;opacity:.65}@keyframes scan{0%{top:0}100%{top:100%}}</style></head>
<body class="min-h-screen flex items-center justify-center p-5"><div class="gridbg"></div><div class="orb a"></div><div class="orb b"></div><main class="card relative overflow-hidden rounded-3xl w-full max-w-md p-7 sm:p-9"><div class="scan"></div><div class="text-center mb-7"><div class="mx-auto mb-4 grid h-16 w-16 place-items-center rounded-2xl border border-cyan-400/40 bg-cyan-400/10 text-3xl">🛡️</div><p class="text-[10px] tracking-[.35em] text-cyan-300 font-bold">CYBERSHIELD • FIELD ACCESS</p><h1 class="mt-2 text-2xl font-black text-white">Sub-Admin Login</h1><p class="mt-2 text-xs text-slate-400">Secure gateway for authorized officers</p></div>
{% if error %}<div class="mb-4 rounded-xl border border-rose-500/40 bg-rose-950/60 px-4 py-3 text-xs text-rose-200">{{ error }}</div>{% endif %}<form action="/sub-admin-login-action" method="POST" class="space-y-4" {% if lock_seconds %}data-lock-seconds="{{ lock_seconds }}"{% endif %}>
<label class="block text-xs font-semibold text-slate-300">Officer ID<input name="sub_admin_id" value="{{ login_id }}" autocomplete="username" required class="field mt-2 w-full rounded-xl px-4 py-3 text-sm text-white" placeholder="Enter your officer ID"></label><label class="block text-xs font-semibold text-slate-300">Password<input type="password" name="password" autocomplete="current-password" required class="field mt-2 w-full rounded-xl px-4 py-3 text-sm text-white" placeholder="Enter password"></label>
<div class="rounded-xl border border-cyan-900 bg-cyan-950/30 p-4"><label class="block text-xs font-semibold text-cyan-100">Security check <span class="ml-1 text-cyan-300">{{ captcha_a }} + {{ captcha_b }} = ?</span><input name="captcha_answer" inputmode="numeric" required class="field mt-2 w-full rounded-lg px-4 py-3 text-sm text-white" placeholder="Solve the quick check"></label></div>
{% if lock_seconds %}<p class="lock-message rounded-lg bg-amber-950/50 p-3 text-center text-xs text-amber-200">Too many failed attempts. Try again in <b class="timer">03:00</b>.</p>{% endif %}<button class="btn w-full rounded-xl py-3.5 font-bold text-white disabled:cursor-not-allowed disabled:opacity-50" type="submit" {% if lock_seconds %}disabled{% endif %}>Authenticate securely →</button></form><p class="mt-6 text-center text-[10px] text-slate-500"><a href="/" class="hover:text-cyan-300">← Back to portal</a> · Demo project access</p></main>
<script>(function(){const f=document.querySelector('form[data-lock-seconds]');if(!f)return;let n=Number(f.dataset.lockSeconds),t=f.querySelector('.timer'),b=f.querySelector('button');const tick=()=>{if(n<=0){t.textContent='00:00';b.disabled=false;f.querySelector('.lock-message').textContent='You can try again now.';return}t.textContent=String(Math.floor(n/60)).padStart(2,'0')+':'+String(n%60).padStart(2,'0');n--;setTimeout(tick,1000)};tick()})();</script></body></html>
'''

ADMIN_LOGIN_PAGE = '''
<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Head Admin Secure Access</title><script src="https://cdn.tailwindcss.com"></script>
<style>*{box-sizing:border-box}body{margin:0;background:#030712;color:#e5e7eb;font-family:Inter,system-ui,sans-serif;overflow:hidden}.gridbg{position:fixed;inset:0;opacity:.2;background-image:linear-gradient(#22d3ee22 1px,transparent 1px),linear-gradient(90deg,#22d3ee22 1px,transparent 1px);background-size:42px 42px;mask-image:radial-gradient(ellipse at center,black,transparent 75%)}.orb{position:fixed;width:340px;height:340px;border-radius:50%;filter:blur(100px);opacity:.17;animation:drift 10s ease-in-out infinite alternate}.orb.a{background:#06b6d4;top:-140px;left:-100px}.orb.b{background:#7c3aed;right:-140px;bottom:-140px;animation-delay:-4s}@keyframes drift{to{transform:translate(60px,50px) scale(1.18)}}@keyframes rise{from{opacity:0;transform:translateY(20px) scale(.98)}to{opacity:1;transform:none}}@keyframes glow{50%{box-shadow:0 0 32px #22d3ee22,0 25px 90px #0009}}@keyframes scan{0%{top:0}100%{top:100%}}.card{animation:rise .65s ease-out both,glow 4s ease-in-out 1s infinite;background:linear-gradient(145deg,#111827f5,#080f1df5);border:1px solid #164e63;box-shadow:0 25px 90px #0009}.field{background:#030712;border:1px solid #263449;transition:.2s}.field:focus{border-color:#22d3ee;box-shadow:0 0 0 3px #22d3ee20;outline:0}.btn{background:linear-gradient(100deg,#0891b2,#4f46e5);transition:.2s}.btn:hover{filter:brightness(1.17);transform:translateY(-1px)}.scan{height:2px;background:#22d3ee;box-shadow:0 0 14px #22d3ee;position:absolute;left:0;right:0;top:0;animation:scan 4s linear infinite;opacity:.6}</style></head>
<body class="min-h-screen flex items-center justify-center p-5"><div class="gridbg"></div><div class="orb a"></div><div class="orb b"></div><main class="card relative overflow-hidden rounded-3xl w-full max-w-md p-7 sm:p-9"><div class="scan"></div><div class="text-center mb-7"><div class="mx-auto mb-4 grid h-16 w-16 place-items-center rounded-2xl border border-cyan-400/40 bg-cyan-400/10 text-3xl">🛡️</div><p class="text-[10px] tracking-[.35em] text-cyan-300 font-bold">CYBERSHIELD • CONTROL ROOM</p><h1 class="mt-2 text-2xl font-black text-white">Head Admin Login</h1><p class="mt-2 text-xs text-slate-400">Privileged access · monitored session</p></div>
{% if error %}<div class="mb-4 rounded-xl border border-rose-500/40 bg-rose-950/60 px-4 py-3 text-xs text-rose-200">{{ error }}</div>{% endif %}<form action="/admin-login-action" method="POST" class="space-y-4" {% if lock_seconds %}data-lock-seconds="{{ lock_seconds }}"{% endif %}>
<label class="block text-xs font-semibold text-slate-300">Admin ID<input type="text" name="admin_num" value="{{ login_id }}" autocomplete="username" required class="field mt-2 w-full rounded-xl px-4 py-3 text-sm text-white" placeholder="Enter admin ID"></label><label class="block text-xs font-semibold text-slate-300">Password<input type="password" name="admin_pass" autocomplete="current-password" required class="field mt-2 w-full rounded-xl px-4 py-3 text-sm text-white" placeholder="Enter password"></label>
<div class="rounded-xl border border-cyan-900 bg-cyan-950/30 p-4"><label class="block text-xs font-semibold text-cyan-100">Security check <span class="ml-1 text-cyan-300">{{ captcha_a }} + {{ captcha_b }} = ?</span><input name="captcha_answer" inputmode="numeric" required class="field mt-2 w-full rounded-lg px-4 py-3 text-sm text-white" placeholder="Solve the quick check"></label></div>
{% if lock_seconds %}<p class="lock-message rounded-lg bg-amber-950/50 p-3 text-center text-xs text-amber-200">Too many failed attempts. Try again in <b class="timer">03:00</b>.</p>{% endif %}<button class="btn w-full rounded-xl py-3.5 font-bold text-white disabled:cursor-not-allowed disabled:opacity-50" type="submit" {% if lock_seconds %}disabled{% endif %}>Enter control room →</button></form><p class="mt-6 text-center text-[10px] text-slate-500"><a href="/" class="hover:text-cyan-300">← Back to portal</a> · Authorized demo access only</p></main>
<script>(function(){const f=document.querySelector('form[data-lock-seconds]');if(!f)return;let n=Number(f.dataset.lockSeconds),t=f.querySelector('.timer'),b=f.querySelector('button');const tick=()=>{if(n<=0){t.textContent='00:00';b.disabled=false;f.querySelector('.lock-message').textContent='You can try again now.';return}t.textContent=String(Math.floor(n/60)).padStart(2,'0')+':'+String(n%60).padStart(2,'0');n--;setTimeout(tick,1000)};tick()})();</script></body></html>
'''

POLICY_PAGE_TEMPLATE = '''<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8"><meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{{ title }} | CyberShield Portal</title>
    <meta name="description" content="{{ summary }}">
    <script src="https://cdn.tailwindcss.com"></script>
    <link href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css" rel="stylesheet">
</head>
<body class="min-h-screen bg-slate-950 text-slate-100">
    <header class="border-b border-slate-800 bg-slate-900/80">
        <div class="mx-auto flex max-w-5xl items-center justify-between gap-4 px-5 py-4">
            <a href="/" class="flex items-center gap-3 font-black tracking-wide text-white"><span class="grid h-10 w-10 place-items-center rounded-xl bg-yellow-400 text-slate-950"><i class="fa-solid fa-shield-halved"></i></span><span>CyberShield <span class="text-yellow-400">Portal</span></span></a>
            <a href="/" class="rounded-lg border border-slate-700 px-4 py-2 text-xs font-bold text-slate-200 transition hover:border-yellow-400 hover:text-yellow-300"><i class="fa-solid fa-arrow-left mr-2"></i>Back to Home</a>
        </div>
    </header>
    <main class="mx-auto max-w-5xl px-4 py-10 md:px-6 md:py-14">
        <div class="mb-8 rounded-3xl border border-blue-400/20 bg-gradient-to-br from-blue-950 via-slate-900 to-slate-900 p-7 shadow-2xl md:p-10">
            <div class="mb-4 inline-flex items-center gap-2 rounded-full border border-yellow-400/30 bg-yellow-400/10 px-3 py-1.5 text-[11px] font-black uppercase tracking-[0.18em] text-yellow-300"><i class="fa-solid fa-file-shield"></i> CyberShield information</div>
            <h1 class="text-3xl font-black leading-tight text-white md:text-5xl">{{ title }}</h1>
            <p class="mt-4 max-w-3xl text-sm leading-7 text-slate-300 md:text-base">{{ summary }}</p>
            <div class="mt-6 flex flex-wrap items-center gap-3 text-xs text-slate-400"><span><i class="fa-regular fa-calendar mr-2 text-yellow-400"></i>Last reviewed: October 20, 2026</span><button onclick="window.print()" class="rounded-lg bg-slate-800 px-3 py-2 font-bold text-slate-200 transition hover:bg-slate-700 print:hidden"><i class="fa-solid fa-print mr-2"></i>Print this page</button></div>
        </div>
        {% if notice %}<div class="mb-7 rounded-2xl border border-amber-400/30 bg-amber-400/10 p-5 text-sm leading-7 text-amber-100"><i class="fa-solid fa-triangle-exclamation mr-2 text-amber-300"></i>{{ notice|safe }}</div>{% endif %}
        <div class="space-y-5">{% for section in sections %}<section class="rounded-2xl border border-slate-800 bg-slate-900/70 p-6 shadow-lg md:p-8"><h2 class="mb-4 flex items-start gap-3 text-lg font-black text-yellow-300 md:text-xl"><span class="mt-1 text-blue-400"><i class="fa-solid fa-angle-right"></i></span>{{ section[0] }}</h2><div class="policy-copy space-y-4 text-sm leading-7 text-slate-300">{{ section[1]|safe }}</div></section>{% endfor %}</div>
        <nav class="mt-8 rounded-2xl border border-slate-800 bg-slate-900 p-5 print:hidden" aria-label="Other policies"><p class="mb-3 text-xs font-black uppercase tracking-widest text-slate-400">Read the other pages</p><div class="flex flex-wrap gap-3"><a href="/disclaimer-page" class="rounded-lg bg-slate-800 px-3 py-2 text-xs font-bold hover:text-yellow-300">Disclaimer</a><a href="/website-policies" class="rounded-lg bg-slate-800 px-3 py-2 text-xs font-bold hover:text-yellow-300">Website Policies &amp; Terms</a><a href="/privacy-policy" class="rounded-lg bg-slate-800 px-3 py-2 text-xs font-bold hover:text-yellow-300">Privacy Policy</a></div></nav>
        <p class="mt-8 text-center text-[11px] leading-6 text-slate-500">CyberShield Portal is an independent project. This information page does not make the site an official government service. <a class="text-slate-300 underline hover:text-yellow-300" href="mailto:sashikantamohanty797@gmail.com">Contact the site developer</a>.</p>
    </main>
    <footer class="border-t border-slate-800 py-5 text-center text-[11px] text-slate-500">© 2026 CyberShield Portal · <a href="/" class="hover:text-yellow-300">Home</a></footer>
</body>
</html>'''

DISCLAIMER_SECTIONS = [
    ("1. Who operates this website", "<p>CyberShield Portal is an independent student/developer project created for learning, demonstration and general public awareness. It is not owned, operated, authorised, sponsored or endorsed by the Government of India, the Government of Odisha, the Indian Cyber Crime Coordination Centre (I4C), the National Cyber Crime Reporting Portal, any police department, or any court. The name, design, sample dashboard figures, notices and role labels on this site must not be taken as proof of government affiliation or official authority.</p><p>This website is not the official National Cyber Crime Reporting Portal. You can reach the Government of India portal at <a class='text-yellow-300 underline' href='https://cybercrime.gov.in/' target='_blank' rel='noopener noreferrer'>cybercrime.gov.in</a>.</p>"),
    ("2. Not an official complaint channel", "<p>A form submission, message, account entry, status view or document generated here does not by itself register a complaint with the police, create an FIR, preserve evidence with an authority, start an investigation, or guarantee that any public authority will receive or act on it. Do not rely on this project for urgent reporting or legal deadlines.</p><p>If you have suffered cybercrime, report it through the official National Cyber Crime Reporting Portal or contact the national cybercrime helpline at <strong class='text-white'>1930</strong>, especially for online financial fraud. Use local police or emergency services where immediate help is needed. Official reporting links: <a class='text-yellow-300 underline' href='https://cybercrime.gov.in/' target='_blank' rel='noopener noreferrer'>cybercrime.gov.in</a>.</p>"),
    ("3. General information only", "<p>Articles, notices, FAQs, generated forms, sample text, analytics, status labels and other material are provided for general information and demonstration. They are not legal, financial, forensic, law-enforcement or professional advice. Laws and procedures can change, and a general explanation may not fit your situation. Obtain advice from a qualified professional or the relevant authority before acting on a serious matter.</p><p>Any generated FIR-style document or draft is only a user-prepared document. It is not an FIR, police record, official certificate, evidence verification or proof that an authority has accepted a report.</p>"),
    ("4. Accuracy, availability and response", "<p>The developer makes reasonable efforts to keep information understandable, but does not promise that every page, notice, count, link, translation or generated output is complete, current, error-free or suitable for your particular purpose. A displayed complaint count or status is based on this application's own database and is not an official government statistic.</p><p>The website may be changed, interrupted, unavailable, or discontinued. A message or feedback form is not an emergency service and may not receive an immediate response. No response should be interpreted as acceptance, rejection or official action on a complaint.</p>"),
    ("5. User-submitted material", "<p>You are responsible for the accuracy and lawfulness of information you submit. Submit only information you are entitled to provide. Do not upload malware, threats, unlawful material, unrelated personal information, or another person's sensitive details unless you have lawful authority to do so. Do not use this site to harass, impersonate, threaten or make knowingly false allegations.</p><p>Submitting material here does not make it confidential or guarantee that it will be preserved as evidence. Do not use this demonstration project to store evidence that must be securely preserved or to disclose passwords, banking credentials, OTPs, payment card details, or unnecessary identity documents.</p>"),
    ("6. External websites and third-party services", "<p>This website may link to government portals, social networks, email providers, content delivery networks or other third-party services. Those services operate under their own terms and privacy practices. The developer does not control their availability, content, security or handling of information, and a link does not imply endorsement.</p>"),
    ("7. Limits and contact", "<p>To the extent permitted by applicable law, the developer is not responsible for loss caused by reliance on general information, service interruption, third-party websites, unauthorised access, user error or circumstances outside the developer's reasonable control. Nothing in this disclaimer excludes a right or responsibility that cannot lawfully be excluded.</p><p>For corrections or questions about this page, contact <a class='text-yellow-300 underline' href='mailto:sashikantamohanty797@gmail.com'>sashikantamohanty797@gmail.com</a>. This page is a general project draft and should be reviewed by a qualified lawyer before the website is used to handle real complaints or sensitive information.</p>")
]

TERMS_SECTIONS = [
    ("1. About these terms", "<p>These Website Policies &amp; Terms explain the basic rules for visiting and using CyberShield Portal. By using the site, you agree to use it lawfully and responsibly. If you do not agree, stop using it. These terms apply to the website and its demonstration features; mandatory rights under applicable law are not limited by this page.</p><p>CyberShield Portal is an independent educational/development project. It is not an official Government of India, Odisha Government, police, I4C or National Cyber Crime Reporting Portal service. A submission here is not an official complaint or FIR.</p>"),
    ("2. Who may use the site", "<p>You may browse public information and use available forms only where you are legally able to do so. If you submit information for another person, you must have proper authority and must ensure the information is accurate. A parent or lawful guardian should assist a minor where required. Do not create an account using someone else's mobile number or identity.</p>"),
    ("3. Acceptable use", "<p>You agree not to: (a) submit information you know is false or misleading; (b) threaten, defame, harass, impersonate or unlawfully target anyone; (c) upload malicious code, scripts or files; (d) probe, disrupt, overload or bypass access controls; (e) use the site to commit fraud or violate another person's rights; or (f) attempt to access another user's account, complaint, evidence or messages.</p><p>The developer may restrict access to content or accounts reasonably believed to be abusive, unlawful, harmful to the service, or inconsistent with these terms, subject to applicable law.</p>"),
    ("4. Accounts, passwords and demo features", "<p>You are responsible for keeping account details private and for activity performed through your account. Do not share passwords or OTPs. Tell the developer if you believe an account has been accessed without permission.</p><p><strong class='text-amber-200'>Important for this current build:</strong> CyberShield is a project/demo application and has not been confirmed as production-secure. Do not submit real complaint narratives, addresses, GPS coordinates, identity documents, passwords or evidence until the operator has secured and reviewed the deployment. Some features may be demonstrations and may not send an official report or notification.</p>"),
    ("5. Content and uploads", "<p>You retain whatever rights you have in material you submit. You give the site operator permission to store and display that material within the application as needed to provide the feature you chose, such as showing a complaint to an administrator or displaying a message in a case conversation. Do not submit content you have no right to share. Uploaded files may be subject to technical limits and may not be preserved permanently.</p><p>The developer does not promise to investigate, verify, remove, preserve or act on every submission. This is not an evidence-custody service. For official reporting, use the National Cyber Crime Reporting Portal at <a class='text-yellow-300 underline' href='https://cybercrime.gov.in/' target='_blank' rel='noopener noreferrer'>cybercrime.gov.in</a> or call 1930 for online financial fraud.</p>"),
    ("6. Intellectual property and third-party links", "<p>Unless stated otherwise, the website's original code, layout and branding are provided by their respective rights holders. You may not copy or use them in a way that falsely suggests endorsement or official status. Third-party names, logos, links, libraries and services belong to their owners and may be governed by separate terms.</p>"),
    ("7. Availability, changes and liability", "<p>The site is provided as available and may be modified, suspended or discontinued. The developer does not guarantee uninterrupted service, data preservation, a particular result, or that displayed material is error-free. To the extent permitted by law, the developer is not liable for indirect loss arising from use of this independent demo. Nothing in these terms excludes liability or rights that applicable law does not allow to be excluded.</p><p>These terms may be updated when the project changes. The review date at the top indicates the date this page was last reviewed; check this page again before continued use.</p>"),
    ("8. Questions and governing law", "<p>Questions or concerns can be sent to <a class='text-yellow-300 underline' href='mailto:sashikantamohanty797@gmail.com'>sashikantamohanty797@gmail.com</a>. These draft terms are intended to be read consistently with applicable laws of India. Any dispute, venue or remedy is subject to applicable law and the jurisdiction of competent authorities or courts. Have a qualified lawyer review these terms before public or production use.</p>")
]

PRIVACY_SECTIONS = [
    ("1. Who is responsible for information", "<p>For this project, the person operating the particular deployment controls how information submitted to that deployment is used. The site is an independent project and is not operated by a government department or the National Cyber Crime Reporting Portal. Privacy questions or requests can be sent to <a class='text-yellow-300 underline' href='mailto:sashikantamohanty797@gmail.com'>sashikantamohanty797@gmail.com</a>.</p>"),
    ("2. Information the application may collect", "<p>Depending on which feature you use, the current application code can collect or store: mobile number and account password; profile name, phone number, district, block, panchayat and PIN code; complaint details such as names, date of birth, contact number, addresses, district/block/panchayat, location coordinates, title and description; evidence files you upload, including optional complaint voice recordings; case remarks and attachments; chat messages; and feedback name, contact details and message. Information you type into a generated form may also appear in the document generated for you.</p><p>The application may also process technical information required to run the site, such as session data, request information, timestamps and server logs, depending on the hosting provider and configuration. The website loads some front-end assets from third-party content delivery services; your browser may contact those providers when a page loads.</p>"),
    ("3. Why the information is used", "<p>The application uses submitted details to create and manage demo accounts, display a user profile, accept complaint drafts, show case status within this site's own database, exchange case remarks, administer the site, respond to feedback, prevent misuse, and maintain or troubleshoot the project. Information is not proof that an official authority has received a complaint.</p><p>The code reviewed for this policy does not show a payment feature or an advertising profile. Hosting, email, backup, analytics or other services added by an operator may involve additional processing and should be described here before they are enabled.</p>"),
    ("4. Where information is stored and who can see it", "<p>In the reviewed build, application records are stored in a local SQLite database named <code class='rounded bg-slate-800 px-1.5 py-0.5 text-yellow-200'>cyber_portal.db</code>, and uploaded files are placed in an application uploads folder. Server administrators with access to the hosting environment and authorised application administrators may be able to view information needed to operate the site. Newly uploaded evidence, voice recordings and chat files require an authenticated, authorized download; notice images are public. The deployment's hosting provider may also process data as part of hosting, security, backups or maintenance.</p><p>This remains a hackathon prototype and has not had an independent production security review. The updated build hashes account passwords, checks complaint ownership and gates uploaded files, but those controls do not establish production readiness. <strong class='text-amber-200'>Do not submit real identity documents, financial information, GPS details or sensitive complaint evidence until deployment, access policies, storage and operations receive a full security review.</strong> This notice is included to avoid giving a false impression of confidentiality or security.</p>"),
    ("5. Sharing and disclosure", "<p>The public home page displays aggregate complaint counts by Odisha district only; it does not display complainant names, contact details, complaint narratives, evidence or precise locations. The reviewed application code does not show an automatic connection that forwards complaints to the police or the official cybercrime portal. A complaint submitted here stays within this application's own storage unless the operator separately accesses, exports or shares it. The operator should only disclose information where necessary to run the requested feature, respond to a valid legal requirement, protect people or the service, or with the user's direction, and should explain any additional sharing introduced by deployment or integrations.</p><p>External links and content delivery providers have their own privacy policies. When you follow an external link, that provider's practices apply.</p>"),
    ("6. Retention, correction and deletion", "<p>The current code does not define a complete automatic retention schedule or a self-service delete tool. Information may remain in the local database or uploads folder until the operator removes it, the application is reset, or hosting backups expire. Do not treat the site as a permanent evidence archive.</p><p>You may email the developer to ask what information is held about you, to request correction or deletion, or to withdraw a permission where applicable. Include enough information for the operator to locate the record, but do not email passwords, OTPs or unnecessary sensitive evidence. The operator may need to verify your identity and may retain information where required to address security, legal or operational needs. Applicable legal rights are not reduced by this paragraph.</p>"),
    ("7. Children, security incidents and updates", "<p>This project is not designed to collect children's information. A parent or lawful guardian should contact the operator if a child has submitted personal information. The operator should take reasonable steps to assess and respond to a suspected unauthorised disclosure, subject to applicable law; this demo policy does not promise a particular response time or guarantee that a breach cannot happen.</p><p>This policy may change when the code or hosting changes. The last-reviewed date appears above. The Digital Personal Data Protection Act, 2023 and the Digital Personal Data Protection Rules, 2025 are official Indian references; this page is a project draft and does not certify legal compliance. Read the <a class='text-yellow-300 underline' href='https://www.meity.gov.in/content/digital-personal-data-protection-act-2023-dpdp-act' target='_blank' rel='noopener noreferrer'>official Act</a> and <a class='text-yellow-300 underline' href='https://www.meity.gov.in/documents/act-and-policies/digital-personal-data-protection-rules-2025-gDOxUjMtQWa?pageTitle=Digital-Personal-Data-Protection-Rules-2025' target='_blank' rel='noopener noreferrer'>official Rules</a>.</p>")
]

@app.route('/disclaimer-page')
def disclaimer_page():
    return render_template_string(POLICY_PAGE_TEMPLATE, title='Disclaimer', summary='Understand what CyberShield Portal is, what it is not, and where to report cybercrime officially.', notice='CyberShield Portal is an independent project, not a government reporting service. For an actual cybercrime report, use <a href="https://cybercrime.gov.in/" class="underline font-bold" target="_blank" rel="noopener noreferrer">cybercrime.gov.in</a> or call <strong>1930</strong> for online financial fraud.', sections=DISCLAIMER_SECTIONS)

@app.route('/website-policies')
def website_policies():
    return render_template_string(POLICY_PAGE_TEMPLATE, title='Website Policies & Terms', summary='The rules for responsible use of this independent CyberShield project and its demonstration features.', notice='This website is not an official complaint channel. Do not submit sensitive real-world complaint information until the deployment has been securely reviewed.', sections=TERMS_SECTIONS)

@app.route('/privacy-policy')
def privacy_policy():
    return render_template_string(POLICY_PAGE_TEMPLATE, title='Privacy Policy', summary='Learn what information this application may collect, how the current build stores it, and how to contact the operator.', notice='Security note: the reviewed build stores account passwords without safe hashing and does not restrict uploaded files per user. Do not submit real sensitive information until those issues are fixed.', sections=PRIVACY_SECTIONS)

@app.route('/')
def home():
    notice_text = get_setting('notice_text')
    notice_photo1 = get_setting('notice_photo1')
    notice_photo2 = get_setting('notice_photo2')
    feedback_sent = session.pop('feedback_sent', False)
    return render_template_string(HOME_PAGE, stats=get_live_analytics(), district_counts=get_district_report_counts(), notice_text=notice_text, notice_photo1=notice_photo1, notice_photo2=notice_photo2, feedback_sent=feedback_sent)

@app.route('/fir-generator')
def fir_generator():
    return render_template_string(FIR_GENERATOR_FORM_PAGE)

@app.route('/generate-fir-pdf', methods=['POST'])
def generate_fir_pdf():
    data = request.form.to_dict()
    now_str = datetime.now().strftime('%d-%m-%Y')
    return render_template_string(FIR_PDF_TEMPLATE, data=data, now_date=now_str, demo_draft=True)

@app.route('/track-status-login')
def track_status_login():
    return render_template_string(TRACK_STATUS_LOGIN_PAGE)

@app.route('/track-status-login-action', methods=['POST'])
def track_status_login_action():
    mobile = request.form.get('mobile', '').strip()
    password = request.form.get('password', '').strip()
    
    conn = sqlite3.connect(DATABASE_PATH)
    cursor = conn.cursor()
    cursor.execute("SELECT id, password FROM users WHERE mobile = ?", (mobile,))
    user = cursor.fetchone()
    ok, migrate = verify_password(user[1], password) if user else (False, False)
    if ok and migrate:
        cursor.execute("UPDATE users SET password=? WHERE id=?", (hash_password(password), user[0]))
        conn.commit()
    conn.close()
    
    if ok:
        session.clear()
        session['user_mobile'] = mobile
        return redirect(url_for('track_status_view'))
    return render_template_string(TRACK_STATUS_LOGIN_PAGE, error="Invalid Mobile Number or Password!")

@app.route('/track-status-view')
def track_status_view():
    mobile = session.get('user_mobile')
    if not mobile: return redirect(url_for('track_status_login'))
    
    conn = sqlite3.connect(DATABASE_PATH)
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM complaints WHERE mobile = ? ORDER BY id DESC", (mobile,))
    user_complaints = cursor.fetchall()
    
    active_cid = request.args.get('cid')
    active_complaint = None
    remarks = []
    is_blocked = False
    remaining_cooldown = 0
    
    if not active_cid and user_complaints:
        active_cid = user_complaints[0][0]
        
    if active_cid:
        cursor.execute("SELECT * FROM complaints WHERE id = ? AND mobile = ?", (active_cid, mobile))
        active_complaint = cursor.fetchone()
        if not active_complaint:
            conn.close()
            abort(404)
        
        cursor.execute("SELECT * FROM complaint_remarks WHERE complaint_id = ? ORDER BY id ASC", (active_cid,))
        remarks = cursor.fetchall()
        
        cursor.execute("SELECT first_msg_time, cooldown_until FROM citizen_chat_timer WHERE complaint_id = ?", (active_cid,))
        timer_row = cursor.fetchone()
        
        now = datetime.now()
        if timer_row and timer_row[0]:
            first_msg_time = datetime.strptime(timer_row[0], '%Y-%m-%d %H:%M:%S')
            cooldown_until = datetime.strptime(timer_row[1], '%Y-%m-%d %H:%M:%S') if timer_row[1] else None
            
            if cooldown_until and now < cooldown_until:
                is_blocked = True
                remaining_cooldown = int((cooldown_until - now).total_seconds())
            elif now > (first_msg_time + timedelta(minutes=5)) and (not cooldown_until or now >= cooldown_until):
                cooldown_until = now + timedelta(minutes=2)
                cursor.execute("UPDATE citizen_chat_timer SET cooldown_until = ? WHERE complaint_id = ?",
                               (cooldown_until.strftime('%Y-%m-%d %H:%M:%S'), active_cid))
                conn.commit()
                is_blocked = True
                remaining_cooldown = 120

    conn.close()
    return render_template_string(CITIZEN_STATUS_VIEW_PAGE, mobile=mobile, user_complaints=user_complaints,
                                  active_cid=int(active_cid) if active_cid else None,
                                  active_complaint=active_complaint, remarks=remarks,
                                  is_blocked=is_blocked, remaining_cooldown=remaining_cooldown)

@app.route('/complaint-certificate/<int:cid>')
def complaint_certificate(cid):
    conn = sqlite3.connect(DATABASE_PATH)
    cursor = conn.cursor()
    mobile = session.get('user_mobile')
    if not mobile and not (session.get('is_head_admin') or session.get('is_sub_admin')):
        return redirect(url_for('login'))
    cursor.execute("SELECT * FROM complaints WHERE id = ?", (cid,))
    complaint = cursor.fetchone()
    conn.close()
    if not complaint: abort(404)
    if mobile and complaint[1] != mobile and not (session.get('is_head_admin') or session.get('is_sub_admin')):
        abort(404)
    return render_template_string(CONGRATS_CERTIFICATE_PAGE, complaint=complaint, email_status=(complaint[23] if len(complaint) > 23 else 'not_configured'))

@app.route('/send-complaint-remark', methods=['POST'])
def send_complaint_remark():
    cid = request.form.get('complaint_id', '')
    msg = request.form.get('message', '').strip()
    is_admin = bool(session.get('is_head_admin') or session.get('is_sub_admin'))
    mobile = session.get('user_mobile')
    if not is_admin and not mobile:
        return redirect(url_for('login'))
    conn = sqlite3.connect(DATABASE_PATH)
    cursor = conn.cursor()
    cursor.execute('SELECT mobile FROM complaints WHERE id=?', (cid,))
    owner = cursor.fetchone()
    if not owner or (not is_admin and owner[0] != mobile):
        conn.close()
        abort(404)
    sender_type = ('head_admin' if session.get('is_head_admin') else 'sub_admin') if is_admin else 'citizen'
    sender_name = session.get('sub_admin_name', 'Head Officer') if is_admin else 'Citizen'
    attachment_file = ''
    if 'attachment' in request.files and request.files['attachment'].filename:
        try:
            attachment_file = save_upload(request.files['attachment'], 'remark')
        except ValueError as e:
            conn.close()
            return str(e), 400
    if not is_admin:
        now = datetime.now()
        cursor.execute('SELECT first_msg_time, cooldown_until FROM citizen_chat_timer WHERE complaint_id=?', (cid,))
        timer = cursor.fetchone()
        if timer and timer[1] and now < datetime.strptime(timer[1], '%Y-%m-%d %H:%M:%S'):
            conn.close()
            return 'Please wait before sending another message.', 429
        if not timer:
            cursor.execute('INSERT INTO citizen_chat_timer (complaint_id, first_msg_time) VALUES (?, ?)', (cid, now.strftime('%Y-%m-%d %H:%M:%S')))
    if msg or attachment_file:
        cursor.execute('INSERT INTO complaint_remarks (complaint_id, sender_type, sender_name, message, attachment) VALUES (?, ?, ?, ?, ?)',
                       (cid, sender_type, sender_name, msg, attachment_file))
        conn.commit()
    conn.close()
    if is_admin:
        return redirect(f"/admin-complaint-remark/{cid}" if session.get('is_head_admin') else f"/subadmin-complaint-remark/{cid}")
    return redirect(f'/track-status-view?cid={cid}')

@app.route('/admin-complaint-remark/<int:cid>')
def admin_complaint_remark(cid):
    if not session.get('is_head_admin'): return redirect(url_for('admin_login'))
    
    conn = sqlite3.connect(DATABASE_PATH)
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM complaints WHERE id = ?", (cid,))
    complaint = cursor.fetchone()
    cursor.execute("SELECT * FROM complaint_remarks WHERE complaint_id = ? ORDER BY id ASC", (cid,))
    remarks = cursor.fetchall()
    conn.close()
    
    return render_template_string(OFFICER_REMARK_CHAT_PAGE, complaint=complaint, remarks=remarks,
                                  role_type='head_admin', role_name='👑 Head Officer',
                                  return_url='/admin-dashboard', redirect_back=f'/admin-complaint-remark/{cid}')

@app.route('/subadmin-complaint-remark/<int:cid>')
def subadmin_complaint_remark(cid):
    if not session.get('is_sub_admin'): return redirect(url_for('sub_admin_login'))
    
    conn = sqlite3.connect(DATABASE_PATH)
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM complaints WHERE id = ?", (cid,))
    complaint = cursor.fetchone()
    cursor.execute("SELECT * FROM complaint_remarks WHERE complaint_id = ? ORDER BY id ASC", (cid,))
    remarks = cursor.fetchall()
    conn.close()
    
    return render_template_string(OFFICER_REMARK_CHAT_PAGE, complaint=complaint, remarks=remarks,
                                  role_type='sub_admin', role_name='🛡️ Sub-Admin Officer',
                                  return_url='/sub-admin-dashboard', redirect_back=f'/subadmin-complaint-remark/{cid}')

@app.route('/submit-feedback', methods=['POST'])
def submit_feedback():
    name = request.form.get('name')
    contact = request.form.get('contact')
    message = request.form.get('message')
    
    conn = sqlite3.connect(DATABASE_PATH)
    cursor = conn.cursor()
    cursor.execute("INSERT INTO feedbacks (name, email_or_phone, message) VALUES (?, ?, ?)", (name, contact, message))
    conn.commit()
    conn.close()
    
    session['feedback_sent'] = True
    return redirect(url_for('home'))

@app.route('/update-notice', methods=['POST'])
def update_notice():
    if not session.get('is_head_admin'): return redirect(url_for('admin_login'))
    txt = request.form.get('notice_text')
    set_setting('notice_text', txt)
    return redirect(url_for('admin_dashboard'))

@app.route('/upload-notice-photo/<int:slot>', methods=['POST'])
def upload_notice_photo(slot):
    if not session.get('is_head_admin'): return redirect(url_for('admin_login'))
    if 'notice_photo' in request.files:
        f = request.files['notice_photo']
        if f and f.filename != '':
            if slot not in (1, 2): abort(404)
            try:
                saved_name = save_upload(f, f'notice{slot}', {'png', 'jpg', 'jpeg', 'webp'})
                set_setting(f'notice_photo{slot}', saved_name)
            except ValueError as e:
                return str(e), 400
    return redirect(url_for('admin_dashboard'))

@app.route('/delete-notice-photo/<int:slot>')
def delete_notice_photo(slot):
    if not session.get('is_head_admin'): return redirect(url_for('admin_login'))
    set_setting(f'notice_photo{slot}', '')
    return redirect(url_for('admin_dashboard'))

@app.route('/send-admin-chat', methods=['POST'])
def send_admin_chat():
    if not (session.get('is_head_admin') or session.get('is_sub_admin')):
        return redirect(url_for('sub_admin_login'))
    is_head = bool(session.get('is_head_admin'))
    sub_id = request.form.get('sub_admin_id', '') if is_head else session.get('sub_admin_id', '')
    if not sub_id:
        abort(400)
    msg_text = request.form.get('message_text', '').strip()
    file_name = ''
    file_type = 'none'
    if 'attachment' in request.files and request.files['attachment'].filename:
        try:
            file_name = save_upload(request.files['attachment'], 'chat')
        except ValueError as e:
            return str(e), 400
        ext = file_name.rsplit('.', 1)[-1]
        file_type = 'image' if ext in {'png', 'jpg', 'jpeg', 'webp'} else ('video' if ext in {'mp4', 'webm', 'mov'} else ('audio' if ext in {'mp3', 'wav', 'ogg', 'm4a'} else 'document'))
    if msg_text or file_name:
        conn = sqlite3.connect(DATABASE_PATH)
        cursor = conn.cursor()
        cursor.execute('INSERT INTO admin_chat_messages (sub_admin_id, sender_role, message_text, file_attachment, file_type) VALUES (?, ?, ?, ?, ?)',
                       (sub_id, 'head_admin' if is_head else 'sub_admin', msg_text, file_name, file_type))
        conn.commit()
        conn.close()
    return redirect(f'/admin-dashboard?target_sub={sub_id}#tab-chat' if is_head else '/sub-admin-dashboard#tab-sub-help')

@app.route('/live-checker')
def live_checker():
    return render_template_string(LIVE_CHECKER_PAGE)

@app.route('/api/assistant', methods=['POST'])
def assistant_reply():
    """Optional general-purpose assistant. The API key stays on the server."""
    payload = request.get_json(silent=True) or {}
    question = str(payload.get('question', '')).strip()
    if not question or len(question) > 500:
        return jsonify(answer='Please enter a question under 500 characters.'), 400

    api_key = os.environ.get('GEMINI_API_KEY', '').strip()
    if not api_key:
        return jsonify(answer='The AI assistant is not connected yet. Add GEMINI_API_KEY in the server environment to enable general questions.'), 503

    model = os.environ.get('GEMINI_MODEL', 'gemini-3.5-flash-lite').strip()
    if not re.fullmatch(r'[A-Za-z0-9._-]{1,80}', model):
        return jsonify(answer='The AI model setting is invalid.'), 500

    request_body = {
        'systemInstruction': {'parts': [{'text': (
            'You are the CyberShield demo portal assistant. Answer general questions helpfully and clearly. '
            'Reply in the language/script the user used; understand English, Odia script, and Romanized Odia. '
            'Be honest when uncertain and never claim a demo report is an official police filing. '
            'For ongoing financial cyber fraud, advise calling India cybercrime helpline 1930 promptly and '
            'contacting the bank through its official channel. Never ask for or repeat passwords, OTPs, UPI PINs, '
            'bank credentials, or private complaint details. Do not provide instructions for wrongdoing. '
            'You have no live web access; say so for current facts that need verification.'
        )}]},
        'contents': [{'role': 'user', 'parts': [{'text': question}]}],
        'generationConfig': {'temperature': 0.4, 'maxOutputTokens': 900},
    }
    endpoint = f'https://generativelanguage.googleapis.com/v1beta/models/{model}:generateContent'
    api_request = URLRequest(
        endpoint,
        data=json.dumps(request_body).encode('utf-8'),
        headers={'Content-Type': 'application/json', 'x-goog-api-key': api_key},
        method='POST',
    )
    try:
        with urlopen(api_request, timeout=20) as response:
            result = json.loads(response.read().decode('utf-8'))
        answer = ''.join(
            part.get('text', '')
            for part in result.get('candidates', [{}])[0].get('content', {}).get('parts', [])
            if isinstance(part, dict)
        ).strip()
        if not answer:
            return jsonify(answer='I could not generate an answer for that question. Please try rephrasing it.'), 502
        return jsonify(answer=answer)
    except HTTPError as exc:
        app.logger.warning('Gemini assistant returned HTTP %s', exc.code)
        return jsonify(answer='The AI service could not answer right now. Please try again shortly.'), 502
    except (URLError, TimeoutError, json.JSONDecodeError, OSError, ValueError) as exc:
        app.logger.warning('Gemini assistant request failed: %s', type(exc).__name__)
        return jsonify(answer='The AI service is temporarily unreachable. Please try again shortly.'), 502

@app.route('/select-category')
def select_category():
    session['selected_category'] = request.args.get('cat', 'General Cyber Crime')
    return redirect(url_for('login'))

@app.route('/register')
def register():
    n1, n2 = random.randint(1, 9), random.randint(1, 9)
    session['captcha_ans'] = str(n1 + n2)
    return render_template_string(REGISTER_PAGE, captcha_num1=n1, captcha_num2=n2)

@app.route('/register-action', methods=['POST'])
def register_action():
    mobile = request.form.get('mobile', '').strip()
    password = request.form.get('password', '')
    if request.form.get('captcha_ans') != session.get('captcha_ans'):
        n1, n2 = random.randint(1, 9), random.randint(1, 9)
        session['captcha_ans'] = str(n1 + n2)
        return render_template_string(REGISTER_PAGE, error="Incorrect CAPTCHA answer!", captcha_num1=n1, captcha_num2=n2)
    if not mobile.isdigit() or not 10 <= len(mobile) <= 15 or len(password) < 10:
        return render_template_string(REGISTER_PAGE, error="Enter a valid mobile number and password with at least 10 characters.", captcha_num1=1, captcha_num2=2)
    conn = sqlite3.connect(DATABASE_PATH)
    cursor = conn.cursor()
    try:
        cursor.execute("INSERT INTO users (mobile, password) VALUES (?, ?)", (mobile, hash_password(password)))
        conn.commit()
    except sqlite3.IntegrityError:
        conn.close()
        return render_template_string(REGISTER_PAGE, error="Mobile already registered! Please login.", captcha_num1=1, captcha_num2=2)
    conn.close()
    session['pending_mobile'] = mobile
    return redirect(url_for('profile_setup'))

@app.route('/login')
def login():
    selected_category = session.get('selected_category', None)
    return render_template_string(LOGIN_PAGE, otp_sent=False, selected_category=selected_category)

@app.route('/send-otp-login', methods=['POST'])
def send_otp_login():
    mobile = request.form.get('mobile', '').strip()
    password = request.form.get('password', '')
    conn = sqlite3.connect(DATABASE_PATH)
    cursor = conn.cursor()
    cursor.execute("SELECT id, password FROM users WHERE mobile = ?", (mobile,))
    user = cursor.fetchone()
    ok, migrate = verify_password(user[1], password) if user else (False, False)
    if ok and migrate:
        cursor.execute("UPDATE users SET password=? WHERE id=?", (hash_password(password), user[0]))
        conn.commit()
    conn.close()
    if ok:
        otp = f"{secrets.randbelow(10000):04d}"
        session['pending_mobile'] = mobile
        session['valid_otp'] = otp
        session['valid_otp_expires'] = (datetime.utcnow() + timedelta(minutes=5)).timestamp()
        session['otp_attempts'] = 0
        selected_category = session.get('selected_category', None)
        return render_template_string(LOGIN_PAGE, otp_sent=True, generated_otp=otp, selected_category=selected_category, otp_demo=True)
    return render_template_string(LOGIN_PAGE, otp_sent=False, error="Invalid mobile or password!")

@app.route('/verify-otp-login', methods=['POST'])
def verify_otp_login():
    expected = session.get('valid_otp')
    expires = session.get('valid_otp_expires', 0)
    if not expected or datetime.utcnow().timestamp() > expires or session.get('otp_attempts', 0) >= 5:
        session.pop('valid_otp', None)
        session.pop('valid_otp_expires', None)
        return render_template_string(LOGIN_PAGE, otp_sent=False, error="Demo code expired or attempt limit reached. Sign in again.")
    entered = request.form.get('entered_otp', '')
    if hmac.compare_digest(entered, expected) and session.get('pending_mobile'):
        mobile = session.pop('pending_mobile')
        session.pop('valid_otp', None)
        session.pop('valid_otp_expires', None)
        session.pop('otp_attempts', None)
        selected_category = session.get('selected_category')
        session.clear()
        if selected_category:
            session['selected_category'] = selected_category
        session['user_mobile'] = mobile
        conn = sqlite3.connect(DATABASE_PATH)
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM citizen_profiles WHERE mobile = ?", (mobile,))
        prof = cursor.fetchone()
        conn.close()
        if not prof:
            return redirect(url_for('profile_setup'))
        return redirect(url_for('dashboard'))
    session['otp_attempts'] = session.get('otp_attempts', 0) + 1
    return render_template_string(LOGIN_PAGE, otp_sent=True, generated_otp=expected, otp_demo=True, error="Incorrect demo code!")

@app.route('/profile-setup')
def profile_setup():
    if not session.get('pending_mobile') and not session.get('user_mobile'):
        return redirect(url_for('register'))
    return render_template_string(PROFILE_SETUP_PAGE, districts=ODISHA_DISTRICTS)

@app.route('/save-profile', methods=['POST'])
def save_profile():
    mobile = session.get('pending_mobile') or session.get('user_mobile')
    if not mobile: return redirect(url_for('register'))
    
    district = canonical_district(request.form.get('district'))
    if not district:
        return 'Please select a valid Odisha district.', 400
    conn = sqlite3.connect(DATABASE_PATH)
    cursor = conn.cursor()
    cursor.execute('''
        INSERT OR REPLACE INTO citizen_profiles (mobile, fullname, district, block, panchayat, pincode, phone, is_completed)
        VALUES (?, ?, ?, ?, ?, ?, ?, 1)
    ''', (mobile, request.form.get('fullname'), district, request.form.get('block'), request.form.get('panchayat'), request.form.get('pincode'), request.form.get('phone')))
    conn.commit()
    conn.close()
    
    session.pop('pending_mobile', None)
    session['user_mobile'] = mobile
    return redirect(url_for('profile_saved'))

@app.route('/profile-saved')
def profile_saved():
    mobile = session.get('user_mobile')
    if not mobile:
        return redirect(url_for('login'))
    conn = sqlite3.connect(DATABASE_PATH)
    profile = conn.execute('SELECT * FROM citizen_profiles WHERE mobile=? AND is_completed=1', (mobile,)).fetchone()
    conn.close()
    if not profile:
        return redirect(url_for('profile_setup'))
    return render_template_string(PROFILE_SAVED_PAGE, profile=profile)

@app.route('/dashboard')
def dashboard():
    mobile = session.get('user_mobile')
    if not mobile: return redirect(url_for('login'))
    
    conn = sqlite3.connect(DATABASE_PATH)
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM citizen_profiles WHERE mobile = ?", (mobile,))
    profile = cursor.fetchone()
    conn.close()
    
    if not profile: return redirect(url_for('profile_setup'))
    
    auto_title = session.get('selected_category', 'General Cyber Incident')
    return render_template_string(DASHBOARD_PAGE, mobile=mobile, profile=profile, profile_district=canonical_district(profile[3]) or ODISHA_DISTRICTS[0], districts=ODISHA_DISTRICTS, auto_title=auto_title)

@app.route('/submit-complaint', methods=['POST'])
def submit_complaint():
    mobile = session.get('user_mobile')
    if not mobile: return redirect(url_for('login'))
    email = request.form.get('contact_email', '').strip()
    if not re.fullmatch(r"[A-Za-z0-9.!#$%&'*+/=?^_`{|}~-]+@[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?(?:\.[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?)+", email):
        return 'Please enter a valid email address.', 400

    complaint_district = canonical_district(request.form.get('district'))
    if not complaint_district:
        return 'Please select a valid Odisha district.', 400
    description = request.form.get('description', '').strip()
    voice_file = request.files.get('voice_recording')
    has_voice = bool(voice_file and voice_file.filename)
    if not description and not has_voice:
        return 'Please type the incident details or attach a voice recording.', 400
    if has_voice:
        safe_audio_name = secure_filename(voice_file.filename)
        audio_ext = safe_audio_name.rsplit('.', 1)[-1].lower() if '.' in safe_audio_name else ''
        if audio_ext not in {'webm', 'ogg', 'mp3', 'wav', 'm4a', 'mp4', 'aac'}:
            return 'Voice recording must be an audio file (WEBM, OGG, MP3, WAV, M4A, MP4, or AAC).', 400
        voice_file.stream.seek(0, os.SEEK_END)
        audio_size = voice_file.stream.tell()
        voice_file.stream.seek(0)
        if audio_size > 6 * 1024 * 1024:
            return 'Voice recording must be 6 MB or smaller.', 400

    saved_name = ''
    if 'evidence' in request.files:
        f = request.files['evidence']
        if f and f.filename:
            try:
                saved_name = save_upload(f, 'evidence')
            except ValueError as e:
                return str(e), 400

    saved_voice = ''
    if has_voice:
        try:
            saved_voice = save_upload(voice_file, 'voice', allowed={'webm', 'ogg', 'mp3', 'wav', 'm4a', 'mp4', 'aac'})
        except ValueError as e:
            return str(e), 400

    conn = sqlite3.connect(DATABASE_PATH)
    cursor = conn.cursor()
    cursor.execute('''
        INSERT INTO complaints (
            mobile, complainant_name, father_name, father_status, mother_name, mother_status,
            dob, district, block, panchayat, active_mobile, permanent_address, present_address,
            gps_lat, gps_lon, title, description, status, evidence_file, contact_email, voice_recording
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'Pending', ?, ?, ?)
    ''', (
        mobile, request.form.get('complainant_name'), request.form.get('father_name'), 'Living',
        request.form.get('mother_name'), 'Living', request.form.get('dob'),
        complaint_district, request.form.get('block'), request.form.get('panchayat'),
        request.form.get('active_mobile'), request.form.get('permanent_address'), request.form.get('present_address'),
        request.form.get('gps_lat'), request.form.get('gps_lon'), request.form.get('title'),
        description, saved_name, email, saved_voice
    ))
    new_cid = cursor.lastrowid
    conn.commit()
    conn.close()

    email_status = send_complaint_confirmation(email, new_cid, request.form.get('complainant_name', ''), request.form.get('title', ''))
    conn = sqlite3.connect(DATABASE_PATH)
    conn.execute('UPDATE complaints SET email_status=? WHERE id=?', (email_status, new_cid))
    conn.commit()
    conn.close()
    session.pop('selected_category', None)
    return redirect(url_for('complaint_certificate', cid=new_cid))

@app.route('/admin-login')
def admin_login():
    return render_login_page(ADMIN_LOGIN_PAGE, 'head_admin')

@app.route('/admin-login-action', methods=['POST'])
def admin_login_action():
    login_id = request.form.get('admin_num', '').strip()
    _, remaining = get_login_lock('head_admin', login_id)
    if remaining:
        return render_login_page(ADMIN_LOGIN_PAGE, 'head_admin', 'Access temporarily paused after two failed attempts.', login_id, remaining), 429
    captcha_ok = request.form.get('captcha_answer', '').strip() == session.get('head_admin_captcha_answer')
    credentials_ok = bool(ADMIN_ID and ADMIN_PASSWORD and hmac.compare_digest(login_id, ADMIN_ID) and hmac.compare_digest(request.form.get('admin_pass', ''), ADMIN_PASSWORD))
    if not captcha_ok or not credentials_ok:
        remaining = record_login_failure('head_admin', login_id)
        error = 'CAPTCHA answer is incorrect.' if not captcha_ok else 'Admin ID or password is incorrect.'
        if remaining: error = 'Two failed attempts. Login is locked for 3 minutes.'
        return render_login_page(ADMIN_LOGIN_PAGE, 'head_admin', error, login_id, remaining), (429 if remaining else 401)
    clear_login_failures('head_admin', login_id)
    session.clear(); session['is_head_admin'] = True
    return redirect(url_for('admin_dashboard'))

@app.route('/admin-dashboard')
def admin_dashboard():
    if not session.get('is_head_admin'): return redirect(url_for('admin_login'))
    target_sub = request.args.get('target_sub', '')
    
    conn = sqlite3.connect(DATABASE_PATH)
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM admin_profile WHERE admin_id = '99999'")
    admin_prof = cursor.fetchone()
    
    cursor.execute("SELECT * FROM feedbacks ORDER BY id DESC")
    feedbacks = cursor.fetchall()

    cursor.execute("SELECT * FROM complaints ORDER BY id DESC")
    cases = [(c, None) for c in cursor.fetchall()]

    cursor.execute("SELECT * FROM sub_admins ORDER BY id DESC")
    sub_admins = cursor.fetchall()

    chat_msgs = []
    if target_sub:
        cursor.execute("SELECT * FROM admin_chat_messages WHERE sub_admin_id = ? ORDER BY id ASC", (target_sub,))
        chat_msgs = cursor.fetchall()

    conn.close()
    
    notice_text = get_setting('notice_text')
    notice_photo1 = get_setting('notice_photo1')
    notice_photo2 = get_setting('notice_photo2')
    
    return render_template_string(HEAD_ADMIN_DASHBOARD, admin_prof=admin_prof, cases=cases, feedbacks=feedbacks, sub_admins=sub_admins, target_sub=target_sub, chat_msgs=chat_msgs, notice_text=notice_text, notice_photo1=notice_photo1, notice_photo2=notice_photo2)

@app.route('/create-sub-admin', methods=['POST'])
def create_sub_admin():
    if not session.get('is_head_admin'): return redirect(url_for('admin_login'))
    sub_id = request.form.get('sub_id')
    sub_pass = request.form.get('sub_pass')
    sub_name = request.form.get('sub_name')
    
    conn = sqlite3.connect(DATABASE_PATH)
    cursor = conn.cursor()
    try:
        cursor.execute("INSERT INTO sub_admins (sub_admin_id, password, name, designation) VALUES (?, ?, ?, ?)",
                       (sub_id, hash_password(sub_pass), sub_name, 'Cyber Field Officer'))
        conn.commit()
    except sqlite3.IntegrityError:
        pass
    conn.close()
    return redirect(url_for('admin_dashboard'))

@app.route('/sub-admin-login')
def sub_admin_login():
    return render_login_page(SUB_ADMIN_LOGIN_PAGE, 'sub_admin')

@app.route('/sub-admin-login-action', methods=['POST'])
def sub_admin_login_action():
    s_id = request.form.get('sub_admin_id', '').strip()
    _, remaining = get_login_lock('sub_admin', s_id)
    if remaining:
        return render_login_page(SUB_ADMIN_LOGIN_PAGE, 'sub_admin', 'Access temporarily paused after two failed attempts.', s_id, remaining), 429
    captcha_ok = request.form.get('captcha_answer', '').strip() == session.get('sub_admin_captcha_answer')
    conn = sqlite3.connect(DATABASE_PATH); cursor = conn.cursor()
    cursor.execute("SELECT * FROM sub_admins WHERE sub_admin_id = ?", (s_id,)); sa = cursor.fetchone()
    ok, migrate = verify_password(sa[2], request.form.get('password', '')) if sa else (False, False)
    if ok and migrate:
        cursor.execute("UPDATE sub_admins SET password=? WHERE id=?", (hash_password(request.form.get('password', '')), sa[0])); conn.commit()
        sa = (sa[0], sa[1], hash_password(request.form.get('password', '')), *sa[3:])
    conn.close()
    if not captcha_ok or not ok:
        remaining = record_login_failure('sub_admin', s_id)
        error = 'CAPTCHA answer is incorrect.' if not captcha_ok else 'Sub-Admin ID or password is incorrect.'
        if remaining: error = 'Two failed attempts. Login is locked for 3 minutes.'
        return render_login_page(SUB_ADMIN_LOGIN_PAGE, 'sub_admin', error, s_id, remaining), (429 if remaining else 401)
    clear_login_failures('sub_admin', s_id)
    session.clear(); session['is_sub_admin'] = True; session['sub_admin_id'] = sa[1]; session['sub_admin_name'] = sa[3]
    return redirect(url_for('sub_admin_dashboard'))

@app.route('/sub-admin-dashboard')
def sub_admin_dashboard():
    if not session.get('is_sub_admin'): return redirect(url_for('sub_admin_login'))
    sub_id = session.get('sub_admin_id')
    
    conn = sqlite3.connect(DATABASE_PATH)
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM feedbacks ORDER BY id DESC")
    feedbacks = cursor.fetchall()
    
    cursor.execute("SELECT * FROM complaints ORDER BY id DESC")
    cases = [(c, None) for c in cursor.fetchall()]

    cursor.execute("SELECT * FROM admin_chat_messages WHERE sub_admin_id = ? ORDER BY id ASC", (sub_id,))
    chat_msgs = cursor.fetchall()
    conn.close()
    
    return render_template_string(SUB_ADMIN_DASHBOARD, sub_admin_name=session.get('sub_admin_name'), sub_admin_id=sub_id, feedbacks=feedbacks, cases=cases, chat_msgs=chat_msgs)

@app.route('/update-status/<int:id>', methods=['POST'])
def update_status(id):
    if not session.get('is_head_admin') and not session.get('is_sub_admin'):
        return redirect(url_for('home'))
        
    new_status = request.form.get('status')
    now = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    
    conn = sqlite3.connect(DATABASE_PATH)
    cursor = conn.cursor()
    cursor.execute("SELECT responded_at FROM complaints WHERE id = ?", (id,))
    row = cursor.fetchone()
    if row and row[0] is None:
        cursor.execute("UPDATE complaints SET status = ?, responded_at = ? WHERE id = ?", (new_status, now, id))
    else:
        cursor.execute("UPDATE complaints SET status = ? WHERE id = ?", (new_status, id))
    conn.commit()
    conn.close()
    
    if session.get('is_head_admin'):
        return redirect(url_for('admin_dashboard'))
    else:
        return redirect(url_for('sub_admin_dashboard'))

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('home'))

if __name__ == '__main__':
    port = int(os.environ.get('PORT', '5000'))
    threading.Timer(1.2, lambda: webbrowser.open_new(f'http://127.0.0.1:{port}/')).start()
    app.run(debug=False, port=port)

