from flask import Flask, render_template, request, redirect, session
import sqlite3, hashlib, time, random, string

app = Flask(__name__)
app.secret_key = "secret123"

# ---------------- DATABASE ----------------
def init_db():
    conn = sqlite3.connect('database.db')
    c = conn.cursor()

    c.execute('''CREATE TABLE IF NOT EXISTS users
                 (username TEXT, attempts INTEGER DEFAULT 0, locked INTEGER DEFAULT 0)''')

    c.execute('''CREATE TABLE IF NOT EXISTS votes
                 (user TEXT, candidate TEXT, time REAL,
                  prev_hash TEXT, hash TEXT, code TEXT)''')

    c.execute('''CREATE TABLE IF NOT EXISTS logs
                 (message TEXT)''')

    conn.commit()
    conn.close()

init_db()

# ---------------- HELPERS ----------------
def hash_data(data):
    return hashlib.sha256(data.encode()).hexdigest()

def last_hash():
    conn = sqlite3.connect('database.db')
    c = conn.cursor()
    c.execute("SELECT hash FROM votes ORDER BY rowid DESC LIMIT 1")
    r = c.fetchone()
    conn.close()
    return r[0] if r else "GENESIS"

def log(msg):
    conn = sqlite3.connect('database.db')
    c = conn.cursor()
    c.execute("INSERT INTO logs VALUES (?)", (msg,))
    conn.commit()
    conn.close()

def generate_code():
    return ''.join(random.choices(string.ascii_uppercase + string.digits, k=5)) + "-" + ''.join(random.choices(string.ascii_uppercase + string.digits, k=4))

# ---------------- SECURITY SYSTEM ----------------
def security_check(user):
    conn = sqlite3.connect('database.db')
    c = conn.cursor()

    # Fast voting detection
    c.execute("SELECT time FROM votes WHERE user=?", (user,))
    times = [t[0] for t in c.fetchall()]

    if len(times) >= 2 and time.time() - times[-1] < 5:
        log(f"⚠ Fast voting detected: {user}")
        return "OTP"

    # Account lock system
    c.execute("SELECT attempts, locked FROM users WHERE username=?", (user,))
    row = c.fetchone()

    if row:
        attempts, locked = row
        if locked == 1:
            return "LOCKED"

        if attempts >= 3:
            c.execute("UPDATE users SET locked=1 WHERE username=?", (user,))
            conn.commit()
            log(f"🔒 Account locked: {user}")
            return "LOCKED"

    conn.close()
    return "OK"

# ---------------- LOGIN ----------------
@app.route('/', methods=['GET','POST'])
def login():
    if request.method == 'POST':
        user = request.form['username']

        conn = sqlite3.connect('database.db')
        c = conn.cursor()

        c.execute("INSERT OR IGNORE INTO users(username) VALUES(?)", (user,))
        c.execute("UPDATE users SET attempts = attempts + 1 WHERE username=?", (user,))
        conn.commit()
        conn.close()

        session['user'] = user
        return redirect('/vote')

    return render_template('login.html')

# ---------------- VOTE ----------------
@app.route('/vote', methods=['GET','POST'])
def vote():
    if 'user' not in session:
        return redirect('/')

    user = session['user']

    check = security_check(user)
    if check == "LOCKED":
        return "🔒 Account locked due to suspicious activity"
    if check == "OTP":
        return "⚠ OTP Verification Required (Adaptive Security Triggered)"

    if request.method == 'POST':
        candidate = request.form['candidate']
        t = time.time()
        prev = last_hash()

        data = user + candidate + str(t) + prev
        h = hash_data(data)

        code = generate_code()

        conn = sqlite3.connect('database.db')
        c = conn.cursor()
        c.execute("INSERT INTO votes VALUES (?,?,?,?,?,?)",
                  (user, candidate, t, prev, h, code))
        conn.commit()
        conn.close()

        return render_template('success.html', code=code)

    return render_template('vote.html')

# ---------------- VERIFY ----------------
@app.route('/verify', methods=['GET','POST'])
def verify():
    result = None

    if request.method == 'POST':
        code = request.form['code']

        conn = sqlite3.connect('database.db')
        c = conn.cursor()
        c.execute("SELECT code FROM votes WHERE code=?", (code,))
        result = c.fetchone()
        conn.close()

    return render_template('verify.html', result=result)

# ---------------- DASHBOARD ----------------
@app.route('/admin')
def admin():
    conn = sqlite3.connect('database.db')
    c = conn.cursor()

    c.execute("SELECT COUNT(*) FROM votes")
    total = c.fetchone()[0]

    c.execute("SELECT COUNT(*) FROM logs")
    suspicious = c.fetchone()[0]

    score = max(0, 100 - suspicious * 10)

    if score > 80:
        risk = "Low"
    elif score > 50:
        risk = "Medium"
    else:
        risk = "High"

    c.execute("SELECT message FROM logs")
    logs = c.fetchall()

    conn.close()

    return render_template('admin.html',
                           total=total,
                           suspicious=suspicious,
                           score=score,
                           risk=risk,
                           logs=logs)

# ---------------- AUDIT SYSTEM ----------------
@app.route('/audit')
def audit():
    conn = sqlite3.connect('database.db')
    c = conn.cursor()

    c.execute("SELECT * FROM votes")
    raw_votes = c.fetchall()

    c.execute("SELECT * FROM logs")
    logs = c.fetchall()

    conn.close()

    # Convert time to readable format
    votes = []
    for v in raw_votes:
        readable_time = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(v[2]))
        votes.append((v[0], v[1], readable_time, v[5]))

    return render_template('audit.html',
                           votes=votes,
                           logs=logs,
                           total=len(votes))

# ---------------- RUN ----------------
if __name__ == '__main__':
    app.run(debug=True)