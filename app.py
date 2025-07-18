import os
import random
import time
from flask import Flask, render_template, request, redirect, url_for, session, flash
from flask_mail import Message
from werkzeug.security import generate_password_hash, check_password_hash
from flask import Response
from config import Config
from extensions import db, mail
from models import User, Result
from helpers import send_otp_email, generate_otp, load_questions_from_excel, classify_role, send_password_reset_otp
from datetime import timedelta
from flask import make_response, render_template
from xhtml2pdf import pisa
from io import BytesIO
import datetime

app = Flask(__name__)
app.config.from_object(Config)
app.permanent_session_lifetime = timedelta(hours=1, minutes=20)


db.init_app(app)
mail.init_app(app)

# ========== ROUTES ==========

@app.route('/')
def home():
    return render_template('register.html')

from datetime import datetime, timedelta

@app.route('/register', methods=['POST'])
def register():
    name = request.form['name']
    email = request.form['email'].strip()
    import re
    EMAIL_REGEX = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    if not re.match(EMAIL_REGEX, email):
        flash("Please enter a valid email address.")
        return redirect(url_for('home'))

    password = request.form.get('password')

    # ✅ Check strong password
    import re
    def is_strong_password(pw):
        return (
            len(pw) >= 8 and
            re.search(r'\d', pw) and
            re.search(r'[!@#$%^&*()_+\-=\[\]{};\'":\\|,.<>\/?]', pw)
        )

    if not is_strong_password(password):
        flash("Password must be at least 8 characters long and include at least one number and one special character.")
        return redirect(url_for('home'))

    existing = User.query.filter_by(email=email).first()
    if existing:
        flash("Email already registered. Please login.")
        return redirect(url_for('login'))

    otp = generate_otp()
    session.permanent = True
    session['temp_user'] = {
        'name': name,
        'email': email,
        'password': generate_password_hash(password)
    }
    session['otp'] = otp
    session['otp_expiry'] = (datetime.now() + timedelta(minutes=10)).timestamp()
    session['email'] = email

    send_otp_email(email, otp)
    return redirect(url_for('verify_otp'))


@app.route('/verify-otp', methods=['GET', 'POST'])
def verify_otp():
    if request.method == 'POST':
        email = session.get('email')
        otp_input = ''.join([request.form.get(f'otp{i}', '') for i in range(6)])
        saved_otp = session.get('otp')
        expiry = session.get('otp_expiry')

        if not email or not saved_otp or not expiry:
            flash("Session expired. Please register again.")
            return redirect(url_for('home'))

        if datetime.now().timestamp() > expiry:
            flash("OTP expired. Please click resend.")
            return redirect(url_for('verify_otp'))

        if otp_input != saved_otp:
            flash("Invalid OTP.")
            return redirect(url_for('verify_otp'))

        # ✅ Save user to DB
        temp_user = session.get('temp_user')
        if not temp_user:
            flash("Session expired. Please register again.")
            return redirect(url_for('home'))

        user = User(
            name=temp_user['name'],
            email=temp_user['email'],
            password_hash=temp_user['password'],
            otp_verified=True
        )
        db.session.add(user)
        db.session.commit()

        # Cleanup session
        session.pop('temp_user', None)
        session.pop('otp', None)
        session.pop('otp_expiry', None)
        session.pop('email', None)

        flash("Account created. Please login.")
        return redirect(url_for('login'))

    return render_template('verify_otp.html')


@app.route('/resend', methods=['POST'])
def resend_otp():
    # ✅ Priority check: are we verifying registration OTP?
    if session.get('temp_user') and session.get('email'):
        # Registration flow
        email = session['email']
        otp = generate_otp()
        session.permanent = True
        session['otp'] = otp
        session['otp_expiry'] = (datetime.now() + timedelta(minutes=10)).timestamp()
        send_otp_email(email, otp)
        flash("New OTP sent to your email.")
        return redirect(url_for('verify_otp'))

    # ✅ Else, password reset flow
    elif session.get('reset_email'):
        email = session['reset_email']
        user = User.query.filter_by(email=email).first()
        otp = generate_otp()
        if user:
            user.otp = otp
            db.session.commit()
        session.permanent = True
        session['otp_expiry'] = (datetime.now() + timedelta(minutes=10)).timestamp()
        send_password_reset_otp(email, otp)
        flash("New OTP sent to your email.")
        return redirect(url_for('reset_verify_otp'))

    flash("Session expired. Please start again.")
    return redirect(url_for('home'))




# Login
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']

        user = User.query.filter_by(email=email).first()
        if user and user.otp_verified and user.check_password(password):
            if user.attempted:
                return render_template("result.html")
            session['email'] = email
            return redirect(url_for('instructions'))
        else:
            flash("Invalid credentials or unverified account.")
    return render_template('login.html')

# Instructions Page
@app.route('/instructions')
def instructions():
    if 'email' not in session:
        return redirect(url_for('login'))
    return render_template('instructions.html')


# Start Test
@app.route('/test')
def test():
    email = session.get('email')
    if not email:
        return redirect(url_for('login'))

    user = User.query.filter_by(email=email).first()
    if user and user.attempted:
        flash('You have already attempted the test.')
        return render_template('result.html')

    # ✅ Generate fresh questions
    all_questions = load_questions_from_excel()
    sample_size = min(40, len(all_questions))
    selected_questions = random.sample(all_questions, sample_size)

    # ✅ Save to session for test flow
    session['questions'] = selected_questions
    session['start_time'] = time.time()

    return render_template('quiz.html', questions=selected_questions, time_limit=3600)

# Submit Test
@app.route('/submit', methods=['POST'])
def submit():
    email = session.get('email')
    if not email:
        return redirect(url_for('login'))

    # cheated = request.form.get('cheated') == 'true'
    submitted_answers = request.form
    questions = session.get('questions', [])
    
    correct = 0
    for idx, q in enumerate(questions):
        qid = f'q{idx}'
        user_ans = submitted_answers.get(qid, '').lower()
        if user_ans == q['answer']:
            correct += 1

    score = int((correct / len(questions)) * 100)
    role = classify_role(score)

    # Force override if cheating
    # if cheated:
    #     role = "Disqualified for Cheating"
    #     score = 0
    #     correct = 0

    # Mark user as attempted
    user = User.query.filter_by(email=email).first()
    user.attempted = True
    db.session.commit()

    # Save result
    result = Result(email=email, score=score, correct=correct, role=role)
    db.session.add(result)
    db.session.commit()

    return render_template("result.html", score=score, role=role, correct=correct, total=len(questions))

@app.route('/download-pdf')
def download_pdf():
    email = session.get('email')
    result = Result.query.filter_by(email=email).order_by(Result.id.desc()).first()

    if not result:
        return "Result not found"

    html = render_template("result_pdf.html", 
        email=email,
        score=result.score,
        correct=result.correct,
        # correct=int(result.score * 40 / 100),
        total=40,
        role=result.role,
        timestamp=datetime.now().strftime("%Y-%m-%d %H:%M")
    )

    buffer = BytesIO()
    pisa.CreatePDF(html, dest=buffer)
    buffer.seek(0)

    response = make_response(buffer.read())
    response.headers['Content-Type'] = 'application/pdf'
    response.headers['Content-Disposition'] = 'attachment; filename=result.pdf'
    return response

@app.after_request
def add_no_cache_headers(response):
    response.headers['Cache-Control'] = 'no-store, no-cache, must-revalidate, post-check=0, pre-check=0, max-age=0'
    response.headers['Pragma'] = 'no-cache'
    response.headers['Expires'] = '-1'
    return response

# Admin Login
@app.route('/admin-login', methods=['GET', 'POST'])
def admin_login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        if email == Config.ADMIN_EMAIL and password == Config.ADMIN_PASSWORD:
            session['admin'] = True
            return redirect(url_for('admin_dashboard'))
        else:
            flash("Invalid admin credentials.")
    return render_template('admin_login.html')

# Admin Dashboard
@app.route('/admin-dashboard')
def admin_dashboard():
    if not session.get('admin'):
        return redirect(url_for('admin_login'))

    users = User.query.all()
    results = Result.query.all()
    return render_template('admin.html', users=users, results=results)

# Admin: Reset student status
@app.route('/admin/reset/<int:user_id>')
def admin_reset(user_id):
    if not session.get('admin'):
        return redirect(url_for('admin_login'))

    user = User.query.get(user_id)
    if user:
        user.attempted = False
        db.session.commit()
        flash(f"Reset attempt status for {user.email}")
    return redirect(url_for('admin_dashboard'))

# Admin: Download all results as CSV
@app.route('/admin/download-results')
def download_all_results():
    if not session.get('admin'):
        return redirect(url_for('admin_login'))

    import csv
    from flask import Response
    results = Result.query.all()

    si = BytesIO()
    si.write("Email,Score,Role\n".encode())

    for r in results:
        line = f"{r.email},{r.score},{r.role}\n"
        si.write(line.encode())

    si.seek(0)
    return Response(
        si,
        mimetype='text/csv',
        headers={'Content-Disposition': 'attachment; filename=all_results.csv'}
    )

@app.route('/admin/download/<int:user_id>', endpoint='download_user_result')
def download_user_result(user_id):
    if not session.get('admin'):
        return redirect(url_for('admin_login'))

    user = User.query.get(user_id)
    if not user:
        flash("User not found.")
        return redirect(url_for('admin_dashboard'))

    result = Result.query.filter_by(email=user.email).order_by(Result.id.desc()).first()
    if not result:
        flash("This user has not attempted the test yet.")
        return redirect(url_for('admin_dashboard'))

    try:
        html = render_template("result_pdf.html",
            email=user.email,
            score=result.score,
            correct=result.correct,
            total=40,
            role=result.role,
            timestamp=datetime.now().strftime("%Y-%m-%d %H:%M")
        )

        buffer = BytesIO()
        pisa.CreatePDF(html, dest=buffer)
        buffer.seek(0)

        response = make_response(buffer.read())
        response.headers['Content-Type'] = 'application/pdf'
        response.headers['Content-Disposition'] = f'attachment; filename={user.email}_result.pdf'
        return response

    except Exception as e:
        return f"PDF generation failed: {str(e)}"


@app.route('/forgot-password', methods=['GET', 'POST'])
def forgot_password():
    if request.method == 'POST':
        email = request.form['email'].strip()
        user = User.query.filter_by(email=email).first()
        if not user:
            flash("No account exists with this email. Please register first.")
            return redirect(url_for('forgot_password'))

        otp = generate_otp()
        user.otp = otp
        db.session.commit()
        send_password_reset_otp(email, otp)
        session.permanent = True
        session['reset_email'] = email

        flash("An OTP has been sent to your registered email.")
        return redirect(url_for('reset_verify_otp'))
    return render_template('forgot_password.html')



@app.route('/reset-password', methods=['GET', 'POST'])
def reset_password():
    if not session.get('otp_verified_for_reset'):
        flash("Unauthorized access.")
        return redirect(url_for('login'))

    if request.method == 'POST':
        new_password = request.form['password']
        confirm_password = request.form['confirm_password']

        # ✅ Add strong password check
        import re
        def is_strong_password(pw):
            return (
                len(pw) >= 8 and
                re.search(r'\d', pw) and
                re.search(r'[!@#$%^&*()_+\-=\[\]{};\'":\\|,.<>\/?]', pw)
            )

        if not is_strong_password(new_password):
            flash("Password must be at least 8 characters long and include at least one number and one special character.")
            return redirect(url_for('reset_password'))

        if new_password != confirm_password:
            flash("Passwords do not match.")
            return redirect(url_for('reset_password'))

        email = session.get('reset_email')
        user = User.query.filter_by(email=email).first()
        if user:
            user.set_password(new_password)
            user.otp = None
            db.session.commit()
            session.pop('otp_verified_for_reset', None)
            session.pop('reset_email', None)
            flash("Password reset successful. Please log in.")
            return redirect(url_for('login'))

    return render_template('reset_password.html')



@app.route('/reset-verify-otp', methods=['GET', 'POST'])
def reset_verify_otp():
    if request.method == 'POST':
        email = session.get('reset_email')
        otp_input = ''.join([request.form.get(f'otp{i}', '') for i in range(6)])
        user = User.query.filter_by(email=email).first()

        if not user or not user.otp:
            flash("Session expired or invalid. Please try again.")
            return redirect(url_for('forgot_password'))

        if otp_input != user.otp:
            flash("Invalid OTP. Please try again.")
            return redirect(url_for('reset_verify_otp'))

        # ✅ OTP matched: Invalidate it immediately
        session['otp_verified_for_reset'] = True
        user.otp = None
        db.session.commit()
        return redirect(url_for('reset_password'))

    return render_template('reset_verify_otp.html')

@app.errorhandler(404)
def page_not_found(e):
    return render_template('404.html'), 404



if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True)
