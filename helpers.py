import pandas as pd
import random
import os
from extensions import mail
from flask_mail import Message
from flask import current_app

def send_otp_email(email, otp):
    msg = Message(
        'Bihar Skill Development Mission - Test Registration OTP',
        sender=current_app.config['MAIL_USERNAME'],
        recipients=[email]
    )
    msg.body = (
        f"Dear Candidate,\n\n"
        f"Thank you for registering for the RTD-BSDM test in training partnership with Orbiqe Technologies Pvt. Ltd.\n\n"
        f"Your One-Time Password (OTP) for completing your registration is:\n\n"
        f"    {otp}\n\n"
        f"Please enter this OTP to verify your email address and complete your registration.\n"
        f"Do not share this OTP with anyone for security reasons.\n\n"
        f"If you did not initiate this registration, please ignore this email.\n\n"
        f"Best regards,\n"
        f"Orbiqe Technologies Pvt. Ltd.\n"
    )
    mail.send(msg)

def generate_otp():
    return str(random.randint(100000, 999999))

def load_questions_from_excel():
    BASE_DIR = os.path.dirname(os.path.abspath(__file__))
    filepath = os.path.join(BASE_DIR, 'questions.xlsx')
    df = pd.read_excel(filepath)
    questions = []
    for _, row in df.iterrows():
        questions.append({
            'question': row['question'],
            'options': {
                'a': row['a'],
                'b': row['b'],
                'c': row['c'],
                'd': row['d'],
            },
            'answer': row['correct'].lower()
        })
    return questions

def classify_role(score):
    if score < 50:
        return 'Fail'
    elif score < 60:
        return 'QA'
    elif score < 70:
        return 'DBMS'
    else:
        return 'AI DevOps'

def send_password_reset_otp(email, otp):
    msg = Message(
        "Bihar Skill Development Mission - Password Reset OTP",
        sender=current_app.config['MAIL_USERNAME'],
        recipients=[email]
    )
    msg.body = (
        f"Dear Candidate,\n\n"
        f"A request to reset your password was received for your RTD-BSDM account in training partnership with Orbiqe Technologies Pvt. Ltd.\n\n"
        f"Your verification OTP is:\n\n"
        f"    {otp}\n\n"
        f"Please enter this OTP to proceed with changing your password.\n"
        f"Do not share this OTP with anyone for security reasons.\n\n"
        f"If you did not request a password change, please secure your account immediately or contact support.\n\n"
        f"Best regards,\n"
        f"Orbiqe Technologies Pvt. Ltd.\n"
    )
    mail.send(msg)
