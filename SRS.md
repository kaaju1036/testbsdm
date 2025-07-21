# Software Requirements Specification (SRS)

## 1. Project Title
**MCQ Test Web Portal with Cheating Detection and Role Assignment**

----------------------------------------------------------------------------------------------------------------------------------

## 2. Introduction

### 2.1 Purpose
Develop a secure web-based MCQ exam system with email OTP registration, random question selection from an Excel bank, cheating detection, scoring, and role assignment.

### 2.2 Scope
- Email registration with OTP verification
- 20 randomized MCQs per test
- 20-minute time limit with auto-submit
- Cheating detection on tab/app switching
- Result display with eligibility role and PDF download
- Admin email Google Form links to eligible users

----------------------------------------------------------------------------------------------------------------------------------

## 3. Overall Description

### 3.1 User Classes
- **Student/User:** Registers, takes test, views result
- **Admin:** Manages data, sends form links

### 3.2 Product Perspective
Standalone Flask web app using SQLite, HTML/CSS/JS frontend.

----------------------------------------------------------------------------------------------------------------------------------

## 4. Functional Requirements

### 4.1 User Registration
- Enter email → receive OTP → verify OTP → set password

### 4.2 Login
- Login only if verified and not already attempted

### 4.3 MCQ Test
- 20 random questions from Excel question bank
- Timer displayed (20 minutes)
- Auto-submit on time expiry
- Cheating detection via tab/app switching → disqualification

### 4.4 Cheating Detection
- 1 tab/app switch → immediate fail (no retries)
- Role set to "Disqualified for Cheating"
- Score and correct answers = 0

### 4.5 Result Display
- Shows correct answers, score, role, friendly message
- Downloadable PDF

### 4.6 Role Classification
- <50%: Fail
- 50–59%: QA
- 60–69%: DBMS
- 70%+: AI DevOps

### 4.7 Result Storage
- Store email, password hash, attempted flag, score, role

### 4.8 Email Google Form Link
- Admin sends Google Form URL to eligible users (not failed/disqualified)

----------------------------------------------------------------------------------------------------------------------------------

## 5. Non-Functional Requirements

### 5.1 Security
- Hashed passwords
- OTP verification
- Cache disabled on sensitive pages
- Prevent test reattempt by browser back

### 5.2 Usability
- Mobile responsive design
- Clear instructions and messages

### 5.3 Performance
- Lightweight Flask app, suitable for moderate users

### 5.4 Portability
- Runs on any Flask-supported environment

----------------------------------------------------------------------------------------------------------------------------------

## 6. External Interfaces

### 6.1 User Interface
- Responsive HTML/CSS/JS forms and pages

### 6.2 Software Interface
- Flask, SQLite, Flask-Mail, pandas, xhtml2pdf

----------------------------------------------------------------------------------------------------------------------------------

## 7. System Architecture

+------------+       +-------------+       +-------------+
|   Browser  | <---> | Flask App   | <---> |   Database  |
| (Frontend) |       | (Backend)   |       |  (SQLite)   |
+------------+       +-------------+       +-------------+
          ↑                 ↓
    Google Form Link Sending (via Flask-Mail)

----------------------------------------------------------------------------------------------------------------------------------

## 8. Technologies Used
- Python Flask
- SQLite3 + SQLAlchemy
- HTML, CSS, JavaScript
- pandas (Excel)
- Flask-Mail (Email OTP)
- xhtml2pdf (PDF)

----------------------------------------------------------------------------------------------------------------------------------

## 9. Future Enhancements
- Admin dashboard for managing questions and users
- Detailed answer review post exam
- Email notification on result
- IP/geolocation anti-cheating features

-----------------------------------------------------------x----------------------------------------------------------------------