# AI-Assisted Bank Fraud Report & Triage Platform

A prototype backend for a platform where bank customers report suspected
fraud, and a lightweight risk-scoring layer helps cyber security staff
prioritize which reports to review first.

> **Disclaimer:** This is a student/portfolio prototype and proof of concept.
> It is not affiliated with, endorsed by, or connected to the Commercial
> Bank of Ethiopia (CBE) or any other financial institution.

## Problem

When a customer reports fraud, staff have to manually read and investigate
every report in the order it arrives. This project explores how a simple
risk-scoring layer can help staff see high-priority cases (repeat suspects,
large amounts) first, while the final decision always stays with a human.

## Features

- Customer signup/login and staff signup/login (separate roles)
- Customers submit fraud reports with an optional screenshot
- Automatic risk scoring (0-100) based on amount, repeat-suspect count,
  and evidence quality
- Staff dashboard data sorted by risk score
- Staff can update report status (Investigating / Resolved / Dismissed)
  and send a short message back to the customer
- Security: bcrypt password hashing, account lockout after failed logins,
  staff-only access codes, strong-password enforcement, file-type/size
  validation on uploads, role-based access control, SQL-injection
  protection via the ORM

## Tech stack

- **Backend:** FastAPI (Python)
- **Database:** SQLite via SQLAlchemy ORM
- **Auth:** JWT tokens, bcrypt password hashing

## Project structure

```
fraud-platform/
├── app/
│   ├── main.py        # FastAPI routes
│   ├── database.py    # SQLAlchemy models (User, Report)
│   ├── auth.py         # hashing, JWT, rate limiting
│   ├── risk.py          # risk scoring logic
│   └── schemas.py      # request/response validation
├── requirements.txt
└── README.md
```

## Running it locally

```bash
pip install -r requirements.txt
uvicorn app.main:app --reload
```

Then open `http://127.0.0.1:8000/docs` for interactive API docs.

## How it works

1. Customer signs up, logs in, and submits a report (amount, suspect
   phone/account, optional screenshot).
2. The backend counts how many prior reports exist for the same suspect
   and calculates a risk score.
3. Staff sign up using an access code (simulating an admin-granted
   invite), log in, and see all reports sorted by risk score, highest
   first.
4. Staff investigate and update the report's status, optionally leaving
   a message the customer can see.

## Security notes

- Passwords are never stored in plain text — only bcrypt hashes.
- 5 failed login attempts locks an account for 15 minutes.
- Staff accounts require a strong password and a valid access code.
- All database queries go through the SQLAlchemy ORM (parameterized
  queries), which prevents SQL injection by construction.
- Uploaded files are checked for type (JPG/PNG/WEBP only) and size
  (5MB max) before being saved under a randomized filename.

## Future improvements

- OCR to auto-extract amount/date/recipient from screenshots
- Two-factor authentication for staff accounts
- Real-time notifications instead of polling
- Admin panel for creating staff accounts (replacing the shared access code)
