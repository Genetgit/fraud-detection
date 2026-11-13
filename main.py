import os
import uuid
import random
from fastapi import FastAPI, Depends, HTTPException, UploadFile, File, Header
from sqlalchemy.orm import Session

from . import auth, schemas, risk
from .database import init_db, get_db, SessionLocal, User, Report
from fastapi import FastAPI, Depends, HTTPException, UploadFile, File, Header, Form
from fastapi.middleware.cors import CORSMiddleware

app = FastAPI(title="Fraud Report Platform")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5173"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

UPLOAD_DIR = "uploads"
ALLOWED_IMAGE_TYPES = {"image/jpeg", "image/png", "image/webp"}
MAX_UPLOAD_BYTES = 5 * 1024 * 1024  # 5 MB


@app.on_event("startup")
def on_startup():
    init_db()
    os.makedirs(UPLOAD_DIR, exist_ok=True)
    
    # ሲስተሙ ሲነሳ አንድ ዋና Admin ከሌለ በራስ-ሰር ይፈጥራል
    db = SessionLocal()
    if not db.query(User).filter(User.role == "admin").first():
        default_admin = User(
            email="admin@cbe.com.et",
            password_hash=auth.hash_password("AdminPass123"),
            role="admin",
            full_name="System Administrator",
            is_verified=True,
        )
        db.add(default_admin)
        db.commit()
    db.close()


# ---------- Auth helpers ----------

def get_current_user(authorization: str = Header(None), db: Session = Depends(get_db)) -> User:
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Missing or invalid token")
    token = authorization.split(" ", 1)[1]
    payload = auth.decode_access_token(token)
    if not payload:
        raise HTTPException(status_code=401, detail="Invalid or expired token")
    user = db.query(User).filter(User.id == int(payload["sub"])).first()
    if not user:
        raise HTTPException(status_code=401, detail="User not found")
    return user


def require_staff(user: User = Depends(get_current_user)) -> User:
    if user.role != "staff":
        raise HTTPException(status_code=403, detail="Staff access only")
    return user


def require_admin(user: User = Depends(get_current_user)) -> User:
    if user.role != "admin":
        raise HTTPException(status_code=403, detail="Admin access only")
    return user


# ---------- Signup / Verify / Login ----------

@app.post("/signup/customer")
def signup_customer(data: schemas.CustomerSignup, db: Session = Depends(get_db)):
    if not auth.is_real_email_domain(data.email):
        raise HTTPException(
            status_code=400, 
            detail="Invalid email domain. Please enter a real, working email address."
        )
    if db.query(User).filter(User.email == data.email).first():
        raise HTTPException(status_code=400, detail="Email already registered")

    otp_code = str(random.randint(100000, 999999))

    user = User(
        email=data.email,
        password_hash=auth.hash_password(data.password),
        role="customer",
        full_name=data.full_name,
        is_verified=False,
        verification_code=otp_code,
    )
    db.add(user)
    db.commit()

    # ለሙከራ ኮዱን ተርሚናል ላይ እናሳያለን (በኋላ SMTP ይገባበታል)
    print(f"DEBUG - Verification code for {data.email}: {otp_code}")

    return {"message": "Account created. Please check your email for the 6-digit verification code."}


@app.post("/verify-email")
def verify_email(data: schemas.VerifyEmailRequest, db: Session = Depends(get_db)):
    user = db.query(User).filter(User.email == data.email).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    if user.is_verified:
        return {"message": "Email already verified"}
    if user.verification_code != data.code:
        raise HTTPException(status_code=400, detail="Invalid verification code")

    user.is_verified = True
    user.verification_code = None
    db.commit()
    return {"message": "Email verified successfully. You can now log in."}


@app.post("/admin/create-staff")
def create_staff(
    data: schemas.StaffCreateByAdmin,
    admin: User = Depends(require_admin),
    db: Session = Depends(get_db),
):
    if not auth.is_valid_staff_email(data.email):
        raise HTTPException(status_code=400, detail="Staff email must end with @cbe.com.et")
    if not auth.is_strong_password(data.password):
        raise HTTPException(
            status_code=400,
            detail="Password must be 8+ chars with upper, lower, and a digit",
        )
    if db.query(User).filter(User.email == data.email).first():
        raise HTTPException(status_code=400, detail="Email already registered")

    user = User(
        email=data.email,
        password_hash=auth.hash_password(data.password),
        role="staff",
        full_name=data.full_name,
        is_verified=True,
    )
    db.add(user)
    db.commit()
    return {"message": f"Staff account created for {data.email}"}


@app.post("/login")
def login(data: schemas.LoginRequest, db: Session = Depends(get_db)):
    user = db.query(User).filter(User.email == data.email).first()
    if not user:
        raise HTTPException(status_code=401, detail="Invalid email or password")

    if not user.is_verified:
        raise HTTPException(status_code=403, detail="Please verify your email before logging in.")

    if auth.is_locked(user):
        raise HTTPException(status_code=423, detail="Account locked. Try again later.")

    if not auth.verify_password(data.password, user.password_hash):
        auth.register_failed_attempt(user, db)
        raise HTTPException(status_code=401, detail="Invalid email or password")

    auth.reset_failed_attempts(user, db)
    token = auth.create_access_token(user.id, user.role)
    return {"access_token": token, "role": user.role, "full_name": user.full_name}


# ---------- Customer endpoints ----------

@app.post("/reports", response_model=schemas.ReportOut)
def create_report(
    amount: float = Form(...),
    suspect_info: str = Form(...),
    screenshot: UploadFile = File(None),
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):

    if user.role != "customer":
        raise HTTPException(status_code=403, detail="Customer access only")

    screenshot_path = None
    if screenshot is not None:
        if screenshot.content_type not in ALLOWED_IMAGE_TYPES:
            raise HTTPException(status_code=400, detail="Only JPG, PNG, or WEBP images are allowed")
        contents = screenshot.file.read()
        if len(contents) > MAX_UPLOAD_BYTES:
            raise HTTPException(status_code=400, detail="File too large (max 5MB)")
        safe_name = f"{uuid.uuid4().hex}_{os.path.basename(screenshot.filename)}"
        screenshot_path = os.path.join(UPLOAD_DIR, safe_name)
        with open(screenshot_path, "wb") as f:
            f.write(contents)

    prior_count = risk.count_prior_reports(db, suspect_info)
    score = risk.calculate_risk_score(amount, prior_count, screenshot_path is not None)

    report = Report(
        customer_id=user.id,
        amount=amount,
        suspect_info=suspect_info,
        screenshot_path=screenshot_path,
        risk_score=score,
        prior_reports_count=prior_count,
        status="Pending",
    )
    db.add(report)
    db.commit()
    db.refresh(report)
    return report


@app.get("/reports/mine", response_model=list[schemas.ReportOut])
def my_reports(user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    if user.role != "customer":
        raise HTTPException(status_code=403, detail="Customer access only")
    return db.query(Report).filter(Report.customer_id == user.id).order_by(Report.created_at.desc()).all()


# ---------- Staff endpoints ----------

@app.get("/staff/reports", response_model=list[schemas.ReportOut])
def all_reports(staff: User = Depends(require_staff), db: Session = Depends(get_db)):
    return db.query(Report).order_by(Report.risk_score.desc()).all()


@app.patch("/staff/reports/{report_id}/decision")
def update_decision(
    report_id: int,
    data: schemas.ReportDecision,
    staff: User = Depends(require_staff),
    db: Session = Depends(get_db),
):
    report = db.query(Report).filter(Report.id == report_id).first()
    if not report:
        raise HTTPException(status_code=404, detail="Report not found")
    if data.status not in {"Investigating", "Resolved", "Dismissed"}:
        raise HTTPException(status_code=400, detail="Invalid status")
    report.status = data.status
    report.assigned_staff_id = staff.id
    db.commit()
    return {"message": "Status updated"}


@app.patch("/staff/reports/{report_id}/message")
def send_message(
    report_id: int,
    data: schemas.StaffMessage,
    staff: User = Depends(require_staff),
    db: Session = Depends(get_db),
):
    report = db.query(Report).filter(Report.id == report_id).first()
    if not report:
        raise HTTPException(status_code=404, detail="Report not found")
    report.staff_message = data.message
    db.commit()
    return {"message": "Message sent to customer"}
