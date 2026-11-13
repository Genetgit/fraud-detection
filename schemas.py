from pydantic import BaseModel, EmailStr, Field
from typing import Optional
from datetime import datetime


class CustomerSignup(BaseModel):
    email: EmailStr
    password: str
    full_name: str


class VerifyEmailRequest(BaseModel):
    email: EmailStr
    code: str


class StaffCreateByAdmin(BaseModel):
    email: EmailStr
    password: str
    full_name: str


class LoginRequest(BaseModel):
    email: EmailStr
    password: str


class ReportCreate(BaseModel):
    amount: float = Field(gt=0)
    suspect_info: str = Field(min_length=3, max_length=100)


class ReportDecision(BaseModel):
    status: str  # "Investigating" | "Resolved" | "Dismissed"


class StaffMessage(BaseModel):
    message: str = Field(min_length=1, max_length=500)


class ReportOut(BaseModel):
    id: int
    amount: float
    suspect_info: str
    risk_score: int
    prior_reports_count: int
    status: str
    staff_message: Optional[str]
    created_at: datetime

    class Config:
        from_attributes = True
