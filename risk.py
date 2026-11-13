"""
Risk scoring logic.
Given a new report and how many prior reports exist against the same
suspect, calculate a 0-100 risk score to help staff prioritize review.
"""

from sqlalchemy.orm import Session
from .database import Report


def count_prior_reports(db: Session, suspect_info: str) -> int:
    return db.query(Report).filter(Report.suspect_info == suspect_info).count()


def calculate_risk_score(amount: float, prior_reports_count: int, has_screenshot: bool) -> int:
    score = 0

    # Factor 1: amount
    if amount > 2000:
        score += 25
    elif amount > 500:
        score += 15
    else:
        score += 5

    # Factor 2: repeat suspect (strongest signal)
    score += min(prior_reports_count * 20, 60)

    # Factor 3: evidence quality
    if has_screenshot:
        score += 10

    return min(score, 100)


def risk_label(score: int) -> str:
    if score >= 70:
        return "High"
    if score >= 40:
        return "Medium"
    return "Low"
