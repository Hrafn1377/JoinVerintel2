from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel
from typing import Optional, List
from app.verification.engine import verify_posting


router = APIRouter(prefix="/api/v1", tags=["api"])


# ============================================
# REQUEST / RESPONSE MODELS
# ============================================

class VerifyRequest(BaseModel):
    posting_text: str
    company_name: Optional[str] = None
    company_domain: Optional[str] = None
    company_phone: Optional[str] = None
    claimed_country: str = "us"


class SignalResponse(BaseModel):
    label: str
    verdict: str
    score: float
    weight: float
    reason: str
    source: str


class VerifyResponse(BaseModel):
    overall_score: float
    status: str
    summary: str
    signals: List[SignalResponse]
    checks_run: int


# ============================================
# ENDPOINTS
# ============================================

@router.post("/verify", response_model=VerifyResponse)
async def api_verify(payload: VerifyRequest):
    """
    Verify a job posting and return a structured risk report.

    - **posting_text**: The full text of the job posting (required)
    - **company_name**: Company name for business registry check (optional)
    - **company_domain**: Company domain for domain age check (optional)
    - **company_phone**: Company phone for country and VOIP checks (optional)
    - **claimed_country**: ISO country code the company claims to be in (default: us)
    """
    report = await verify_posting(
        posting_text=payload.posting_text,
        company_name=payload.company_name,
        company_domain=payload.company_domain,
        company_phone=payload.company_phone,
        claimed_country=payload.claimed_country,
    )

    if report.overall_score >= 0.6:
        status = "pass"
        summary = "Looks legitimate."
    elif report.overall_score >= 0.4:
        status = "warn"
        summary = "Proceed with caution."
    else:
        status = "fail"
        summary = "High risk — do not apply."

    # Check if fraud pattern was detected and override summary
    for signal in report.signals:
        if signal.label == "Fraud pattern detected":
            summary = "Multiple fraud indicators found. Do not apply to this role."
            break

    return VerifyResponse(
        overall_score=round(report.overall_score, 4),
        status=status,
        summary=summary,
        signals=[
            SignalResponse(
                label=s.label,
                verdict=s.verdict.value,
                score=round(s.score, 4),
                weight=round(s.weight, 4),
                reason=s.reason,
                source=s.source,
            )
            for s in report.signals
        ],
        checks_run=len(report.signals),
    )
