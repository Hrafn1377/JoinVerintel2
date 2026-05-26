from fastapi import APIRouter, Request, Depends, Form
from fastapi.templating import Jinja2Templates
from fastapi.responses import HTMLResponse
from sqlalchemy.orm import Session
from typing import Optional
from app.db.session import get_db
from app.db.models import Verification
from app.auth.dependencies import get_optional_user
from app.verification.engine import verify_posting

templates = Jinja2Templates(directory="templates")

router = APIRouter(prefix="/verify", tags=["verify"])


@router.get("/")
async def verify_page(
    request: Request,
    current_user=Depends(get_optional_user),
):
    return templates.TemplateResponse(
        request=request,
        name="pages/verify/index.html",
        context={"user": current_user, "active": "verify"}
    )


@router.post("/")
async def verify_submit(
    request: Request,
    current_user=Depends(get_optional_user),
    posting_text: str = Form(...),
    company_name: Optional[str] = Form(None),
    company_domain: Optional[str] = Form(None),
    company_phone: Optional[str] = Form(None),
    claimed_country: str = Form("us"),
):
    return templates.TemplateResponse(
        request=request,
        name="pages/verify/stream.html",
        context={
            "user": current_user,
            "active": "verify",
            "posting_text": posting_text,
            "company_name": company_name,
            "company_domain": company_domain,
            "company_phone": company_phone,
            "claimed_country": claimed_country,
        }
    )


    # Save to history if user is logged in
    if current_user:
        verification = Verification(
            user_id=current_user.id,
            posting_text=posting_text,
            company_name=company_name,
            company_domain=company_domain,
            company_phone=company_phone,
            claimed_country=claimed_country,
            overall_score=report.overall_score,
            verification_status=(
                "pass" if report.overall_score >= 0.6
                else "warn" if report.overall_score >= 0.4
                else "fail"
            ),
            signals=[{
                "label": s.label,
                "verdict": s.verdict.value,
                "score": s.score,
                "weight": s.weight,
                "reason": s.reason,
                "source": s.source,
            } for s in report.signals],
        )
        db.add(verification)
        db.commit()

    return templates.TemplateResponse(
        request=request,
        name="pages/verify/results.html",
        context={
            "user": current_user,
            "active": "verify",
            "report": report,
            "posting_text": posting_text,
        }
    )
