from fastapi import APIRouter, Request, Depends, Form
from fastapi.responses import StreamingResponse
from fastapi.templating import Jinja2Templates
from sqlalchemy.orm import Session
from typing import Optional, AsyncGenerator
from app.db.session import get_db
from app.auth.dependencies import get_optional_user
from app.verification.engine import (
    run_nlp_checks,
    detect_fraud_patterns,
    VerificationReport
)
from app.verification.domain import check_domain_age
from app.verification.company import check_business_registry
from app.verification.phone import check_phone_country
from app.verification.voip import check_voip
from app.scoring.models import Signal, Verdict
import asyncio

templates = Jinja2Templates(directory="templates")

router = APIRouter(prefix="/verify-stream", tags=["verify_stream"])

STATUS_ID_MAP = {
    "Fraud language": "status-fraud-language",
    "Urgency pressure": "status-urgency-pressure",
    "Personal info requests": "status-personal-info",
    "Salary sanity": "status-salary-sanity",
    "Currency conversion": "status-currency-conversion",
    "Domain age": "status-domain-age",
    "Business registry": "status-business-registry",
    "Phone country": "status-phone-country",
    "VOIP detection": "status-voip",
    "Fraud pattern detected": "status-fraud-pattern",
    "Fraud indicators": "status-fraud-pattern",
}


def render_status_running(label: str) -> str:
    status_id = STATUS_ID_MAP.get(label, "")
    if not status_id:
        return ""
    return f"""
<div id="{status_id}" hx-swap-oob="true" class="status-row status-row--running">
    <span class="status-light"></span>
    <span class="status-name">{label}</span>
    <span class="status-state">Checking...</span>
</div>
"""


def render_status_done(signal: Signal) -> str:
    status_id = STATUS_ID_MAP.get(signal.label, "")
    if not status_id:
        return ""
    verdict = signal.verdict.value
    state_label = verdict.upper()
    return f"""
<div id="{status_id}" hx-swap-oob="true" class="status-row status-row--{verdict}">
    <span class="status-light"></span>
    <span class="status-name">{signal.label}</span>
    <span class="status-state">{state_label}</span>
</div>
"""


def render_signal_card(signal: Signal) -> str:
    verdict_class = signal.verdict.value
    score_pct = int(signal.score * 100)
    return f"""
<div class="signal-card signal-card--{verdict_class} signal-card--animate">
    <div class="signal-card-header">
        <div class="signal-card-left">
            <span class="signal-verdict-dot signal-dot--{verdict_class}"></span>
            <span class="signal-label">{signal.label}</span>
        </div>
        <div class="signal-card-right">
            <span class="signal-score">{score_pct}%</span>
            <span class="signal-badge signal-badge--{verdict_class}">{signal.verdict.value.upper()}</span>
        </div>
    </div>
    <p class="signal-reason">{signal.reason}</p>
    <p class="signal-source">Source: {signal.source}</p>
</div>
"""


def render_score_update(report: VerificationReport) -> str:
    score_pct = int(report.overall_score * 100)
    if report.overall_score >= 0.6:
        score_class = "score--pass"
        label = "Looks legitimate"
    elif report.overall_score >= 0.4:
        score_class = "score--warn"
        label = "Proceed with caution"
    else:
        score_class = "score--fail"
        label = "High risk — do not apply"

    return f"""
<div id="score-card" hx-swap-oob="true">
    <div class="results-score-card">
        <div class="results-score-wrap">
            <span class="results-score-number {score_class}">{score_pct}%</span>
            <div class="results-score-info">
                <p class="results-score-label">{label}</p>
                <p class="results-score-sub">Based on {len(report.signals)} checks</p>
            </div>
        </div>
    </div>
</div>
"""


async def stream_verification(
    posting_text: str,
    company_name: Optional[str],
    company_domain: Optional[str],
    company_phone: Optional[str],
    claimed_country: str,
) -> AsyncGenerator[str, None]:

    report = VerificationReport()

    # NLP checks
    nlp_labels = [
        "Fraud language",
        "Urgency pressure",
        "Personal info requests",
        "Salary sanity",
        "Currency conversion",
    ]

    for label in nlp_labels:
        yield render_status_running(label)
        await asyncio.sleep(0.3)

    nlp_signals = run_nlp_checks(posting_text)
    for signal in nlp_signals:
        report.signals.append(signal)
        report.compute()
        yield render_status_done(signal)
        yield render_signal_card(signal)
        yield render_score_update(report)
        await asyncio.sleep(0.15)

    # Domain age
    if company_domain:
        yield render_status_running("Domain age")
        await asyncio.sleep(0.3)
        signal = await check_domain_age(company_domain)
        report.signals.append(signal)
        report.compute()
        yield render_status_done(signal)
        yield render_signal_card(signal)
        yield render_score_update(report)

    # Business registry
    if company_name:
        yield render_status_running("Business registry")
        await asyncio.sleep(0.3)
        signal = await check_business_registry(company_name, claimed_country)
        report.signals.append(signal)
        report.compute()
        yield render_status_done(signal)
        yield render_signal_card(signal)
        yield render_score_update(report)

    # Phone checks
    if company_phone:
        yield render_status_running("Phone country")
        await asyncio.sleep(0.3)
        signal = check_phone_country(company_phone, claimed_country)
        report.signals.append(signal)
        report.compute()
        yield render_status_done(signal)
        yield render_signal_card(signal)
        yield render_score_update(report)

        yield render_status_running("VOIP detection")
        await asyncio.sleep(0.3)
        signal = await check_voip(company_phone)
        report.signals.append(signal)
        report.compute()
        yield render_status_done(signal)
        yield render_signal_card(signal)
        yield render_score_update(report)

    # Fraud pattern
    yield render_status_running("Fraud pattern analysis")
    await asyncio.sleep(0.4)
    report = detect_fraud_patterns(report)
    report.compute()

    for signal in report.signals:
        if signal.label in ("Fraud pattern detected", "Fraud indicators"):
            yield render_status_done(signal)
            yield render_signal_card(signal)
            yield render_score_update(report)

    # If no fraud pattern signal was added mark it as pass
    fraud_labels = [s.label for s in report.signals]
    if "Fraud pattern detected" not in fraud_labels and "Fraud indicators" not in fraud_labels:
        yield f"""
<div id="status-fraud-pattern" hx-swap-oob="true" class="status-row status-row--pass">
    <span class="status-light"></span>
    <span class="status-name">Fraud pattern analysis</span>
    <span class="status-state">PASS</span>
</div>
"""

    yield """<div id="verify-actions" hx-swap-oob="true" class="results-actions results-actions--visible">
    <a href="/verify/" class="btn btn--secondary">Verify another posting</a>
</div>"""


@router.post("/")
async def verify_stream_endpoint(
    request: Request,
    current_user=Depends(get_optional_user),
    posting_text: str = Form(...),
    company_name: Optional[str] = Form(None),
    company_domain: Optional[str] = Form(None),
    company_phone: Optional[str] = Form(None),
    claimed_country: str = Form("us"),
):
    return StreamingResponse(
        stream_verification(
            posting_text=posting_text,
            company_name=company_name,
            company_domain=company_domain,
            company_phone=company_phone,
            claimed_country=claimed_country,
        ),
        media_type="text/html",
    )
