from app.scoring.models import Signal, Verdict, VerificationReport
from typing import List, Optional
import re


# ============================================
# PHRASE LISTS
# ============================================

# Tier 1 - Near certain fraud. One hit = FAIL
TIER_1_FRAUD = [
    "be your own boss",
    "unlimited earning potential",
    "pay for your own training",
    "pay for your own kit",
    "pay for your own equipment",
    "multi-level marketing",
    "network marketing",
    "passive income",
    "ground floor opportunity",
    "financial freedom",
    "residual income",
    "downline",
    "upline",
    "distributor opportunity",
]

# Tier 2 - Strong warning. Two hits = FAIL, one hit = WARN
TIER_2_FRAUD = [
    "no experience necessary",
    "no experience needed",
    "no experience required",
    "work from anywhere",
    "make money from home",
    "earn from home",
    "be your own boss",
    "set your own hours",
    "unlimited income",
    "six figures",
    "six-figure income",
]

# Tier 3 - Context dependent. Only meaningful in combination
TIER_3_FRAUD = [
    "immediate start",
    "urgently hiring",
    "positions filling fast",
    "apply immediately",
    "limited spots available",
    "don't miss out",
    "act now",
    "must apply today",
    "hiring now",
]

# Personal info requests - always a red flag in a job posting
PERSONAL_INFO_REQUESTS = [
    "social security",
    "ssn",
    "bank account",
    "routing number",
    "passport number",
    "date of birth",
    "mother's maiden name",
    "copy of your id",
    "copy of your passport",
    "wire transfer",
    "western union",
    "money gram",
]

# Urgency pressure phrases
URGENCY_PHRASES = [
    "apply immediately",
    "limited spots",
    "act now",
    "don't miss out",
    "positions filling fast",
    "immediate start",
    "urgently hiring",
    "must apply today",
]

# Typical annual salary ranges by job category (USD)
SALARY_SANITY_RANGES = {
    "data entry": (25000, 55000),
    "customer service": (28000, 60000),
    "administrative": (30000, 70000),
    "receptionist": (28000, 50000),
    "warehouse": (30000, 60000),
    "driver": (35000, 80000),
    "full stack": (65000, 160000),
    "full stack developer": (65000, 160000),
    "full-stack": (65000, 160000),
    "frontend developer": (55000, 140000),
    "backend developer": (60000, 150000),
    "web developer": (50000, 130000),
    "wordpress developer": (45000, 120000),
    "software engineer": (70000, 180000),
    "developer": (55000, 160000),
    "designer": (45000, 130000),
    "marketing": (40000, 120000),
    "sales": (35000, 150000),
    "manager": (50000, 180000),
    "director": (80000, 300000),
    "nurse": (55000, 120000),
    "teacher": (35000, 80000),
    "accountant": (45000, 120000),
    "analyst": (50000, 130000),
}

# Approximate USD value of common foreign annual salary ranges
FOREIGN_SALARY_AS_USD = [
    {
        "currency": "INR",
        "country": "India",
        "min": 300000,
        "max": 2000000,
        "note": "Indian rupee annual salaries commonly range ₹3-20 lakh"
    },
    {
        "currency": "PHP",
        "country": "Philippines",
        "min": 200000,
        "max": 1000000,
        "note": "Philippine peso annual salaries commonly range ₱200k-1M"
    },
    {
        "currency": "PKR",
        "country": "Pakistan",
        "min": 500000,
        "max": 3000000,
        "note": "Pakistani rupee annual salaries commonly range ₨500k-3M"
    },
    {
        "currency": "NGN",
        "country": "Nigeria",
        "min": 1000000,
        "max": 10000000,
        "note": "Nigerian naira annual salaries commonly range ₦1M-10M"
    },
    {
        "currency": "BDT",
        "country": "Bangladesh",
        "min": 300000,
        "max": 2000000,
        "note": "Bangladeshi taka annual salaries commonly range ৳300k-2M"
    },
    {
        "currency": "GHS",
        "country": "Ghana",
        "min": 4000,
        "max": 12000,
        "note": "Ghanaian cedi annual salaries approximately $4k-12k USD"
    },
]


# ============================================
# NLP CHECKS
# ============================================

def check_fraud_language(text: str) -> Signal:
    text_lower = text.lower()
    tier1_found = [p for p in TIER_1_FRAUD if p in text_lower]
    tier2_found = [p for p in TIER_2_FRAUD if p in text_lower]

    if tier1_found:
        return Signal(
            label="Fraud language",
            verdict=Verdict.FAIL,
            score=0.0,
            weight=0.8,
            reason=f"'{tier1_found[0]}' — this phrase belongs in scam postings and MLM pitches. Not legitimate job postings.",
            source="NLP"
        )

    if len(tier2_found) >= 2:
        return Signal(
            label="Fraud language",
            verdict=Verdict.FAIL,
            score=0.0,
            weight=0.8,
            reason=f"Multiple red flag phrases found: {', '.join(tier2_found[:2])}. This combination is a strong indicator of fraud.",
            source="NLP"
        )

    if tier2_found:
        return Signal(
            label="Fraud language",
            verdict=Verdict.WARN,
            score=0.3,
            weight=0.8,
            reason=f"Found a phrase worth noting: '{tier2_found[0]}'. Not conclusive on its own, but worth keeping in mind.",
            source="NLP"
        )

    return Signal(
        label="Fraud language",
        verdict=Verdict.PASS,
        score=1.0,
        weight=0.8,
        reason="No scam language found.",
        source="NLP"
    )


def check_urgency(text: str) -> Signal:
    text_lower = text.lower()
    found = [phrase for phrase in URGENCY_PHRASES if phrase in text_lower]

    if not found:
        return Signal(
            label="Urgency pressure",
            verdict=Verdict.PASS,
            score=1.0,
            weight=0.3,
            reason="No pressure tactics found.",
            source="NLP"
        )

    return Signal(
        label="Urgency pressure",
        verdict=Verdict.WARN,
        score=0.4,
        weight=0.3,
        reason=f"'{found[0]}' — legitimate employers don't pressure candidates. This is a warning sign.",
        source="NLP"
    )


def check_personal_info_requests(text: str) -> Signal:
    text_lower = text.lower()
    found = [p for p in PERSONAL_INFO_REQUESTS if p in text_lower]

    if not found:
        return Signal(
            label="Personal info requests",
            verdict=Verdict.PASS,
            score=1.0,
            weight=0.9,
            reason="No requests for personal or financial information found.",
            source="NLP"
        )

    return Signal(
        label="Personal info requests",
        verdict=Verdict.FAIL,
        score=0.0,
        weight=0.9,
        reason=f"This posting asks for '{found[0]}'. No legitimate employer needs this at the application stage.",
        source="NLP"
    )


# ============================================
# SALARY CHECKS
# ============================================

def extract_salary_figures(text: str) -> List[float]:
    figures = []
    dollar_pattern = r'\$\s*(\d{1,3}(?:,\d{3})+|\d{5,})([kK])?'
    matches = re.finditer(dollar_pattern, text)

    for match in matches:
        number_str = match.group(1).replace(",", "")
        multiplier = match.group(2)
        try:
            amount = float(number_str)
            if multiplier and multiplier.lower() == "k":
                amount *= 1000
            if amount < 500:
                amount *= 2080
            elif 1000 <= amount <= 15000:
                amount *= 12
            figures.append(amount)
        except ValueError:
            continue

    return figures


def check_salary_sanity(text: str) -> Signal:
    figures = extract_salary_figures(text)
    text_lower = text.lower()

    if not figures:
        return Signal(
            label="Salary sanity",
            verdict=Verdict.WARN,
            score=0.5,
            weight=0.4,
            reason="No salary listed. Legitimate employers are upfront about pay.",
            source="NLP"
        )

    for role, (min_sal, max_sal) in SALARY_SANITY_RANGES.items():
        if role in text_lower:
            for figure in figures:
                if figure > max_sal * 2:
                    return Signal(
                        label="Salary sanity",
                        verdict=Verdict.FAIL,
                        score=0.0,
                        weight=0.7,
                        reason=f"${figure:,.0f} is unrealistically high for a {role} role. A common tactic used to attract applicants to fake postings.",
                        source="NLP"
                    )
                if figure < min_sal * 0.5:
                    return Signal(
                        label="Salary sanity",
                        verdict=Verdict.WARN,
                        score=0.3,
                        weight=0.4,
                        reason=f"${figure:,.0f} is unusually low for a {role} role.",
                        source="NLP"
                    )

    return Signal(
        label="Salary sanity",
        verdict=Verdict.PASS,
        score=1.0,
        weight=0.4,
        reason="Salary looks reasonable for the role.",
        source="NLP"
    )


def check_currency_conversion(text: str) -> Signal:
    figures = extract_salary_figures(text)

    if not figures:
        return Signal(
            label="Currency conversion",
            verdict=Verdict.PASS,
            score=1.0,
            weight=0.6,
            reason="No salary figures to check.",
            source="NLP"
        )

    for figure in figures:
        for currency in FOREIGN_SALARY_AS_USD:
            if currency["min"] <= figure <= currency["max"]:
                return Signal(
                    label="Currency conversion",
                    verdict=Verdict.FAIL,
                    score=0.0,
                    weight=0.6,
                    reason=f"${figure:,.0f} matches the range of a typical {currency['country']} salary in {currency['currency']}. This is a known scam pattern — foreign salaries presented as US dollars.",
                    source="NLP"
                )

    return Signal(
        label="Currency conversion",
        verdict=Verdict.PASS,
        score=1.0,
        weight=0.6,
        reason="Salary doesn't match any known foreign currency conversion patterns.",
        source="NLP"
    )


def run_nlp_checks(text: str) -> List[Signal]:
    return [
        check_fraud_language(text),
        check_urgency(text),
        check_personal_info_requests(text),
        check_salary_sanity(text),
        check_currency_conversion(text),
    ]


# ============================================
# MAIN ENGINE
# ============================================

def detect_fraud_patterns(report: VerificationReport) -> VerificationReport:
    signals_by_label = {s.label: s for s in report.signals}

    fraud_indicators = []

    salary_sanity = signals_by_label.get("Salary sanity")
    currency_conversion = signals_by_label.get("Currency conversion")
    phone_country = signals_by_label.get("Phone country")
    voip = signals_by_label.get("VOIP detection")
    business_registry = signals_by_label.get("Business registry")
    domain_age = signals_by_label.get("Domain age")
    fraud_language = signals_by_label.get("Fraud language")
    personal_info = signals_by_label.get("Personal info requests")

    if salary_sanity and salary_sanity.verdict == Verdict.FAIL:
        fraud_indicators.append("unrealistic salary")
    if currency_conversion and currency_conversion.verdict == Verdict.FAIL:
        fraud_indicators.append("salary matches foreign currency conversion")
    if phone_country and phone_country.verdict == Verdict.FAIL:
        fraud_indicators.append("phone number country mismatch")
    if voip and voip.verdict == Verdict.FAIL:
        fraud_indicators.append("VOIP or virtual phone number")
    if business_registry and business_registry.verdict == Verdict.FAIL:
        fraud_indicators.append("not found in business registry")
    if domain_age and domain_age.verdict == Verdict.FAIL:
        fraud_indicators.append("newly registered domain")
    if fraud_language and fraud_language.verdict == Verdict.FAIL:
        fraud_indicators.append("high-confidence fraud language")
    if personal_info and personal_info.verdict == Verdict.FAIL:
        fraud_indicators.append("requests for sensitive personal information")

    if len(fraud_indicators) >= 3:
        report.signals.append(Signal(
            label="Fraud pattern detected",
            verdict=Verdict.FAIL,
            score=0.0,
            weight=1.0,
            reason=f"Multiple fraud indicators found: {', '.join(fraud_indicators)}. Do not apply to this role.",
            source="Fraud detection"
        ))
    elif len(fraud_indicators) == 2:
        report.signals.append(Signal(
            label="Fraud indicators",
            verdict=Verdict.WARN,
            score=0.1,
            weight=0.6,
            reason=f"Two warning signs found: {', '.join(fraud_indicators)}. Research this company independently before applying.",
            source="Fraud detection"
        ))

    return report


async def verify_posting(
    posting_text: str,
    company_name: Optional[str] = None,
    company_domain: Optional[str] = None,
    company_phone: Optional[str] = None,
    claimed_country: str = "us",
) -> VerificationReport:
    report = VerificationReport()
    report.signals.extend(run_nlp_checks(posting_text))

    if company_domain:
        from app.verification.domain import check_domain_age
        report.signals.append(await check_domain_age(company_domain))

    if company_name:
        from app.verification.company import check_business_registry
        report.signals.append(await check_business_registry(company_name, claimed_country))

    if company_phone:
        from app.verification.phone import check_phone_country
        report.signals.append(check_phone_country(company_phone, claimed_country))

        from app.verification.voip import check_voip
        report.signals.append(await check_voip(company_phone))

    report = detect_fraud_patterns(report)
    report.compute()
    return report
