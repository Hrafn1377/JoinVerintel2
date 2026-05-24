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
        "note": "Ghanaian cedi annual salaries commonly range ₵50k-500k, approximately $4k-12k UDS"
    },
]


# ============================================
# NLP CHECKS
# ============================================

def check_fraud_language(text: str) -> Signal:
    """
    Checks for fraud phrases using a tiered system.
    Tier 1 = immediate fail. Tier 2 = fail on two hits, warn on one.
    """
    text_lower = text.lower()

    tier1_found = [p for p in TIER_1_FRAUD if p in text_lower]
    tier2_found = [p for p in TIER_2_FRAUD if p in text_lower]

    if tier1_found:
        return Signal(
            label="Fraud language",
            verdict=Verdict.FAIL,
            score=0.0,
            weight=0.8,
            reason=f"High-confidence fraud language detected: '{tier1_found[0]}'. This phrase is almost exclusively used in scams and MLM schemes.",
            source="NLP"
        )

    if len(tier2_found) >= 2:
        return Signal(
            label="Fraud language",
            verdict=Verdict.FAIL,
            score=0.0,
            weight=0.8,
            reason=f"Multiple suspicious phrases detected: {', '.join(tier2_found[:2])}. This combination is a strong indicator of a fraudulent posting.",
            source="NLP"
        )

    if tier2_found:
        return Signal(
            label="Fraud language",
            verdict=Verdict.WARN,
            score=0.3,
            weight=0.8,
            reason=f"Suspicious phrase detected: '{tier2_found[0]}'. This language is sometimes used in misleading job postings.",
            source="NLP"
        )

    return Signal(
        label="Fraud language",
        verdict=Verdict.PASS,
        score=1.0,
        weight=0.8,
        reason="No fraud language detected.",
        source="NLP"
    )


def check_urgency(text: str) -> Signal:
    """
    Checks for urgency pressure tactics.
    Legitimate employers don't need to pressure candidates.
    """
    text_lower = text.lower()
    found = [phrase for phrase in URGENCY_PHRASES if phrase in text_lower]

    if not found:
        return Signal(
            label="Urgency pressure",
            verdict=Verdict.PASS,
            score=1.0,
            weight=0.3,
            reason="No urgency pressure tactics detected.",
            source="NLP"
        )

    return Signal(
        label="Urgency pressure",
        verdict=Verdict.WARN,
        score=0.4,
        weight=0.3,
        reason=f"Urgency language detected: '{found[0]}'. Legitimate employers rarely pressure candidates to apply immediately.",
        source="NLP"
    )


def check_personal_info_requests(text: str) -> Signal:
    """
    Checks if the posting asks for sensitive personal information.
    No legitimate employer asks for SSN, bank details, or passport
    numbers in a job posting.
    """
    text_lower = text.lower()
    found = [p for p in PERSONAL_INFO_REQUESTS if p in text_lower]

    if not found:
        return Signal(
            label="Personal info requests",
            verdict=Verdict.PASS,
            score=1.0,
            weight=0.9,
            reason="No requests for sensitive personal information detected.",
            source="NLP"
        )

    return Signal(
        label="Personal info requests",
        verdict=Verdict.FAIL,
        score=0.0,
        weight=0.9,
        reason=f"This posting requests sensitive personal information: '{found[0]}'. No legitimate employer asks for this in a job posting.",
        source="NLP"
    )


# ============================================
# SALARY CHECKS
# ============================================

def extract_salary_figures(text: str) -> List[float]:
    """
    Extracts salary figures from text.
    Handles formats like: $50,000 $50k $50,000/year $25/hour
    Returns a list of annualized figures.
    """
    figures = []

    # Match full dollar amounts including comma-separated thousands
    dollar_pattern = r'\$\s*(\d{1,3}(?:,\d{3})+|\d{5,})([kK])?'
    matches = re.finditer(dollar_pattern, text)

    for match in matches:
        number_str = match.group(1).replace(",", "")
        multiplier = match.group(2)
        try:
            amount = float(number_str)
            if multiplier and multiplier.lower() == "k":
                amount *= 1000

            # If it looks like an hourly rate (under $500), annualize it
            if amount < 500:
                amount *= 2080

            # If it looks like a monthly rate (between $1000 and $15000)
            elif 1000 <= amount <= 15000:
                amount *= 12

            figures.append(amount)
        except ValueError:
            continue

    return figures


def check_salary_sanity(text: str) -> Signal:
    """
    Checks if salary figures make sense for the type of role.
    """
    figures = extract_salary_figures(text)
    text_lower = text.lower()

    if not figures:
        return Signal(
            label="Salary sanity",
            verdict=Verdict.WARN,
            score=0.5,
            weight=0.4,
            reason="No salary figures found. Legitimate employers are transparent about compensation.",
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
                        reason=f"Salary of ${figure:,.0f} is unrealistically high for a {role} role. This is a common scam tactic to attract applicants.",
                        source="NLP"
                    )
                if figure < min_sal * 0.5:
                    return Signal(
                        label="Salary sanity",
                        verdict=Verdict.WARN,
                        score=0.3,
                        weight=0.4,
                        reason=f"Salary of ${figure:,.0f} appears unusually low for a {role} role.",
                        source="NLP"
                    )

    return Signal(
        label="Salary sanity",
        verdict=Verdict.PASS,
        score=1.0,
        weight=0.4,
        reason="Salary figures appear reasonable.",
        source="NLP"
    )


def check_currency_conversion(text: str) -> Signal:
    """
    Detects salary figures that look like foreign currency amounts
    presented as USD.
    """
    figures = extract_salary_figures(text)
    print(f"DEBUG salary figures: {figures}")

    if not figures:
        return Signal(
            label="Currency conversion",
            verdict=Verdict.PASS,
            score=1.0,
            weight=0.6,
            reason="No salary figures to check for currency conversion.",
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
                    reason=f"Salary of ${figure:,.0f} falls within the range of typical {currency['country']} salaries in {currency['currency']}. This is a common scam pattern where foreign salaries are presented with a dollar sign to appear as US compensation.",
                    source="NLP"
                )

    return Signal(
        label="Currency conversion",
        verdict=Verdict.PASS,
        score=1.0,
        weight=0.6,
        reason="Salary figures do not match known foreign currency conversion patterns.",
        source="NLP"
    )


def run_nlp_checks(text: str) -> List[Signal]:
    """
    Runs all NLP checks on the posting text.
    Returns a list of signals.
    """
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
    """
    Looks at all signals together and fires a fraud pattern signal
    when multiple red flags are present in combination.
    
    This is the final verdict layer — individual checks catch specific
    issues, this catches the overall pattern.
    """
    signals_by_label = {s.label: s for s in report.signals}

    fraud_indicators = []

    # Check each signal for failures
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

    # Fire fraud pattern signal based on number of indicators
    if len(fraud_indicators) >= 3:
        report.signals.append(Signal(
            label="Fraud pattern detected",
            verdict=Verdict.FAIL,
            score=0.0,
            weight=1.0,
            reason=f"This posting shows multiple characteristics consistent with fraud: {', '.join(fraud_indicators)}. We strongly recommend not applying to this role.",
            source="Fraud detection"
        ))
    elif len(fraud_indicators) == 2:
        report.signals.append(Signal(
            label="Fraud indicators",
            verdict=Verdict.WARN,
            score=0.1,
            weight=0.6,
            reason=f"This posting shows warning signs associated with fraudulent listings: {', '.join(fraud_indicators)}. Proceed with caution and research this company independently.",
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