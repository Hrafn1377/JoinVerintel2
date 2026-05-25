import whois
from datetime import datetime, timezone
from app.scoring.models import Signal, Verdict


async def check_domain_age(domain: str) -> Signal:
    """
    Checks how old a domain is.
    Scammers frequently use newly registered domains.
    A domain less than 6 months old is a red flag.
    A domain less than 1 year old is worth noting.
    Legitimate companies typically have domains several years old.
    """
    # Strip protocol and trailing slashes
    domain = domain.replace("https://", "").replace("http://", "").strip("/").strip()

    try:
        w = whois.whois(domain)
        creation_date = w.creation_date

        # Sometimes creation_date is a list, take the first one
        if isinstance(creation_date, list):
            creation_date = creation_date[0]

        if not creation_date:
            return Signal(
                label="Domain age",
                verdict=Verdict.WARN,
                score=0.3,
                weight=0.4,
                reason=f"Could not determine domain registration date for {domain}. This may indicate WHOIS privacy protection.",
                source="WHOIS"
            )

        # Make sure creation_date is timezone aware
        if creation_date.tzinfo is None:
            creation_date = creation_date.replace(tzinfo=timezone.utc)

        now = datetime.now(timezone.utc)
        age_days = (now - creation_date).days
        age_years = age_days / 365

        if age_days < 180:
            return Signal(
                label="Domain age",
                verdict=Verdict.FAIL,
                score=0.0,
                weight=0.4,
                reason=f"{domain} was registered {age_days} days ago. Newly registered domains are a red flag.",
                source="WHOIS"
            )

        if age_days < 365:
            return Signal(
                label="Domain age",
                verdict=Verdict.WARN,
                score=0.3,
                weight=0.4,
                reason=f"{domain} is less than a year old ({age_days} days). Proceed with caution.",
                source="WHOIS"
            )

        return Signal(
            label="Domain age",
            verdict=Verdict.PASS,
            score=1.0,
            weight=0.4,
            reason=f"Domain {domain} has been registered for {age_years:.1f} years. Established domain.",
            source="WHOIS"
        )

    except Exception as e:
        return Signal(
            label="Domain age",
            verdict=Verdict.WARN,
            score=0.4,
            weight=0.4,
            reason=f"Domain check couldn't be completed for {domain}. Manual verification recommended.",
            source="WHOIS"
        )