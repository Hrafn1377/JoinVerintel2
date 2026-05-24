import httpx
from app.scoring.models import Signal, Verdict


async def check_business_registry(company_name: str, claimed_country: str = "us") -> Signal:
    """
    Checks if a company exists in the OpenCorporates business registry.
    OpenCorporates is the largest open database of companies in the world.
    
    A company not found in the registry of their claimed country is a red flag.
    Legitimate companies are registered businesses. Scammers often claim to be
    US-based but have no US business registration.
    """

    # Map country codes to OpenCorporates jurisdiction codes
    JURISDICTION_MAP = {
        "us": ["us_de", "us_ca", "us_ny", "us_tx", "us_fl", "us_wa"],
        "gb": ["gb"],
        "ca": ["ca"],
        "au": ["au"],
        "de": ["de"],
        "fr": ["fr"],
        "ie": ["ie"],
        "in": ["in"],
        "no": ["no"],
        "ph": ["ph"],
    }

    jurisdictions = JURISDICTION_MAP.get(claimed_country.lower(), [claimed_country.lower()])

    try:
        async with httpx.AsyncClient(timeout=10.0) as client:
            response = await client.get(
                "https://api.opencorporates.com/v0.4/companies/search",
                params={
                    "q": company_name,
                    "jurisdiction_code": jurisdictions[0],
                    "inactive": "false",
                }
            )

            if response.status_code != 200:
                return Signal(
                    label="Business registry",
                    verdict=Verdict.WARN,
                    score=0.5,
                    weight=0.5,
                    reason=f"Could not access business registry to verify {company_name}. Manual verification recommended.",
                    source="OpenCorporates"
                )

            data = response.json()
            companies = data.get("results", {}).get("companies", [])

            if not companies:
                return Signal(
                    label="Business registry",
                    verdict=Verdict.FAIL,
                    score=0.0,
                    weight=0.7,
                    reason=f"No active company named '{company_name}' found in the {claimed_country.upper()} business registry. This may indicate a subsidiary, DBA, or unregistered business. Legitimate companies are registered businesses. This could indicate a fraudulent posting or a company operating under a different registered name.",
                    source="OpenCorporates"
                )

            # Check if any result is a close match
            company_name_lower = company_name.lower()
            for item in companies[:5]:
                registered_name = item.get("company", {}).get("name", "").lower()
                if company_name_lower in registered_name or registered_name in company_name_lower:
                    return Signal(
                        label="Business registry",
                        verdict=Verdict.PASS,
                        score=1.0,
                        weight=0.7,
                        reason=f"'{company_name}' found in the {claimed_country.upper()} business registry as an active company.",
                        source="OpenCorporates"
                    )

            return Signal(
                label="Business registry",
                verdict=Verdict.WARN,
                score=0.3,
                weight=0.7,
                reason=f"Could not find an exact match for '{company_name}' in the {claimed_country.upper()} business registry. Large companies may be registered under a parent company name.",
                source="OpenCorporates"
            )

    except Exception as e:
        return Signal(
            label="Business registry",
            verdict=Verdict.WARN,
            score=0.4,
            weight=0.7,
            reason=f"Could not complete business registry check for '{company_name}'. Manual verification recommended.",
            source="OpenCorporates"
        )