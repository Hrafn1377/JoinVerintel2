import httpx
from app.scoring.models import Signal, Verdict


async def check_business_registry(company_name: str, claimed_country: str = "us") -> Signal:
    """
    Checks if a company exists in the OpenCorporates business registry.
    """

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
                    reason=f"Couldn't reach the business registry to verify {company_name}. Manual verification recommended.",
                    source="OpenCorporates"
                )

            data = response.json()
            companies = data.get("results", {}).get("companies", [])

            if not companies:
                return Signal(
                    label="Business registry",
                    verdict=Verdict.WARN,
                    score=0.3,
                    weight=0.5,
                    reason=f"'{company_name}' wasn't found in the {claimed_country.upper()} business registry. Could be a subsidiary, DBA, or unregistered business.",
                    source="OpenCorporates"
                )

            company_name_lower = company_name.lower()
            for item in companies[:5]:
                registered_name = item.get("company", {}).get("name", "").lower()
                if company_name_lower in registered_name or registered_name in company_name_lower:
                    return Signal(
                        label="Business registry",
                        verdict=Verdict.PASS,
                        score=1.0,
                        weight=0.7,
                        reason=f"'{company_name}' is registered as an active company in {claimed_country.upper()}.",
                        source="OpenCorporates"
                    )

            return Signal(
                label="Business registry",
                verdict=Verdict.WARN,
                score=0.3,
                weight=0.5,
                reason=f"No exact match for '{company_name}' in the {claimed_country.upper()} registry. Large companies may be registered under a parent name.",
                source="OpenCorporates"
            )

    except Exception:
        return Signal(
            label="Business registry",
            verdict=Verdict.WARN,
            score=0.5,
            weight=0.5,
            reason=f"Business registry check couldn't be completed for '{company_name}'. Manual verification recommended.",
            source="OpenCorporates"
        )
