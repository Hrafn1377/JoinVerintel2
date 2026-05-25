import phonenumbers
from phonenumbers import geocoder, carrier
from app.scoring.models import Signal, Verdict


COUNTRY_PHONE_MAP = {
    "us": ["US"],
    "gb": ["GB"],
    "ca": ["CA"],
    "au": ["AU"],
    "de": ["DE"],
    "fr": ["FR"],
    "ie": ["IE"],
    "in": ["IN"],
    "no": ["NO"],
    "ph": ["PH"],
}


def check_phone_country(phone: str, claimed_country: str) -> Signal:
    """
    Checks if a phone number's country matches the company's claimed location.
    """
    try:
        phone_clean = phone.strip().replace(" ", "").replace("-", "")

        try:
            parsed = phonenumbers.parse(phone_clean, None)
        except Exception:
            region_hint = claimed_country.upper()
            parsed = phonenumbers.parse(phone_clean, region_hint)

        if not phonenumbers.is_valid_number(parsed):
            return Signal(
                label="Phone country",
                verdict=Verdict.WARN,
                score=0.4,
                weight=0.5,
                reason="Phone number couldn't be validated.",
                source="Phone check"
            )

        phone_region = geocoder.region_code_for_number(parsed)

        if not phone_region:
            return Signal(
                label="Phone country",
                verdict=Verdict.WARN,
                score=0.4,
                weight=0.5,
                reason="Couldn't determine the country from this phone number.",
                source="Phone check"
            )

        expected_regions = COUNTRY_PHONE_MAP.get(claimed_country.lower(), [claimed_country.upper()])

        if phone_region in expected_regions:
            return Signal(
                label="Phone country",
                verdict=Verdict.PASS,
                score=1.0,
                weight=0.5,
                reason=f"Phone number matches the claimed location ({claimed_country.upper()}).",
                source="Phone check"
            )

        country_name = geocoder.description_for_number(parsed, "en")
        return Signal(
            label="Phone country",
            verdict=Verdict.FAIL,
            score=0.0,
            weight=0.5,
            reason=f"Phone number traces to {country_name} ({phone_region}). Company claims to be based in {claimed_country.upper()}. That's a red flag.",
            source="Phone check"
        )

    except Exception:
        return Signal(
            label="Phone country",
            verdict=Verdict.WARN,
            score=0.4,
            weight=0.5,
            reason="Couldn't parse this phone number to verify its country.",
            source="Phone check"
        )
