import phonenumbers
from phonenumbers import geocoder, carrier
from app.scoring.models import Signal, Verdict


# Map country codes to expected phone regions
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
    A US company with an Indian phone number is a strong fraud signal.
    
    Uses the phonenumbers library which contains Google's libphonenumber data -
    the same data used by Android to identify phone numbers worldwide.
    """
    try:
        # Clean the phone number
        phone_clean = phone.strip().replace(" ", "").replace("-", "")

        # Try parsing without region hint first
        try:
            parsed = phonenumbers.parse(phone_clean, None)
        except Exception:
            # If that fails, try with the claimed country as hint
            region_hint = claimed_country.upper()
            parsed = phonenumbers.parse(phone_clean, region_hint)

        if not phonenumbers.is_valid_number(parsed):
            return Signal(
                label="Phone country",
                verdict=Verdict.WARN,
                score=0.4,
                weight=0.5,
                reason="Phone number could not be validated.",
                source="Phone check"
            )
        
        # Get the region this number belongs to
        phone_region = geocoder.region_code_for_number(parsed)

        if not phone_region:
            return Signal(
                label="Phone country",
                verdict=Verdict.WARN,
                score=0.4,
                weight=0.5,
                reason="Could not determine country from phone number.",
                source="Phone check"
            )
        
        expected_regions = COUNTRY_PHONE_MAP.get(claimed_country.lower(), [claimed_country.upper()])

        if phone_region in expected_regions:
            return Signal(
                label="Phone country",
                verdict=Verdict.PASS,
                score=1.0,
                weight=0.5,
                reason=f"Phone number country matches claimed location ({claimed_country.upper()}).",
                source="Phone check"
            )
        
        # Phone country doesn't match claimed country
        country_name = geocoder.description_for_number(parsed, "en")
        return Signal(
            label="Phone country",
            verdict=Verdict.FAIL,
            score=0.0,
            weight=0.5,
            reason=f"Phone number is registered in {country_name} ({phone_region}) but company claims to be based in {claimed_country.upper()}. This mismatch is a common indicator of fraud.",
            source="Phone check"
        )
    
    except Exception as e:
        return Signal(
            label="Phone country",
            verdict=Verdict.WARN,
            score=0.4,
            weight=0.5,
            reason="Could not parse phone number to verify country.",
            source="Phone check"
        )