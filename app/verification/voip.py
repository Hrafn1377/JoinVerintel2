import httpx
import os
from app.scoring.models import Signal, Verdict


async def check_voip(phone: str) -> Signal:
    """
    Checks if a phone number is a VOIP or virtual number.
    """
    api_key = os.getenv("APILAYER_KEY")

    if not api_key:
        return Signal(
            label="VOIP detection",
            verdict=Verdict.WARN,
            score=0.5,
            weight=0.4,
            reason="VOIP detection unavailable — API key not configured.",
            source="APILayer"
        )

    phone_clean = phone.strip().replace(" ", "").replace("-", "")

    try:
        async with httpx.AsyncClient(timeout=5.0) as client:
            response = await client.get(
                "https://api.apilayer.com/number_verification/validate",
                params={"number": phone_clean},
                headers={"apikey": api_key},
            )

            if response.status_code != 200:
                return Signal(
                    label="VOIP detection",
                    verdict=Verdict.WARN,
                    score=0.5,
                    weight=0.4,
                    reason="VOIP check couldn't be completed. Manual review recommended.",
                    source="APILayer"
                )

            data = response.json()
            valid = data.get("valid", False)
            line_type = data.get("line_type", "").lower()
            carrier_name = data.get("carrier", "Unknown")

            if not valid:
                return Signal(
                    label="VOIP detection",
                    verdict=Verdict.WARN,
                    score=0.4,
                    weight=0.4,
                    reason="Phone number couldn't be validated.",
                    source="APILayer"
                )

            if line_type in ("voip", "virtual"):
                return Signal(
                    label="VOIP detection",
                    verdict=Verdict.FAIL,
                    score=0.0,
                    weight=0.4,
                    reason=f"This is a VOIP or virtual number (carrier: {carrier_name}). Scammers use virtual numbers to appear local while operating overseas.",
                    source="APILayer"
                )

            return Signal(
                label="VOIP detection",
                verdict=Verdict.PASS,
                score=1.0,
                weight=0.4,
                reason=f"Legitimate {line_type} number (carrier: {carrier_name}).",
                source="APILayer"
            )

    except Exception:
        return Signal(
            label="VOIP detection",
            verdict=Verdict.WARN,
            score=0.5,
            weight=0.4,
            reason="VOIP check couldn't be completed. Manual review recommended.",
            source="APILayer"
        )
