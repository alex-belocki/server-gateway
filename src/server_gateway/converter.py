from __future__ import annotations

import json
from decimal import Decimal, ROUND_DOWN, ROUND_HALF_UP, getcontext
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen


getcontext().prec = 28

TBANK_RATE_URL = "https://www.tbank.ru/api/common/v1/currency_rates?from=BYN&to=RUB"
TBANK_CARD_CATEGORY = "DebitCardsOperations"
HTTP_TIMEOUT_SECONDS = 20
USER_AGENT = "Mozilla/5.0 (compatible; byn-rub-converter/2.0)"
TWOPLACES = Decimal("0.01")


class RateError(Exception):
    pass


def decimal_from_string(value: str) -> Decimal:
    return Decimal(value.strip().replace(",", "."))


def round_byn(value: Decimal) -> Decimal:
    return value.quantize(TWOPLACES, rounding=ROUND_HALF_UP)


def round_card_rub(value: Decimal) -> Decimal:
    return value.quantize(TWOPLACES, rounding=ROUND_DOWN)


def currency_code(currency: object) -> str | None:
    if not isinstance(currency, dict):
        return None

    for key in ("name", "strCode", "code"):
        value = currency.get(key)
        if value is None:
            continue
        normalized = str(value).upper()
        if normalized == "933":
            return "BYN"
        if normalized == "643":
            return "RUB"
        return normalized

    return None


def card_rate_from_tbank_response(body: str, category: str = TBANK_CARD_CATEGORY) -> Decimal:
    try:
        data = json.loads(body)
    except json.JSONDecodeError as exc:
        raise RateError(f"Failed to parse T-Bank response: {exc}") from exc

    if data.get("resultCode") != "OK":
        raise RateError(f"T-Bank response resultCode is {data.get('resultCode')!r}, expected 'OK'")

    rates = data.get("payload", {}).get("rates", [])
    if not isinstance(rates, list):
        raise RateError("T-Bank response does not contain payload.rates")

    for item in rates:
        if not isinstance(item, dict) or item.get("category") != category:
            continue

        buy = item.get("buy")
        sell = item.get("sell")
        if buy is None or sell is None:
            raise RateError(f"T-Bank category {category} does not contain buy/sell")

        from_currency = currency_code(item.get("fromCurrency"))
        to_currency = currency_code(item.get("toCurrency"))

        if from_currency == "BYN" and to_currency == "RUB":
            return decimal_from_string(str(sell))

        if from_currency == "RUB" and to_currency == "BYN":
            return Decimal("1") / decimal_from_string(str(buy))

        raise RateError(f"T-Bank category {category} is not a BYN/RUB rate")

    raise RateError(f"T-Bank response does not contain category {category}")


def fetch_card_rate(opener=urlopen) -> Decimal:
    request = Request(TBANK_RATE_URL, headers={"User-Agent": USER_AGENT, "Accept": "application/json"})
    try:
        with opener(request, timeout=HTTP_TIMEOUT_SECONDS) as response:
            body = response.read().decode("utf-8", errors="replace")
    except (HTTPError, URLError, TimeoutError, OSError) as exc:
        raise RateError(f"Failed to fetch T-Bank rate: {exc}") from exc

    return card_rate_from_tbank_response(body)


def byn_to_rub(amount_byn: Decimal, rate: Decimal) -> Decimal:
    return round_card_rub(amount_byn * rate)


def rub_to_byn(amount_rub: Decimal, rate: Decimal) -> Decimal:
    return round_byn(amount_rub / rate)


def format_decimal(value: Decimal) -> str:
    return format(value, "f")
