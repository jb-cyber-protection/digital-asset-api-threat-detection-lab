"""Synthetic digital-asset trading and API activity generator."""

from __future__ import annotations

import json
import random
from collections import Counter, defaultdict
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from digital_asset_lab.common.constants import DEFAULT_START_TIME

EVENT_CATEGORIES = {
    "auth.login.success": "identity",
    "auth.login.failure": "identity",
    "api_key.used": "api",
    "order.create": "trading",
    "order.cancel": "trading",
    "withdrawal.request": "custody",
    "ws.heartbeat": "connectivity",
}

PROFILE_CODES = {
    "market_maker": "mm",
    "momentum": "mo",
    "arb_like": "ar",
}

COUNTRY_TO_REGION = {
    "GB": "eu-west-2",
    "NL": "eu-west-1",
    "FR": "eu-west-3",
    "DE": "eu-central-1",
    "US": "us-east-1",
    "SG": "ap-southeast-1",
    "IE": "eu-west-1",
}

COUNTRY_IP_PREFIX = {
    "GB": "51.140",
    "NL": "20.67",
    "FR": "15.236",
    "DE": "18.194",
    "US": "34.85",
    "SG": "18.141",
    "IE": "34.241",
}

API_ENDPOINTS = [
    "/v1/order/create",
    "/v1/order/cancel",
    "/v1/orders/open",
    "/v1/positions",
    "/v1/balance",
    "/v1/market/ticker",
]

READ_ONLY_ENDPOINTS = {"/v1/orders/open", "/v1/positions", "/v1/balance", "/v1/market/ticker"}
WITHDRAWAL_NETWORKS = {
    "BTC": "bitcoin",
    "ETH": "ethereum",
    "SOL": "solana",
    "USDT": "ethereum",
}


def parse_start_time(start_time: str) -> datetime:
    """Parse ISO8601 timestamps and normalize to UTC."""

    iso_value = start_time.replace("Z", "+00:00")
    parsed = datetime.fromisoformat(iso_value)
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def load_simulation_config(config_path: str | Path) -> dict[str, Any]:
    """Load the simulator config JSON."""

    path = Path(config_path)
    with path.open("r", encoding="utf-8") as handle:
        return json.load(handle)


def _weighted_choice(rng: random.Random, weights: dict[str, float]) -> str:
    total = sum(weight for weight in weights.values() if weight > 0)
    if total <= 0:
        raise ValueError("Weight map must contain at least one positive value")

    threshold = rng.random() * total
    running = 0.0
    for key, weight in weights.items():
        if weight <= 0:
            continue
        running += weight
        if running >= threshold:
            return key
    return next(reversed(weights))


def _build_account_pool(config: dict[str, Any]) -> dict[str, list[dict[str, str]]]:
    pool: dict[str, list[dict[str, str]]] = {}
    for profile_name, profile_config in config["profiles"].items():
        code = PROFILE_CODES[profile_name]
        accounts = []
        for idx in range(1, int(profile_config["accounts"]) + 1):
            accounts.append(
                {
                    "account_id": f"acct-{code}-{idx:03d}",
                    "bot_id": f"bot-{code}-{idx:03d}",
                    "api_key_id": f"key-{code}-{idx:03d}",
                }
            )
        pool[profile_name] = accounts
    return pool


def _pick_country(profile_config: dict[str, Any], rng: random.Random) -> str:
    return rng.choice(profile_config["countries"])


def _build_ip(country: str, rng: random.Random) -> str:
    prefix = COUNTRY_IP_PREFIX.get(country, "34.85")
    return f"{prefix}.{rng.randint(0, 255)}.{rng.randint(1, 254)}"


def _pick_symbol(config: dict[str, Any], rng: random.Random) -> str:
    return rng.choice(list(config["symbols"].keys()))


def _next_price(
    symbol: str,
    market_state: dict[str, float],
    trend_state: dict[str, str],
    config: dict[str, Any],
    rng: random.Random,
) -> float:
    symbol_cfg = config["symbols"][symbol]
    volatility = float(symbol_cfg["volatility_bps"]) / 10_000
    trend_drift = float(symbol_cfg["trend_bps"]) / 10_000

    side_drift = trend_drift if trend_state[symbol] == "buy" else -trend_drift
    noise = rng.gauss(side_drift, volatility)
    updated = max(0.01, market_state[symbol] * (1 + noise))
    market_state[symbol] = updated

    # Slowly changing trend to mimic market sessions.
    if rng.random() < 0.03:
        trend_state[symbol] = "sell" if trend_state[symbol] == "buy" else "buy"

    return round(updated, 2)


def _select_order_side(profile_name: str, symbol: str, trend_state: dict[str, str], rng: random.Random) -> str:
    if profile_name == "market_maker":
        return "buy" if rng.random() < 0.5 else "sell"

    if profile_name == "momentum":
        trend = trend_state[symbol]
        if rng.random() < 0.74:
            return trend
        return "sell" if trend == "buy" else "buy"

    spread_signal = rng.uniform(-1.0, 1.0)
    return "buy" if spread_signal > 0 else "sell"


def _build_base_event(
    *,
    event_id: int,
    timestamp: datetime,
    profile_name: str,
    account: dict[str, str],
    exchange: str,
    symbol: str,
    country: str,
    ip_address: str,
    user_agent: str,
    event_type: str,
    request_suffix: int,
) -> dict[str, Any]:
    return {
        "event_id": f"evt-{event_id:08d}",
        "timestamp": timestamp.isoformat(),
        "event_type": event_type,
        "event_category": EVENT_CATEGORIES[event_type],
        "profile": profile_name,
        "account_id": account["account_id"],
        "bot_id": account["bot_id"],
        "api_key_id": account["api_key_id"],
        "exchange": exchange,
        "symbol": symbol,
        "ip": ip_address,
        "ip_country": country,
        "region": COUNTRY_TO_REGION.get(country, "eu-west-1"),
        "user_agent": user_agent,
        "request_id": f"req-{event_id:08d}-{request_suffix}",
    }


def _create_order_event(
    *,
    event: dict[str, Any],
    profile_name: str,
    profile_config: dict[str, Any],
    symbol: str,
    current_price: float,
    trend_state: dict[str, str],
    open_orders: dict[str, list[dict[str, Any]]],
    order_sequence: int,
    rng: random.Random,
) -> int:
    side = _select_order_side(profile_name, symbol, trend_state, rng)
    min_qty, max_qty = profile_config["order_size"]
    min_offset_bps, max_offset_bps = profile_config["quote_offset_bps"]
    price_offset = rng.uniform(min_offset_bps, max_offset_bps) / 10_000
    limit_price = round(max(0.01, current_price * (1 + price_offset)), 2)
    quantity = round(rng.uniform(min_qty, max_qty), 6)

    if profile_name == "momentum":
        order_type = "market" if rng.random() < 0.18 else "limit"
    elif profile_name == "arb_like":
        order_type = "ioc" if rng.random() < 0.24 else "limit"
    else:
        order_type = "limit"

    order_id = f"ord-{order_sequence:09d}"
    status = "filled" if order_type == "market" else "open"

    event["endpoint"] = "/v1/order/create"
    event["http_method"] = "POST"
    event["details"] = {
        "order_id": order_id,
        "side": side,
        "order_type": order_type,
        "time_in_force": rng.choice(profile_config["time_in_force"]),
        "quantity": quantity,
        "limit_price": limit_price,
        "notional_usd": round(quantity * limit_price, 2),
        "status": status,
    }

    if status == "open":
        open_orders[event["account_id"]].append(
            {
                "order_id": order_id,
                "symbol": symbol,
                "side": side,
                "created_event": event["event_id"],
            }
        )

    return order_sequence + 1


def _create_cancel_event(
    *,
    event: dict[str, Any],
    account_id: str,
    open_orders: dict[str, list[dict[str, Any]]],
    rng: random.Random,
) -> bool:
    if not open_orders[account_id]:
        return False

    canceled = open_orders[account_id].pop(rng.randrange(len(open_orders[account_id])))
    event["endpoint"] = "/v1/order/cancel"
    event["http_method"] = "POST"
    event["details"] = {
        "order_id": canceled["order_id"],
        "cancel_reason": rng.choice(["reprice", "risk_limit", "strategy_update"]),
        "linked_create_event": canceled["created_event"],
        "status": "canceled",
    }
    return True


def _create_auth_event(event: dict[str, Any], event_type: str, rng: random.Random) -> None:
    success = event_type == "auth.login.success"
    event["endpoint"] = "/v1/auth/login"
    event["http_method"] = "POST"
    details: dict[str, Any] = {
        "auth_method": "api_key",
        "mfa_present": True,
        "success": success,
    }
    if not success:
        details["failure_reason"] = rng.choice(["bad_signature", "expired_nonce", "invalid_token"])
    event["details"] = details


def _create_api_key_event(event: dict[str, Any], rng: random.Random) -> None:
    endpoint = rng.choice(API_ENDPOINTS)
    event["endpoint"] = endpoint
    event["http_method"] = "GET" if endpoint in READ_ONLY_ENDPOINTS else "POST"
    event["details"] = {
        "scope": "read" if endpoint in READ_ONLY_ENDPOINTS else "trade",
        "latency_ms": rng.randint(8, 190),
        "status_code": 200,
    }


def _create_withdrawal_event(event: dict[str, Any], symbol: str, rng: random.Random) -> None:
    asset = symbol.split("-")[0]
    if asset not in WITHDRAWAL_NETWORKS:
        asset = "USDT"

    amount_ranges = {
        "BTC": (0.002, 0.18),
        "ETH": (0.03, 1.1),
        "SOL": (1.0, 32.0),
        "USDT": (150.0, 7500.0),
    }
    low, high = amount_ranges[asset]

    event["endpoint"] = "/v1/withdrawals"
    event["http_method"] = "POST"
    event["details"] = {
        "asset": asset,
        "amount": round(rng.uniform(low, high), 6),
        "network": WITHDRAWAL_NETWORKS[asset],
        "destination_type": rng.choice(["internal_vault", "whitelisted_hot_wallet"]),
        "whitelisted_address": True,
        "risk_score": round(rng.uniform(0.01, 0.18), 3),
    }


def _create_heartbeat_event(event: dict[str, Any], rng: random.Random) -> None:
    event["endpoint"] = "/ws/market"
    event["http_method"] = "WS"
    event["details"] = {
        "channel": rng.choice(["book", "trades", "private-orders"]),
        "latency_ms": rng.randint(5, 120),
        "status": "alive",
    }


def _profile_has_open_orders(
    profile_accounts: list[dict[str, str]], open_orders: dict[str, list[dict[str, Any]]]
) -> bool:
    for account in profile_accounts:
        if open_orders[account["account_id"]]:
            return True
    return False


def _pick_account_for_cancel(
    profile_accounts: list[dict[str, str]],
    open_orders: dict[str, list[dict[str, Any]]],
    rng: random.Random,
) -> dict[str, str] | None:
    candidates = [account for account in profile_accounts if open_orders[account["account_id"]]]
    if not candidates:
        return None
    return rng.choice(candidates)


def iter_events(
    *,
    total_events: int,
    seed: int,
    start_time: datetime,
    config: dict[str, Any],
) -> list[dict[str, Any]]:
    """Generate synthetic events for trading/API activity."""

    rng = random.Random(seed)
    account_pool = _build_account_pool(config)
    market_state = {
        symbol: float(symbol_cfg["base_price"])
        for symbol, symbol_cfg in config["symbols"].items()
    }
    trend_state = {symbol: rng.choice(["buy", "sell"]) for symbol in config["symbols"]}
    open_orders: dict[str, list[dict[str, Any]]] = defaultdict(list)

    current_ts = start_time
    order_sequence = 1
    events: list[dict[str, Any]] = []

    for event_idx in range(1, total_events + 1):
        profile_name = _weighted_choice(rng, config["profile_weights"])
        profile_config = config["profiles"][profile_name]
        event_type = _weighted_choice(rng, config["event_type_weights"][profile_name])

        profile_accounts = account_pool[profile_name]
        account = rng.choice(profile_accounts)
        if event_type == "order.cancel":
            cancel_account = _pick_account_for_cancel(profile_accounts, open_orders, rng)
            if cancel_account is None:
                event_type = "order.create"
            else:
                account = cancel_account

        cadence_min, cadence_max = profile_config["cadence_ms"]
        current_ts = current_ts + timedelta(milliseconds=rng.randint(cadence_min, cadence_max))

        country = _pick_country(profile_config, rng)
        ip_address = _build_ip(country, rng)
        symbol = _pick_symbol(config, rng)
        current_price = _next_price(symbol, market_state, trend_state, config, rng)
        exchange = rng.choice(config["exchanges"])
        user_agent = rng.choice(config["user_agents"])

        event = _build_base_event(
            event_id=event_idx,
            timestamp=current_ts,
            profile_name=profile_name,
            account=account,
            exchange=exchange,
            symbol=symbol,
            country=country,
            ip_address=ip_address,
            user_agent=user_agent,
            event_type=event_type,
            request_suffix=rng.randint(1000, 9999),
        )

        if event_type == "order.create":
            order_sequence = _create_order_event(
                event=event,
                profile_name=profile_name,
                profile_config=profile_config,
                symbol=symbol,
                current_price=current_price,
                trend_state=trend_state,
                open_orders=open_orders,
                order_sequence=order_sequence,
                rng=rng,
            )
        elif event_type == "order.cancel":
            canceled = _create_cancel_event(
                event=event,
                account_id=account["account_id"],
                open_orders=open_orders,
                rng=rng,
            )
            if not canceled:
                # Defensive fallback if order pools are exhausted.
                event["event_type"] = "order.create"
                event["event_category"] = EVENT_CATEGORIES["order.create"]
                order_sequence = _create_order_event(
                    event=event,
                    profile_name=profile_name,
                    profile_config=profile_config,
                    symbol=symbol,
                    current_price=current_price,
                    trend_state=trend_state,
                    open_orders=open_orders,
                    order_sequence=order_sequence,
                    rng=rng,
                )
        elif event_type in {"auth.login.success", "auth.login.failure"}:
            _create_auth_event(event, event_type, rng)
        elif event_type == "api_key.used":
            _create_api_key_event(event, rng)
        elif event_type == "withdrawal.request":
            _create_withdrawal_event(event, symbol, rng)
        elif event_type == "ws.heartbeat":
            _create_heartbeat_event(event, rng)

        events.append(event)

    return events


def generate_events(
    *,
    total_events: int,
    seed: int,
    start_time: str,
    config_path: str | Path,
) -> list[dict[str, Any]]:
    """Convenience wrapper used by the CLI script and tests."""

    config = load_simulation_config(config_path)
    parsed_start = parse_start_time(start_time or config.get("start_time", DEFAULT_START_TIME))
    return iter_events(total_events=total_events, seed=seed, start_time=parsed_start, config=config)


def summarize_events(events: list[dict[str, Any]]) -> dict[str, Any]:
    """Return profile and event distribution metrics for quick validation."""

    profile_counts: Counter[str] = Counter()
    event_type_counts: Counter[str] = Counter()
    profile_event_counts: dict[str, Counter[str]] = defaultdict(Counter)

    for event in events:
        profile = str(event["profile"])
        event_type = str(event["event_type"])
        profile_counts[profile] += 1
        event_type_counts[event_type] += 1
        profile_event_counts[profile][event_type] += 1

    return {
        "total_events": len(events),
        "profile_counts": dict(profile_counts),
        "event_type_counts": dict(event_type_counts),
        "profile_event_counts": {key: dict(value) for key, value in profile_event_counts.items()},
    }
