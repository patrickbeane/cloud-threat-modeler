from __future__ import annotations

import ipaddress

_BROAD_PUBLIC_ALIASES = frozenset({"*", "internet", "any"})


def is_broad_public_range(value: object) -> bool:
    normalized = str(value or "").strip().lower()
    if not normalized:
        return False
    if normalized in _BROAD_PUBLIC_ALIASES:
        return True
    try:
        network = ipaddress.ip_network(normalized, strict=False)
    except ValueError:
        return False
    return network.prefixlen == 0
