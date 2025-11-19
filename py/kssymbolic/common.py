def parse_addr(x: int | str | None) -> int:
    """Parses an address."""
    if x is None:
        return 0
    if isinstance(x, int):
        return x
    if isinstance(x, str):
        if x[:2] == "0x":
            return int(x[2:], 16)
        return int(x)
    raise ValueError(f"Unsupported address format {x!r}")
