"""Private string helpers. Do not ship."""


def clean(value: str) -> str:
    return " ".join(value.split())
