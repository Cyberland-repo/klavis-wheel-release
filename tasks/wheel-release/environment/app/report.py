from app._impl.fmt import *


def summarize(title: str, name: str) -> str:
    return bracket(title) + " " + name
