import app._impl.model as _m


def render(title: str, name: str) -> str:
    return _m.Card(title, name).line()
