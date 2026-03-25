import contextlib


def process():
    with contextlib.suppress(Exception):
        risky()
