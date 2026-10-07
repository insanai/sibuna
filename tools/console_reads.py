"""Bounded pacing for fixtures sharing a management session's query allowance."""
import time


def budgeted(h, port, method, path, body=None, cookie=None, csrf=None):
    """Retry a throttled read for one allowance window; other failures remain visible."""
    deadline = time.monotonic() + 65
    while True:
        response = h.request(port, method, path, body, cookie, csrf)
        if response[0] != 429:
            return response
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise AssertionError(("the query allowance did not recover", path, response[2][:128]))
        time.sleep(min(5, remaining))
