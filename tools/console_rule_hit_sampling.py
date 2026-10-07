"""Place real request cohorts inside one retained 1 Hz counter-sampling minute."""
import time


def begin(wait):
    # The journal assigns counter deltas to the sampling minute, not to individual
    # request timestamps. Keep headroom on both sides of a minute boundary.
    deadline = time.monotonic() + 65
    while not 2 <= int(time.time()) % 60 <= 45:
        assert time.monotonic() < deadline, "rule-hit cohort start deadline"
        wait()
    return int(time.time()) // 60


def finish(first):
    last = int(time.time()) // 60
    assert first == last and int(time.time()) % 60 < 55, "cohort crossed sampling boundary"
    return last
