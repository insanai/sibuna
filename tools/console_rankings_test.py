"""Current-minute rankings must come from traffic and exclude query-string secrets."""
import json
import time
from console_reads import budgeted


def check(h, port, data_port, cookie):
    endpoint = "/console/api/rankings"
    assert h.request(port, "GET", endpoint)[0] == 401
    # A boundary may fall between generation and reading. Retry a bounded population;
    # do not infer an exact count from probabilistic sampling or sleep for a minute.
    for attempt in range(3):
        for index in range(512):
            h.request(data_port, "GET", "/rank-review?token=not-for-the-console",
                      extra_headers={"X-Forwarded-For": f"9.{attempt}.{index // 256}.{index % 256}",
                                     "Referer": "https://news.example.test/story?secret=1",
                                     "User-Agent": "Mozilla/5.0 (X11; Linux x86_64; rv:127.0) "
                                                   "Gecko/20100101 Firefox/127.0"})
        time.sleep(0.3)
        status, _, body = budgeted(h, port, "GET", endpoint, cookie=cookie)
        assert status == 200 and len(body) <= 16384, (status, len(body), body[:128])
        assert b"not-for-the-console" not in body
        page = json.loads(body)
        assert page["sampling_probability"] == "1/64"
        assert page["counter_capacity"] == 256
        assert len(page["rows"]) <= 12
        assert page["minute_start"] <= page["snapshot_at"] < page["minute_start"] + 60
        rows = [row for row in page["rows"] if row["key"] == "/rank-review"]
        if not rows:
            continue
        assert rows[0]["encoding"] == "utf8"
        assert rows[0]["estimate"] > 0 and rows[0]["error_bound"] == 0
        assert page["retained_samples"] >= rows[0]["estimate"]
        # Referring hosts keep the host only; families are exact over the same samples.
        assert b"secret=1" not in body and b"/story" not in body
        hosts = [row for row in page["referrers"] if row["key"] == "news.example.test"]
        assert hosts and hosts[0]["estimate"] >= 1
        assert page["referrer_samples"] <= page["retained_samples"]
        families = page["families"]
        assert families["os"][5] >= 1 and families["browser"][2] >= 1, families
        assert sum(families["status"]) == page["retained_samples"]
        return
    raise AssertionError("live sample generation did not populate current-minute rankings")
