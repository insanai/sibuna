#!/usr/bin/env python3
"""Prepare real challenges and sessions outside benchmark timing.

All protocols use SHA-256 and 16 leading zero bits, but their envelopes and session
mechanisms differ. Request groups retain each product's actual round trip count.
"""
from dataclasses import dataclass
import gzip
import hashlib
import http.client
import json
import re
import time
import urllib.parse

from compare import API, cookies
from product_fixtures import BITS, CLIENT_HEADERS


@dataclass(frozen=True)
class Request:
    method: str
    path: str
    headers: dict
    body: object = None
    expected: int = 200


class AdmissionClient:
    def __init__(self, host, port, product):
        self.host, self.port, self.product = host, port, product

    def exchange(self, task, connection=None):
        own = connection is None
        connection = connection or http.client.HTTPConnection(self.host, self.port, timeout=15)
        try:
            connection.request(task.method, task.path, task.body, task.headers)
            response = connection.getresponse()
            body = response.read()
            if response.status != task.expected:
                raise ValueError(f"{task.path}: expected {task.expected}, got {response.status}: "
                                 f"{body[:200]!r}")
            if response.getheader("Content-Encoding", "").lower() == "gzip":
                body = gzip.decompress(body)
            return response.getheaders(), body
        finally:
            if own:
                connection.close()

    def prepare(self):
        if self.product.startswith("sibuna"):
            time.sleep(0.025)  # Below the native adaptive issuance baseline; untimed.
            headers, body = self.exchange(Request("GET", "/__sibuna/challenge.json?path=/private",
                                                   CLIENT_HEADERS))
            challenge = json.loads(body)
            if challenge["difficulty"] != BITS:
                raise ValueError("Sibuna's issued work differs from the matched fixture")
            prefix, identifier, cookie = challenge["id"] + ":", challenge["id"], ""
        elif self.product.startswith("anubis"):
            headers, body = self.exchange(Request("GET", "/private", CLIENT_HEADERS))
            match = re.search(rb'<script id="anubis_challenge"[^>]*>(.*?)</script>', body, re.S)
            if not match:
                raise ValueError("Anubis did not return its challenge envelope")
            info = json.loads(match.group(1))
            if info["rules"]["difficulty"] != BITS // 4:
                raise ValueError("Anubis's issued work differs from the matched fixture")
            prefix, identifier = info["challenge"]["randomData"], info["challenge"]["id"]
            cookie = cookies(headers)
        else:
            headers, _ = self.exchange(Request("GET", "/private", CLIENT_HEADERS, expected=302))
            cookie = cookies(headers)
            _, body = self.exchange(Request("GET", "/challenge",
                                            {**CLIENT_HEADERS, "Cookie": cookie}))
            match = re.search(rb'digestMessage\("([^"]+)"\+a.toString\(\)\)', body)
            if not match or b'.startsWith("0000")' not in body:
                raise ValueError("BunkerWeb did not return its 16-bit JavaScript challenge")
            prefix, identifier = match.group(1).decode(), ""
        for nonce in range(1 << 24):
            digest = hashlib.sha256((prefix + str(nonce)).encode()).hexdigest()
            if digest.startswith("0" * (BITS // 4)):
                return self.verification(identifier, nonce, digest, cookie)
        raise ValueError("bounded proof solver exhausted")

    def verification(self, identifier, nonce, digest, cookie):
        headers = {**CLIENT_HEADERS, "Cookie": cookie}
        if self.product.startswith("sibuna"):
            return Request("POST", "/__sibuna/verify", headers,
                           json.dumps({"challenge_id": identifier, "nonce": str(nonce)}))
        if self.product.startswith("anubis"):
            query = urllib.parse.urlencode({"id": identifier, "nonce": nonce, "response": digest,
                                            "elapsedTime": 1000, "redir": "/private"})
            return Request("GET", API + "pass-challenge?" + query, headers, expected=302)
        headers["Content-Type"] = "application/x-www-form-urlencoded"
        return Request("POST", "/challenge", headers,
                       urllib.parse.urlencode({"challenge": nonce, "next": "/private"}), 302)

    def session(self):
        task = self.prepare()
        headers, _ = self.exchange(task)
        cookie = cookies(headers)
        if not cookie:
            raise ValueError("verified proof produced no session cookie")
        return cookie

    def bootstrap(self):
        if self.product.startswith("sibuna"):
            return [Request("GET", "/__sibuna/challenge", CLIENT_HEADERS),
                    Request("GET", "/__sibuna/challenge.json?path=/private", CLIENT_HEADERS)]
        if self.product.startswith("anubis"):
            return [Request("GET", "/private", CLIENT_HEADERS)]
        return [Request("GET", "/private", CLIENT_HEADERS, expected=302),
                Request("GET", "/challenge", CLIENT_HEADERS)]
