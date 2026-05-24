"""Shared utilities for windows_dataset scrapers.

All per-domain scrapers (msrc.microsoft.com/, portal.msrc.microsoft.com/,
github.com/, git.kernel.org/, ibm.com/) import this module to get:

* A pool of realistic User-Agents and a randomised picker.
* Randomised delay helpers (per-request + per-retry).
* A `requests.Session` factory that rotates UA per call.
* `fetch_with_retries(...)` — retry/backoff wrapper that honours
  Retry-After and treats 429/5xx as transient.
* JSON load/save helpers + atomic checkpoint writes.

The deliberate jitter on every request is to avoid pattern detection from
the upstream web servers (MSRC, GitHub, IBM, kernel.org). Tune the
`min_delay` / `max_delay` knobs in each scraper to whatever the host
tolerates.
"""

import json
import os
import random
import time
import urllib.parse
from typing import Any, Dict, Iterable, Optional

import requests

USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36 Edg/119.0.0.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_2) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Safari/605.1.15",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 13_6) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:122.0) Gecko/20100101 Firefox/122.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_2 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Mobile/15E148 Safari/604.1",
]


def random_user_agent() -> str:
    return random.choice(USER_AGENTS)


def random_delay(min_delay: float = 1.5, max_delay: float = 4.0) -> None:
    time.sleep(random.uniform(min_delay, max_delay))


def domain_of(url: str) -> str:
    netloc = urllib.parse.urlparse(url).netloc.lower()
    if netloc.startswith("www."):
        netloc = netloc[4:]
    return netloc


def make_session(extra_headers: Optional[Dict[str, str]] = None) -> requests.Session:
    s = requests.Session()
    s.headers.update({
        "User-Agent": random_user_agent(),
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        "Accept-Language": "en-US,en;q=0.9",
        "Accept-Encoding": "gzip, deflate",
        "Connection": "keep-alive",
        "Upgrade-Insecure-Requests": "1",
    })
    if extra_headers:
        s.headers.update(extra_headers)
    return s


def fetch_with_retries(
    session: requests.Session,
    url: str,
    *,
    method: str = "GET",
    max_retries: int = 4,
    timeout: int = 30,
    min_delay: float = 1.5,
    max_delay: float = 4.0,
    accept_status: Iterable[int] = (200,),
    **kwargs: Any,
) -> Optional[requests.Response]:
    """Fetch a URL with retry, jittered delay, and rotated User-Agent.

    Returns the `Response` if its status_code is in `accept_status`, else
    None after exhausting retries. 429 and 5xx are treated as transient
    and retried with backoff that respects Retry-After when present.
    """
    last_resp: Optional[requests.Response] = None
    for attempt in range(max_retries):
        session.headers["User-Agent"] = random_user_agent()
        try:
            resp = session.request(method, url, timeout=timeout, **kwargs)
            last_resp = resp
            if resp.status_code in accept_status:
                random_delay(min_delay, max_delay)
                return resp
            if resp.status_code in (429, 500, 502, 503, 504):
                wait = _retry_after(resp) or ((attempt + 1) * 5 + random.uniform(0, 3))
                time.sleep(wait)
                continue
            # Hard failure (4xx other than 429): don't retry.
            random_delay(min_delay, max_delay)
            return resp
        except requests.RequestException:
            time.sleep((attempt + 1) * 3 + random.uniform(0, 2))
    return last_resp


def _retry_after(resp: requests.Response) -> Optional[float]:
    val = resp.headers.get("Retry-After")
    if not val:
        return None
    try:
        return float(val)
    except ValueError:
        return None


def load_json(path: str) -> Any:
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def save_json(path: str, data: Any) -> None:
    parent = os.path.dirname(path)
    if parent:
        os.makedirs(parent, exist_ok=True)
    tmp = f"{path}.tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False, indent=2)
    os.replace(tmp, path)


def safe_filename(text: str, maxlen: int = 160) -> str:
    """Sanitise a string for use as a filename (URL stems, commit ids...)."""
    keep = "-_.()"
    out = "".join(c if c.isalnum() or c in keep else "_" for c in text)
    return out[:maxlen] or "unnamed"
