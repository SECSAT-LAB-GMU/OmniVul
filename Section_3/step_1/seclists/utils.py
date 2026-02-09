import time
import requests
from const import req_reties, Req_backoff, req_timeout, Req_delay

def fetch_with_retry(session, url, headers=None):
    # Fetch a URL with retries on failure
    for attempt in range(1, req_reties + 1):
        try:
            resp = session.get(url, headers=headers, timeout=req_timeout)
            if resp.status_code == 200:
                return resp
            elif resp.status_code == 429:
                retry_after = resp.headers.get("Retry-After")
                wait_time = int(retry_after) if retry_after and retry_after.isdigit() else Req_backoff * attempt
                time.sleep(wait_time)
        except requests.exceptions.RequestException as e:
            time.sleep(Req_backoff * attempt)
    return None

