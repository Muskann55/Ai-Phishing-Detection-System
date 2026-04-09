from typing import Set
from urllib.parse import urlparse

WHITELIST: Set[str] = {
    "official-vote.university.edu",
    "mycollege.ac.in",
}

BLACKLIST: Set[str] = {
    "malicious-vote.xyz",
    "fake-login.top",
}

def host_from_url(url: str) -> str:
    return urlparse(url).netloc.lower()

def check_lists(url: str) -> dict:
    host = host_from_url(url)
    if host in BLACKLIST:
        return {"blacklisted": True, "whitelisted": False}
    if host in WHITELIST:
        return {"blacklisted": False, "whitelisted": True}
    return {"blacklisted": False, "whitelisted": False}