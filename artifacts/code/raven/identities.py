"""Identifier canonicalisation and identity acquisition for overlap control (P3).

Canonical keys are plain strings with a kind prefix, e.g. ``repo:github.com/owner/name``,
``npm:left-pad``, ``adv:CVE-2021-4278``, ``commit:<40 hex>``. Two records sharing any key
end up in the same equivalence group.
"""

from __future__ import annotations

import re
import urllib.error
import urllib.parse
import urllib.request
from typing import Any

CVE = re.compile(r"\bCVE-\d{4}-\d{4,}\b", re.IGNORECASE)
GHSA = re.compile(r"\bGHSA(?:-[23456789cfghjmpqrvwx]{4}){3}\b", re.IGNORECASE)
SNYK = re.compile(r"\bSNYK-[A-Z0-9]+-[A-Z0-9_.-]+-\d+\b", re.IGNORECASE)
COMMIT = re.compile(r"^[0-9a-f]{40}$")

_SCP = re.compile(r"^(?:[\w.-]+@)?([\w.-]+):(?!//)(.+)$")
_REPO_TAIL = re.compile(r"/(?:tree|blob|commit|commits|issues|pull|pulls|releases|tags|wiki|security|compare)(?:/.*)?$")


def advisory_keys(*texts: str) -> set[str]:
    keys = set()
    for text in texts:
        if not text:
            continue
        keys |= {f"adv:{m.upper()}" for m in CVE.findall(text)}
        keys |= {f"adv:{m.upper()}" for m in GHSA.findall(text)}
        keys |= {f"adv:{m.upper()}" for m in SNYK.findall(text)}
    return keys


def canonical_repo(url: str) -> str:
    pass




    url = (url or "").strip()
    if not url:
        return ""
    for prefix, host in (("github:", "github.com"), ("gitlab:", "gitlab.com"), ("bitbucket:", "bitbucket.org")):
        if url.startswith(prefix):
            url = f"https://{host}/{url[len(prefix):]}"
    if re.fullmatch(r"[\w.-]+/[\w.-]+", url):
        url = f"https://github.com/{url}"
    url = re.sub(r"^git\+", "", url)
    scp = _SCP.match(url)
    if scp and "://" not in url:
        url = f"https://{scp.group(1)}/{scp.group(2)}"
    parsed = urllib.parse.urlparse(url)
    host = (parsed.hostname or "").lower().removeprefix("www.")
    path = _REPO_TAIL.sub("", parsed.path).strip("/")
    path = re.sub(r"\.git$", "", path)
    parts = [p for p in path.split("/") if p]
    if not host or len(parts) < 2 or host.endswith(("npmjs.com", "npmjs.org")):
        return ""
    if host == "github.com" and parts[0] in {"advisories", "orgs", "sponsors", "topics", "marketplace"}:
        return ""
    return f"{host}/{parts[0]}/{parts[1]}".lower()


def canonical_package(name: str) -> str:
    return (name or "").strip().lower()


def target_dependencies(record_id: str, packages: list[str], helpers: set[str]) -> tuple[list[str], list[str], str]:
    pass





    if len(packages) <= 1:
        return packages, [], "single"
    leaf = record_id.rsplit("/", 1)[-1]
    stem = leaf.rsplit("_", 1)[0] if "_" in leaf else leaf
    named = [p for p in packages if canonical_package(p) == canonical_package(stem)]
    if len(named) == 1:
        return named, [p for p in packages if p not in named], "directory_name"
    rest = [p for p in packages if canonical_package(p) not in helpers]
    if len(rest) == 1:
        return rest, [p for p in packages if p not in rest], "helpers_removed"
    return packages, [], "all_dependencies"


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args: Any, **kwargs: Any) -> None:
        return None


def github_location(owner_name: str, timeout: float = 30.0) -> tuple[int | None, str]:
    pass



    opener = urllib.request.build_opener(_NoRedirect)
    request = urllib.request.Request(
        f"https://github.com/{owner_name}", method="HEAD",
        headers={"User-Agent": "RAVEN-pilot-identity (research; metadata only)"},
    )
    try:
        with opener.open(request, timeout=timeout) as response:
            return response.status, ""
    except urllib.error.HTTPError as exc:
        if exc.code in (301, 302, 307, 308):
            target = canonical_repo(exc.headers.get("Location", ""))
            return exc.code, target.removeprefix("github.com/") if target.startswith("github.com/") else ""
        return exc.code, ""
    except (urllib.error.URLError, TimeoutError, ConnectionError) as exc:
        return None, f"error: {type(exc).__name__}"
