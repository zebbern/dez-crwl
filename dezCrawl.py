#!/usr/bin/env python3
import argparse
import json
import logging
import os
import random
import re
import signal
import sys
import threading
import time
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import List, Optional, Set, Tuple, Dict
from urllib.parse import urlparse

import requests
import yaml
from colorama import init, Fore, Style
from dateutil import parser as date_parser
from pystyle import Colorate, Colors

# --- Additional Imports for Async Enhancements ---
import asyncio
import aiohttp

# ====================================================================
# Existing functions remain unchanged.
# ====================================================================

# --- Clear Screen and Print Logo at Startup ---
def clear():
    os.system('cls' if os.name == 'nt' else 'clear')
clear()
init(autoreset=True)
logo = r"""_____              ____               _ 
|  _ \  ___ ____  / ___|_ ____      _| |
| | | |/ _ \_  / | |   | '__\ \ /\ / / |
| |_| |  __// /  | |___| |   \ V  V /| |
|____/ \___/___|  \____|_|    \_/\_/ |_|

═║ Developed by: Github.com/zebbern ║═

"""
print(Colorate.Diagonal(Colors.purple_to_red, logo.strip()), end="\n\n")

# --- Global Settings & Results Folder ---
USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/58.0.3029.110 Safari/537.3",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.0 Safari/605.1.15",
]
logging.getLogger().setLevel(logging.CRITICAL)  # Suppress normal logging

def get_results_folder(domains: List[str]) -> Path:
    if len(domains) == 1:
        folder_name = f"{domains[0]}-results"
    else:
        folder_name = "combined-results"
    folder = Path(folder_name)
    folder.mkdir(exist_ok=True)
    (folder / "status").mkdir(exist_ok=True)
    return folder

# --- Dashboard Global Variables & Function ---
dashboard_data = {
    "domain": "",
    "output": 0,
    "fetched_urls": [],
    "directories": 0,
    "js_endpoints": 0,
    "js_checked": 0,
    "subdomains": [],
    "filtered": {},
    "ips": [],
    "sensitive": 0,
}
dashboard_running = True

def display_dashboard():
    while dashboard_running:
        clear()
        print(Colorate.Horizontal(Colors.purple_to_red, logo.strip()))
        print(f"{Fore.GREEN}Domain:{Style.RESET_ALL} {dashboard_data.get('domain', 'N/A')}\n")
        print(f"{Fore.GREEN}Urls Fetched:{Style.RESET_ALL} {dashboard_data.get('output', 0)}")
        fetched = dashboard_data.get("fetched_urls", [])
        if fetched:
            for url in fetched[:10]:
                print(f"   {url}")
            if len(fetched) > 10:
                print(f"   ... and {len(fetched)-10} more")
        print(f"{Fore.GREEN}Directories Found:{Style.RESET_ALL} {dashboard_data.get('directories', 0)}")
        print(f"{Fore.GREEN}JS Endpoints Found:{Style.RESET_ALL} {dashboard_data.get('js_endpoints', 0)} (JS checked: {dashboard_data.get('js_checked', 0)})")
        subs = dashboard_data.get("subdomains", [])
        if subs:
            print(f"{Fore.GREEN}Subdomains Found:{Style.RESET_ALL} {' | '.join(subs)}")
        filt = dashboard_data.get("filtered", {})
        if filt:
            filt_display = " | ".join([f"{k}: {v}" for k, v in filt.items() if v > 0])
            print(f"{Fore.GREEN}Filtered Found:{Style.RESET_ALL} {filt_display}")
        ips = dashboard_data.get("ips", [])
        if ips:
            print(f"{Fore.GREEN}IP Found:{Style.RESET_ALL} {' | '.join(ips)}")
        sensitive = dashboard_data.get("sensitive", 0)
        if sensitive:
            print(f"{Fore.GREEN}Sensitive Info Found:{Style.RESET_ALL} {sensitive} items")
        time.sleep(2)

# --- Helper: Robust HTTP GET with Exponential Backoff ---
def log_http_status(status: int, url: str, results_folder: Path) -> None:
    status_dir = results_folder / "status"
    status_dir.mkdir(exist_ok=True)
    file_path = status_dir / f"{status}.txt"
    timestamp = datetime.utcnow().isoformat()
    with file_path.open("a") as f:
        f.write(f"{timestamp} | {url}\n")

def robust_get(session: requests.Session, url: str, headers: dict, timeout: int = 30, log_status: bool = False, results_folder: Optional[Path] = None, max_retries_override: Optional[int] = None) -> requests.Response:
    max_retries = max_retries_override if max_retries_override is not None else 7
    delay = 2
    for attempt in range(max_retries):
        try:
            resp = session.get(url, headers=headers, timeout=timeout)
            if log_status and results_folder is not None:
                log_http_status(resp.status_code, url, results_folder)
            if resp.status_code == 429:
                raise requests.exceptions.HTTPError("429 Too Many Requests")
            resp.raise_for_status()
            return resp
        except requests.exceptions.HTTPError as e:
            if hasattr(e, "response") and e.response is not None and e.response.status_code == 429:
                time.sleep(delay)
                delay *= 2
            else:
                raise
    raise Exception(f"Max retries exceeded for {url}")

def get_random_headers() -> dict:
    return {"User-Agent": random.choice(USER_AGENTS)}

# --- Dataclasses ---
@dataclass
class WebURL:
    url: str
    date: str = ""
    def formatted(self, show_date: bool) -> str:
        if show_date and self.date:
            try:
                d = date_parser.parse(self.date)
                return f"{d.isoformat()} {self.url}"
            except Exception:
                return self.url
        return self.url

# --- Configuration ---
def load_config(config_path: str = "config.yaml") -> dict:
    config = {}
    if os.path.exists(config_path):
        try:
            with open(config_path, "r") as f:
                config = yaml.safe_load(f) or {}
        except Exception:
            pass
    return config

# --- Utility Functions ---
def is_domain(s: str) -> bool:
    return "." in s and "/" not in s

def read_domains_from_file(filename: str) -> List[str]:
    try:
        with open(filename, "r") as f:
            return [line.strip() for line in f if line.strip()]
    except Exception as e:
        raise Exception(f"Error opening file {filename}: {e}")

def get_domains(target: Optional[str], args: List[str]) -> List[str]:
    if target:
        if is_domain(target):
            return [target]
        if not os.path.exists(target):
            raise Exception(f"Target file '{target}' does not exist.")
        return read_domains_from_file(target)
    return args

def parse_status_codes(codes: Optional[str]) -> Optional[Set[str]]:
    if codes:
        return {code.strip() for code in codes.split(",") if code.strip()}
    return None

def write_output(results: List[WebURL], output_file: Optional[str], show_dates: bool, results_folder: Path) -> None:
    sorted_results = sorted(
        results,
        key=lambda x: (os.path.splitext(urlparse(x.url).path)[1].lower(), x.url)
    )
    if output_file:
        path = results_folder / output_file
        with path.open("w") as f:
            for w in sorted_results:
                f.write(f"{w.formatted(show_dates)}\n")
    else:
        for w in sorted_results:
            print(w.formatted(show_dates))

# --- Common Crawl Functions ---
def get_latest_commoncrawl_index(session: requests.Session) -> str:
    url = "https://index.commoncrawl.org/collinfo.json"
    resp = robust_get(session, url, get_random_headers(), timeout=30)
    collinfo = resp.json()
    return collinfo[0]["id"]

def get_common_crawl_osint(domain: str, no_subdomains: bool, _vt_api_key: str, session: requests.Session, allowed_status_codes: Optional[Set[str]] = None, results_folder: Path = None, **kwargs) -> List[WebURL]:
    index = get_latest_commoncrawl_index(session)
    prefix = "" if no_subdomains else "*."
    cc_url = f"https://index.commoncrawl.org/{index}-index?url={prefix}{domain}/*&output=json"
    resp = robust_get(session, cc_url, get_random_headers(), timeout=30, results_folder=results_folder)
    out = []
    for line in resp.text.splitlines():
        try:
            record = json.loads(line)
            url = record.get("url", "")
            timestamp = record.get("timestamp", "")
            statuscode = record.get("status", "")
            if allowed_status_codes and statuscode not in allowed_status_codes:
                continue
            out.append(WebURL(url=url, date=timestamp))
        except Exception:
            continue
    return out

# --- Other Fetcher Functions ---
def get_wayback_urls(domain: str, no_subdomains: bool, _vt_api_key: str, session: requests.Session, allowed_status_codes: Optional[Set[str]] = None, results_folder: Path = None) -> List[WebURL]:
    if no_subdomains:
        prefix = ""
        suffix = ""
        collapse = ""
    else:
        prefix = "*."
        suffix = "/*"
        collapse = "&collapse=urlkey"
    wayback_url = (f"https://web.archive.org/cdx/search/cdx?url={prefix}{domain}{suffix}{collapse}"
                   f"&fl=timestamp,original,mimetype,statuscode,digest&output=json")
    resp = robust_get(session, wayback_url, get_random_headers(), timeout=30, log_status=True, results_folder=results_folder)
    records = resp.json()
    out = []
    for i, record in enumerate(records):
        if i == 0 and record[0].lower() == "timestamp":
            continue
        if len(record) < 5:
            continue
        timestamp, original, mimetype, statuscode, digest = record[:5]
        if allowed_status_codes and statuscode not in allowed_status_codes:
            continue
        log_http_status(statuscode, original, results_folder)
        out.append(WebURL(url=original, date=timestamp))
    return out

def get_virustotal_urls(domain: str, no_subdomains: bool, vt_api_key: str, session: requests.Session, **kwargs) -> List[WebURL]:
    if not vt_api_key:
        return []
    url = f"https://www.virustotal.com/vtapi/v2/domain/report?apikey={vt_api_key}&domain={domain}"
    resp = robust_get(session, url, get_random_headers(), timeout=30)
    data = resp.json()
    out = []
    for item in data.get("detected_urls", []):
        out.append(WebURL(url=item.get("url", "")))
    return out

def get_versions(u: str, session: requests.Session) -> List[str]:
    url = f"http://web.archive.org/cdx/search/cdx?url={u}&output=json"
    resp = robust_get(session, url, get_random_headers(), timeout=30)
    records = resp.json()
    out = []
    seen = set()
    for i, record in enumerate(records):
        if i == 0 or len(record) < 6:
            continue
        digest = record[5]
        if digest in seen:
            continue
        seen.add(digest)
        timestamp, original_url = record[1], record[2]
        out.append(f"https://web.archive.org/web/{timestamp}if_/{original_url}")
    return out

def get_version_urls(domains: List[str], session: requests.Session) -> None:
    for u in domains:
        try:
            for v in get_versions(u, session):
                print(v)
        except Exception:
            continue

# --- JavaScript Extraction & Sensitive Info ---
def extract_sensitive_info(text: str) -> Dict[str, List[str]]:
    patterns = {
        "jwt": re.compile(r"\b([A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+)\b"),
        "aws_key": re.compile(r"\b(AKIA[0-9A-Z]{16})\b"),
        "google_key": re.compile(r"\b(AIza[0-9A-Za-z\-_]{35})\b"),
        "stripe_key": re.compile(r"\b(sk_live_[0-9a-zA-Z]{24,})\b"),
        "db_url": re.compile(r"\b(?:mysql|postgres|mongodb)://[^'\"\s]+\b"),
        "oauth": re.compile(r"\b(?:oauth2?://)[^'\"\s]+\b"),
    }
    extracted = defaultdict(list)
    for label, pattern in patterns.items():
        matches = pattern.findall(text)
        extracted[label].extend(matches)
    return dict(extracted)

FALSE_POSITIVES = {
    "e.prototype.reset",
    "this.settings.render",
    "config.apiKey",
    "window.token",
    "null",
    "undefined",
    "",
}

def clean_sensitive_data(data: Dict[str, List[str]]) -> Dict[str, List[str]]:
    cleaned = {}
    for label, values in data.items():
        valid = []
        for value in values:
            if label == "jwt":
                parts = value.split('.')
                if len(parts) != 3 or any(len(p) < 10 for p in parts):
                    continue
            if label == "aws_key" and not value.startswith("AKIA"):
                continue
            if label == "google_key" and not value.startswith("AIza"):
                continue
            if label == "stripe_key" and not value.startswith("sk_live_"):
                continue
            if label == "db_url" and not (value.startswith("mysql://") or value.startswith("postgres://") or value.startswith("mongodb://")):
                continue
            if value in FALSE_POSITIVES:
                continue
            valid.append(value)
        if valid:
            cleaned[label] = list(set(valid))
    return cleaned

def extract_hidden_api_from_js(js_url: str, session: requests.Session) -> dict:
    endpoint_pattern = re.compile(r"((?:https?|wss)://[a-zA-Z0-9./?=&%_\-]+)")
    results = {"endpoints": [], "sensitive": {}}
    try:
        resp = robust_get(session, js_url, get_random_headers(), timeout=30, max_retries_override=10)
        text = resp.text
        endpoints = endpoint_pattern.findall(text)
        results["endpoints"] = list(set(endpoints))
        raw_sensitive = extract_sensitive_info(text)
        results["sensitive"] = clean_sensitive_data(raw_sensitive)
        return results
    except Exception:
        return {"endpoints": [], "sensitive": {}}

def extract_apis_from_js_urls(js_urls: List[str], session: requests.Session, workers: int = 5) -> dict:
    discovered = {}
    with ThreadPoolExecutor(max_workers=workers) as executor:
        futures = {executor.submit(extract_hidden_api_from_js, url, session): url for url in js_urls}
        for future in as_completed(futures):
            js_url = futures[future]
            try:
                result = future.result()
                if result["endpoints"] or result["sensitive"]:
                    discovered[js_url] = result
            except Exception:
                continue
    return discovered

# --- Automatic Subdomain Discovery ---
def discover_subdomains(urls: List[WebURL], base_domains: List[str]) -> Set[str]:
    discovered = set()
    for weburl in urls:
        try:
            host = urlparse(weburl.url).hostname
            if host:
                for base in base_domains:
                    if host.endswith(base) and host != base:
                        discovered.add(host)
        except Exception:
            continue
    return discovered

# --- Directory Extraction ---
def extract_directory_patterns(urls: List[WebURL]) -> dict:
    dir_patterns = {}
    for weburl in urls:
        try:
            parsed = urlparse(weburl.url)
            scheme = parsed.scheme or "https"
            netloc = parsed.netloc
            segments = [seg for seg in parsed.path.split("/") if seg]
            if segments:
                first_dir = segments[0]
                pattern = f"https://web.archive.org/web/*/{scheme}://{netloc}/{first_dir}/*"
                dir_patterns.setdefault(first_dir, set()).add(pattern)
        except Exception:
            continue
    return {k: list(v) for k, v in dir_patterns.items()}

# --- Result Filtering ---
def filter_results(results: List[WebURL], filter_pattern: str) -> dict:
    filters = [p.strip() for p in filter_pattern.strip("()").split("|") if p.strip()]
    filtered = {pattern: [] for pattern in filters}
    for weburl in results:
        for pattern in filters:
            if re.search(pattern, weburl.url, re.IGNORECASE):
                filtered[pattern].append(weburl.url)
    return filtered

# --- Local Summary Generation ---
def generate_local_summary(results: List[WebURL], subdomains: Set[str]) -> dict:
    summary = {}
    file_types = defaultdict(int)
    for weburl in results:
        ext = os.path.splitext(urlparse(weburl.url).path)[1].lower() or "none"
        file_types[ext] += 1
    summary["file_types"] = dict(file_types)
    status_counts = {}
    status_dir = RESULTS_FOLDER / "status"
    if status_dir.exists():
        for file in status_dir.glob("*.txt"):
            try:
                with file.open("r") as f:
                    count = sum(1 for _ in f)
                status_counts[file.stem] = count
            except Exception:
                continue
    summary["status_codes"] = status_counts
    summary["subdomains"] = list(subdomains)
    return summary

# --- External API Calls for Summary ---
def get_mnemonic_and_isc(domain: str, session: requests.Session, config: dict) -> dict:
    ip_results = []
    url = f"https://api.mnemonic.no/pdns/v3/{domain}"
    try:
        resp = robust_get(session, url, get_random_headers(), timeout=30)
        data = resp.json()
        if isinstance(data, list):
            ip_results = list({item.get("address") for item in data if item.get("address")})
    except Exception:
        pass
    isc_results = {}
    for ip in ip_results:
        isc_url = f"https://isc.sans.edu/api/ip/{ip}?json"
        try:
            resp = robust_get(session, isc_url, get_random_headers(), timeout=30)
            isc_results[ip] = resp.json()
        except Exception:
            continue
    countries = set()
    for ip, result in isc_results.items():
        country = result.get("country")
        if country:
            countries.add(country)
    return {"ips": ip_results, "isc": isc_results, "uniqIPs": list(ip_results), "uniqCountries": list(countries)}

def get_urlscan_results(domain: str, session: requests.Session, config: dict) -> List[dict]:
    url = f"https://urlscan.io/api/v1/search/?q=domain:{domain}&size=10000"
    try:
        resp = robust_get(session, url, get_random_headers(), timeout=30)
        data = resp.json()
        results = data.get("results", [])
        seen = set()
        unique = []
        for item in results:
            link = item.get("page", {}).get("url")
            if link and link not in seen:
                seen.add(link)
                unique.append(item)
        return unique
    except Exception:
        return []

def get_certspotter_results(domain: str, session: requests.Session, config: dict) -> List[dict]:
    url = f"https://api.certspotter.com/v1/issuances?domain={domain}&include_subdomains=true&expand=dns_names&expand=issuer&expand=revocation&expand=problem_reporting&expand=cert_der"
    try:
        resp = robust_get(session, url, get_random_headers(), timeout=30)
        data = resp.json()
        seen = set()
        unique = []
        for item in data:
            fp = item.get("fingerprint")
            if fp and fp not in seen:
                seen.add(fp)
                unique.append(item)
        return unique
    except Exception:
        return []

def generate_external_summary(domains: List[str], session: requests.Session, config: dict) -> dict:
    summary_ext = {}
    for domain in domains:
        mnemonic_isc = get_mnemonic_and_isc(domain, session, config)
        summary_ext[domain] = {
            "urlscan": get_urlscan_results(domain, session, config),
            "mnemonic_isc": mnemonic_isc,
            "certspotter": get_certspotter_results(domain, session, config)
        }
    return summary_ext

# --- Concurrency & Fetching ---
def fetch_urls(domains: List[str], no_subdomains: bool, vt_api_key: str, allowed_status_codes: Optional[Set[str]], use_commoncrawl: bool, max_workers: int = 10, session: Optional[requests.Session] = None, results_folder: Path = None) -> Tuple[List[WebURL], List[Exception]]:
    fetch_functions = [get_wayback_urls]
    if vt_api_key:
        fetch_functions.append(get_virustotal_urls)
    if use_commoncrawl:
        fetch_functions.append(get_common_crawl_osint)
    results: List[WebURL] = []
    errors: List[Exception] = []
    tasks = []
    if session is None:
        session = requests.Session()
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        for domain in domains:
            for func in fetch_functions:
                tasks.append(executor.submit(func, domain, no_subdomains, vt_api_key, session, allowed_status_codes=allowed_status_codes, results_folder=results_folder))
        try:
            for future in as_completed(tasks):
                try:
                    results.extend(future.result())
                    dashboard_data["output"] = len(results)
                    dashboard_data["fetched_urls"] = [r.url for r in results]
                except Exception as e:
                    errors.append(e)
        except KeyboardInterrupt:
            executor.shutdown(wait=False)
            raise
    unique = {url.url: url for url in results}
    return list(unique.values()), errors

# --- CLI & Main Logic ---
def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        usage=r'dezCrwl target.com -dir -cw -js -ws -sum -o output.txt -f "(\.json|\.env|\.bak|\.backup|\.old|\.git|\.svn|\.swp|\.sql|\.db|\.sqlite|\.log|\.txt|\.zip|\.rar|\.tar\.gz|\.7z|\.pdf|\.docx|\.xlsx|\.conf|\.ini|\.yml|\.yaml|\.dump|\.sql\.dump|\.session|\.pem|\.key|\.crt|\.tmp)"',
    )
    parser.add_argument("-d", action="store_true", help="Include fetch date in output")
    parser.add_argument("-t", metavar="target.com", help="Domain or file with a list of domains")
    parser.add_argument("-n", action="store_true", help="Disable Subdomains Gathering")
    parser.add_argument("-o", metavar="file", help="Save results to a file")
    parser.add_argument("-v", action="store_true", help="List only versioned URLs")
    parser.add_argument("-vt", help="Add VirusTotal API key in (config.yaml)")
    parser.add_argument("-s", metavar="code", help="Filter status codes | Example: -s 403,404")
    parser.add_argument("--workers", type=int, default=10, help="Set concurrent worker count")
    parser.add_argument("-cw", action="store_true", help="Enable Common Crawl")
    parser.add_argument("-ws", action="store_true", help="Improve web status handling")
    parser.add_argument("-js", action="store_true", help="Extract APIs from .js files")
    parser.add_argument("-dir", action="store_true", help="Extract directory patterns")
    parser.add_argument("-f", metavar="regex", help="Filter results using regex")
    parser.add_argument("-sum", action="store_true", help="Generate detailed summary")
    parser.add_argument("domains", nargs="*", help=argparse.SUPPRESS)
    args = parser.parse_args()
    if not args.t and not args.domains:
        parser.error("At least one DOMAIN argument is required.")
    return args

# --- Main ---
if __name__ == "__main__":
    signal.signal(signal.SIGINT, lambda s, f: sys.exit(1))
    config = load_config()
    if config.get("verbose", False):
        logging.getLogger().setLevel(logging.DEBUG)
    args = parse_args()
    allowed_status_codes = parse_status_codes(args.s)
    try:
        base_domains = get_domains(args.t, args.domains)
    except Exception:
        sys.exit(1)
    dashboard_data["domain"] = ", ".join(base_domains)
    RESULTS_FOLDER = get_results_folder(base_domains)
    processed_domains = set(base_domains)
    all_results: List[WebURL] = []
    errors: List[Exception] = []
    vt_api = args.vt if args.vt else ""
    # Start dashboard thread
    dashboard_thread = threading.Thread(target=display_dashboard, daemon=True)
    dashboard_thread.start()
    with requests.Session() as session:
        try:
            if args.v:
                get_version_urls(base_domains, session)
                sys.exit(0)
            results, errs = fetch_urls(
                base_domains,
                args.n,
                vt_api,
                allowed_status_codes,
                use_commoncrawl=args.cw,
                max_workers=args.workers,
                session=session,
                results_folder=RESULTS_FOLDER
            )
            all_results.extend(results)
            errors.extend(errs)
            new_subdomains = discover_subdomains(results, base_domains)
            new_subdomains -= processed_domains
            if new_subdomains:
                with (RESULTS_FOLDER / "subdomains.txt").open("a") as f:
                    for sd in new_subdomains:
                        f.write(f"{sd}\n")
                processed_domains.update(new_subdomains)
            dashboard_data["subdomains"] = list(processed_domains)
            sub_results, sub_errs = fetch_urls(
                list(new_subdomains),
                args.n,
                vt_api,
                allowed_status_codes,
                use_commoncrawl=args.cw,
                max_workers=args.workers,
                session=session,
                results_folder=RESULTS_FOLDER
            )
            all_results.extend(sub_results)
            errors.extend(sub_errs)
        except KeyboardInterrupt:
            sys.exit(1)
        endpoints_dict = {}
        if args.js:
            js_urls = [r.url for r in all_results if r.url.lower().endswith(".js")]
            dashboard_data["js_checked"] = len(js_urls)
            if js_urls:
                endpoints_dict = extract_apis_from_js_urls(js_urls, session, workers=5)
                try:
                    with (RESULTS_FOLDER / "endpoints.json").open("w") as f:
                        json.dump(endpoints_dict, f, indent=2)
                    total_endpoints = sum(len(v.get("endpoints", [])) for v in endpoints_dict.values())
                    total_sensitive = sum(len(v.get("sensitive", {})) for v in endpoints_dict.values())
                    dashboard_data["js_endpoints"] = total_endpoints
                    dashboard_data["sensitive"] = total_sensitive
                except Exception:
                    pass
        unique_results = {r.url: r for r in all_results}
        all_results = list(unique_results.values())
        if args.dir:
            dir_patterns = extract_directory_patterns(all_results)
            try:
                with (RESULTS_FOLDER / "dirs.json").open("w") as f:
                    json.dump(dir_patterns, f, indent=2)
                dashboard_data["directories"] = len(dir_patterns)
            except Exception:
                pass
        if args.f:
            filtered = filter_results(all_results, args.f)
            try:
                with (RESULTS_FOLDER / "filtered.json").open("w") as f:
                    json.dump(filtered, f, indent=2)
                dashboard_data["filtered"] = {k: len(v) for k, v in filtered.items() if len(v) > 0}
            except Exception:
                pass
        if args.sum:
            external_summary = generate_external_summary(base_domains, session, config)
            local_summary = generate_local_summary(all_results, processed_domains)
            for domain in base_domains:
                mi = external_summary.get(domain, {}).get("mnemonic_isc", {})
                if domain == base_domains[0]:
                    dashboard_data["ips"] = mi.get("uniqIPs", [])
            full_summary = {"external": external_summary, "local": local_summary}
            try:
                with (RESULTS_FOLDER / "summary.yaml").open("w") as f:
                    yaml.dump(full_summary, f, default_flow_style=False)
            except Exception:
                pass
    dashboard_data["output"] = len(all_results)
    dashboard_data["fetched_urls"] = [r.url for r in all_results]
    time.sleep(2)
    dashboard_running = False
    try:
        write_output(all_results, args.o, args.d, RESULTS_FOLDER)
    except Exception:
        sys.exit(1)
