import re
from urllib.parse import urlparse

def extract_url(url: str) -> dict:
    parsed = urlparse(url)
    hostname = parsed.hostname or ""
    path = parsed.path or ""

    def count(char): return url.count(char)

    feature = {
        "length_url": len(url),
        "length_hostname": len(hostname),
        "ip": 1 if re.match(r"(\d{1,3}\.){3}\d{1,3}", hostname) else 0,
        "nb_dots": hostname.count("."),
        "nb_hyphens": hostname.count("-"),
        "nb_at": url.count("@"),
        "nb_qm": url.count("?"),
        "nb_eq": url.count("="),
        "nb_slash": url.count("/"),
        "https_token": 1 if "https" in url.lower() else 0,
        "nb_subdomains": len(hostname.split(".")) - 2 if hostname.count(".") > 1 else 0,
        "prefix_suffix": 1 if "-" in hostname else 0,
        "tld_in_path": 1 if re.search(r"\.[a-z]{2,3}/", path) else 0,
        "punycode": 1 if "xn--" in hostname else 0,
    }

    return feature
