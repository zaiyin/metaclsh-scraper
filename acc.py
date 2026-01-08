import base64
import yaml
import requests
from urllib.parse import urlparse, parse_qs
import json
from bs4 import BeautifulSoup

# =============================
#  COUNTRY CODE YANG DIAMBIL
# =============================
COUNTRIES = ["sg", "my"]

HEADERS = {
    "User-Agent": "Mozilla/5.0"
}

# =============================
#  SCRAPE KEY DARI v2nodes
# =============================
def get_key(country):
    url = f"https://www.v2nodes.com/country/{country}/"
    try:
        r = requests.get(url, headers=HEADERS, timeout=10)
        soup = BeautifulSoup(r.text, "html.parser")
        inp = soup.find("input", id="subscription")
        if not inp:
            return None

        sub_url = inp.get("value")
        parsed = urlparse(sub_url)
        return parse_qs(parsed.query).get("key", [None])[0]
    except Exception as e:
        print(f"[!] Gagal ambil key {country}:", e)
        return None


# =============================
#  BUILD URL SUBSCRIPTION
# =============================
def build_urls():
    urls = []
    for c in COUNTRIES:
        key = get_key(c)
        if key:
            sub = f"https://www.v2nodes.com/subscriptions/country/{c}/?key={key}"
            urls.append(sub)
            print(f"[+] {c.upper()} key: {key}")
    return urls


# =============================
#  PORT YANG DIPERBOLEHKAN (WS)
# =============================
ALLOWED_PORTS = {
    80, 8080, 8880, 2052, 2082, 2086, 2095,
    443, 8443, 2053, 2083, 2087, 2096
}

# =============================
#  NEGARA ASIA
# =============================
ASIA_CODES = [
    "SG","MY","ID","JP","KR","HK","TW","TH",
    "VN","PH","IN","BD","CN"
]

def is_asia(name):
    up = name.upper()
    return any(f"-{c}-" in up or f" {c}" in up for c in ASIA_CODES)

# =============================
#  CHECK SERVER HIDUP
# =============================
def check_alive(host):
    try:
        requests.head(f"https://{host}", timeout=3)
        return True
    except:
        return False


# =============================
#  FETCH & DECODE
# =============================
def fetch_subscription(url):
    print(f"[*] Fetching: {url}")
    try:
        r = requests.get(url, timeout=10)
        r.raise_for_status()
        return r.text.strip()
    except:
        return ""

def decode_subscription(data):
    try:
        return base64.b64decode(data).decode()
    except:
        return data

def parse_nodes(text):
    return [l.strip() for l in text.splitlines() if l.strip()]

def clean_name(name):
    return name.replace("[www.v2nodes.com]", "").strip()


# =============================
#  PARSER VMESS
# =============================
def parse_vmess(uri):
    try:
        js = json.loads(base64.b64decode(uri[8:]).decode())
    except:
        return None

    port = int(js.get("port", 0))
    host = js.get("host", "")
    if js.get("net") != "ws" or port not in ALLOWED_PORTS or not check_alive(host):
        return None

    return {
        "name": clean_name(js.get("ps", "vmess")),
        "type": "vmess",
        "server": "bug.xcp",
        "port": port,
        "uuid": js["id"],
        "alterId": int(js.get("aid", 0)),
        "cipher": "auto",
        "tls": js.get("tls") == "tls",
        "network": "ws",
        "udp": True,
        "ws-opts": {
            "path": js.get("path", "/"),
            "headers": {"Host": host}
        },
        "servername": host
    }


# =============================
#  PARSER VLESS
# =============================
def parse_vless(uri):
    u = urlparse(uri.replace("&amp;", "&"))
    q = parse_qs(u.query)
    host = q.get("host", [""])[0]
    port = int(u.port)

    if q.get("type", ["tcp"])[0] != "ws" or port not in ALLOWED_PORTS or not check_alive(host):
        return None

    return {
        "name": clean_name(u.fragment),
        "type": "vless",
        "server": "bug.xcp",
        "port": port,
        "uuid": u.username,
        "network": "ws",
        "tls": q.get("security", ["none"])[0] == "tls",
        "udp": True,
        "ws-opts": {
            "path": q.get("path", [""])[0],
            "headers": {"Host": host}
        }
    }


# =============================
#  PARSER TROJAN
# =============================
def parse_trojan(uri):
    u = urlparse(uri.replace("&amp;", "&"))
    q = parse_qs(u.query)
    host = q.get("host", [""])[0]
    port = int(u.port)

    if q.get("type", ["tcp"])[0] != "ws" or port not in ALLOWED_PORTS or not check_alive(host):
        return None

    return {
        "name": clean_name(u.fragment),
        "type": "trojan",
        "server": "bug.xcp",
        "port": port,
        "password": u.username,
        "udp": True,
        "ws-opts": {
            "path": q.get("path", [""])[0],
            "headers": {"Host": host}
        }
    }


# =============================
#  BUILD PROXIES
# =============================
def build_proxies(nodes):
    proxies = []
    for n in nodes:
        p = None
        if n.startswith("vmess://"):
            p = parse_vmess(n)
        elif n.startswith("vless://"):
            p = parse_vless(n)
        elif n.startswith("trojan://"):
            p = parse_trojan(n)

        if p and is_asia(p["name"]):
            proxies.append(p)

    return {"proxies": proxies}


def save_yaml(data, file="jomblo.yaml"):
    with open(file, "w", encoding="utf-8") as f:
        yaml.dump(data, f, allow_unicode=True, sort_keys=False)
    print("[✓] Saved:", file)


# =============================
#  MAIN
# =============================
def main():
    URLS = build_urls()
    all_nodes = []

    for u in URLS:
        raw = fetch_subscription(u)
        decoded = decode_subscription(raw)
        all_nodes.extend(parse_nodes(decoded))

    print("[*] Total node:", len(all_nodes))
    save_yaml(build_proxies(all_nodes))


if __name__ == "__main__":
    main()
