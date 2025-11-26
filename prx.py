import base64
import yaml
import requests
from urllib.parse import urlparse, parse_qs
import json

# =============================
#  DAFTAR URL SUBSCRIPTION
# =============================
URLS = [
    "https://www.v2nodes.com/subscriptions/country/my/?key=AADB0E71BD506FF",
    "https://www.v2nodes.com/subscriptions/country/sg/?key=AADB0E71BD506FF",
]

# =============================
#  PORT YANG DIPERBOLEHKAN
# =============================
ALLOWED_PORTS = {
    80, 8080, 8880, 2052, 2082, 2086, 2095,
    443, 8443, 2053, 2083, 2087, 2096
}


def fetch_subscription(url):
    print(f"[*] Fetching: {url}")
    try:
        resp = requests.get(url, timeout=10)
        resp.raise_for_status()
        return resp.text.strip()
    except Exception as e:
        print(f"[!] Gagal fetch {url} → {e}")
        return ""


def decode_subscription(data):
    try:
        return base64.b64decode(data).decode("utf-8")
    except:
        return data


def parse_nodes(text):
    return [l.strip() for l in text.splitlines() if l.strip()]


def clean_name(name):
    return name.replace("[www.v2nodes.com]", "").strip()


# ---------------- PARSER VMESS ---------------- #
def parse_vmess(uri):
    try:
        raw = uri.replace("vmess://", "")
        data = base64.b64decode(raw).decode("utf-8")
        js = json.loads(data)
    except:
        return None

    net = js.get("net", "tcp")
    port = int(js.get("port", 0))

    if net != "ws":
        return None
    if port not in ALLOWED_PORTS:
        return None

    proxy = {
        "name": clean_name(js.get("ps", "vmess-node")),
        "type": "vmess",
        "server": "bug.xcp",
        "port": port,
        "uuid": js["id"],
        "alterId": int(js.get("aid", 0)),
        "cipher": "auto",
        "tls": js.get("tls", "") == "tls",
        "network": "ws",
        "udp": True,
        "ws-opts": {
            "path": js.get("path", "/"),
            "headers": {"Host": js.get("host", "")}
        }
    }

    if js.get("host"):
        proxy["servername"] = js.get("host")

    return proxy


# ---------------- PARSER VLESS ---------------- #
def parse_vless(uri):
    uri = uri.replace("&amp;", "&")
    u = urlparse(uri)
    q = parse_qs(u.query)

    net = q.get("type", ["tcp"])[0]
    port = int(u.port)

    if net != "ws":
        return None
    if port not in ALLOWED_PORTS:
        return None

    proxy = {
        "name": clean_name(u.fragment or "vless-node"),
        "type": "vless",
        "server": "bug.xcp",
        "port": port,
        "uuid": u.username,
        "network": "ws",
        "tls": q.get("security", ["none"])[0] == "tls",
        "udp": True,
        "ws-opts": {
            "path": q.get("path", [""])[0],
            "headers": {"Host": q.get("host", [""])[0]}
        }
    }

    if "sni" in q:
        proxy["sni"] = q["sni"][0]

    return proxy


# ---------------- PARSER TROJAN ---------------- #
def parse_trojan(uri):
    uri = uri.replace("&amp;", "&")
    u = urlparse(uri)
    q = parse_qs(u.query)

    net = q.get("type", ["tcp"])[0]
    port = int(u.port)

    if net != "ws":
        return None
    if port not in ALLOWED_PORTS:
        return None

    proxy = {
        "name": clean_name(u.fragment or "trojan-node"),
        "type": "trojan",
        "server": "bug.xcp",
        "port": port,
        "password": u.username,
        "udp": True,
        "ws-opts": {
            "path": q.get("path", [""])[0],
            "headers": {"Host": q.get("host", [""])[0]}
        }
    }

    if "sni" in q:
        proxy["sni"] = q["sni"][0]

    return proxy


def parse_ss(uri):
    return None


def build_proxies(nodes):
    proxies = []

    for n in nodes:
        try:
            proxy = None

            if n.startswith("vmess://"):
                proxy = parse_vmess(n)
            elif n.startswith("vless://"):
                proxy = parse_vless(n)
            elif n.startswith("trojan://"):
                proxy = parse_trojan(n)

            if proxy:
                proxies.append(proxy)

        except Exception as e:
            print("Parsing gagal:", e)
            print("Node bermasalah:", n)

    return {"proxies": proxies}


def save_yaml(data, filename="jomblo.yaml"):
    with open(filename, "w", encoding="utf-8") as f:
        yaml.dump(data, f, sort_keys=False, allow_unicode=True)

    print("[*] File saved:", filename)


def main():

    all_nodes = []

    for url in URLS:
        raw = fetch_subscription(url)
        decoded = decode_subscription(raw)
        nodes = parse_nodes(decoded)
        all_nodes.extend(nodes)

    print(f"[*] Total node terkumpul: {len(all_nodes)}")

    result = build_proxies(all_nodes)
    save_yaml(result)


if __name__ == "__main__":
    main()
