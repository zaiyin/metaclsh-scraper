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
    # Tambah URL lagi di sini:
    # "https://example.com/sub1",
    # "https://example.com/sub2",
]


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


# ---------------- CLEAN NAME ---------------- #
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

    if js.get("net") != "ws":
        return None
    if str(js.get("port")) != "443":
        return None

    proxy = {
        "name": clean_name(js.get("ps", "vmess-node")),
        "type": "vmess",
        "server": "bug.xcp",
        "port": 443,
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

    if q.get("type", ["tcp"])[0] != "ws":
        return None
    if int(u.port) != 443:
        return None

    proxy = {
        "name": clean_name(u.fragment or "vless-node"),
        "type": "vless",
        "server": "bug.xcp",
        "port": 443,
        "uuid": u.username,
        "network": "ws",
        "tls": q.get("security", ["none"])[0] == "tls",
        "udp": True,
    }

    if "sni" in q:
        proxy["sni"] = q["sni"][0]

    proxy["ws-opts"] = {
        "path": q.get("path", [""])[0],
        "headers": {"Host": q.get("host", [""])[0]}
    }

    return proxy


# ---------------- PARSER TROJAN ---------------- #
def parse_trojan(uri):
    uri = uri.replace("&amp;", "&")
    u = urlparse(uri)
    q = parse_qs(u.query)

    if q.get("type", ["tcp"])[0] != "ws":
        return None
    if int(u.port) != 443:
        return None

    proxy = {
        "name": clean_name(u.fragment or "trojan-node"),
        "type": "trojan",
        "udp": True,
        "server": "bug.xcp",
        "port": 443,
        "password": u.username
    }

    if "sni" in q:
        proxy["sni"] = q["sni"][0]

    proxy["ws-opts"] = {
        "path": q.get("path", [""])[0],
        "headers": {"Host": q.get("host", [""])[0]}
    }

    return proxy


# ---------------- PARSER SS → SKIP ---------------- #
def parse_ss(uri):
    return None


# ---------------- BUILD PROXIES ---------------- #
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
            elif n.startswith("ss://"):
                proxy = parse_ss(n)

            if proxy:
                proxies.append(proxy)

        except Exception as e:
            print("Parsing gagal:", e)
            print("Node bermasalah:", n)

    return {"proxies": proxies}


# ---------------- SAVE YAML ---------------- #
def save_yaml(data, filename="jomblo.yaml"):
    with open(filename, "w", encoding="utf-8") as f:
        yaml.dump(data, f, sort_keys=False, allow_unicode=True)

    print("[*] File saved:", filename)


# ---------------- MAIN ---------------- #
def main():

    all_nodes = []

    # fetch semua URL subscription
    for url in URLS:
        raw = fetch_subscription(url)
        decoded = decode_subscription(raw)
        nodes = parse_nodes(decoded)
        all_nodes.extend(nodes)

    print(f"[*] Total node yang terkumpul: {len(all_nodes)}")

    result = build_proxies(all_nodes)
    save_yaml(result)


if __name__ == "__main__":
    main()
