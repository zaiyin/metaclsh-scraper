import base64
import yaml
import requests
from urllib.parse import urlparse, parse_qs
import json
from bs4 import BeautifulSoup

# ============================================
# COUNTRY LIST
# ============================================
COUNTRY = ["sg", "my", "jp"]
HEADERS = {"User-Agent": "Mozilla/5.0"}

# ============================================
# AUTO AMBIL SUBSCRIPTION URL
# ============================================
def get_subscription_url(country):
    url = f"https://www.v2nodes.com/country/{country}/"
    r = requests.get(url, headers=HEADERS, timeout=10)
    r.raise_for_status()

    soup = BeautifulSoup(r.text, "html.parser")
    inp = soup.find("input", id="subscription")
    if not inp:
        raise RuntimeError("subscription input tidak ditemukan")

    return inp.get("value")


# ============================================
# FETCH & DECODE
# ============================================
def fetch_subscription(url):
    print("[*] Fetching subscription…")
    r = requests.get(url, timeout=10)
    r.raise_for_status()
    return r.text.strip()


def decode_subscription(data):
    try:
        return base64.b64decode(data).decode("utf-8")
    except:
        return data


def parse_nodes(text):
    return [l.strip() for l in text.splitlines() if l.strip()]


# ============================================
# CLEAN NAME
# ============================================
def clean_name(name):
    return name.replace("[www.v2nodes.com]", "DP").strip()


# ============================================
# PARSER VMESS
# ============================================
def parse_vmess(uri):
    js = json.loads(base64.b64decode(uri[8:]).decode())

    proxy = {
        "name": clean_name(js.get("ps", "vmess-node")),
        "dialer-proxy": "LBCF",
        "type": "vmess",
        "server": js["add"],
        "port": int(js["port"]),
        "uuid": js["id"],
        "alterId": int(js.get("aid", 0)),
        "cipher": "auto",
        "tls": js.get("tls", "") == "tls",
        "udp": True,
        "network": js.get("net", "tcp")
    }

    if js.get("net") == "ws":
        proxy["ws-opts"] = {
            "path": js.get("path", "/"),
            "headers": {"Host": js.get("host", "")}
        }

    if js.get("host"):
        proxy["servername"] = js.get("host")

    return proxy


# ============================================
# PARSER VLESS
# ============================================
def parse_vless(uri):
    u = urlparse(uri.replace("&amp;", "&"))
    q = parse_qs(u.query)

    proxy = {
        "name": clean_name(u.fragment or "vless-node"),
        "dialer-proxy": "LBCF",
        "type": "vless",
        "server": u.hostname,
        "port": int(u.port),
        "uuid": u.username,
        "udp": True,
        "network": q.get("type", ["tcp"])[0],
        "tls": q.get("security", ["none"])[0] == "tls",
    }

    if "sni" in q:
        proxy["sni"] = q["sni"][0]

    if proxy["network"] == "ws":
        proxy["ws-opts"] = {
            "path": q.get("path", [""])[0],
            "headers": {"Host": q.get("host", [""])[0]}
        }

    return proxy


# ============================================
# PARSER TROJAN
# ============================================
def parse_trojan(uri):
    u = urlparse(uri.replace("&amp;", "&"))
    q = parse_qs(u.query)

    proxy = {
        "name": clean_name(u.fragment or "trojan-node"),
        "dialer-proxy": "LBCF",
        "type": "trojan",
        "server": u.hostname,
        "port": int(u.port),
        "password": u.username,
        "udp": True,
    }

    if "sni" in q:
        proxy["sni"] = q["sni"][0]

    return proxy


# ============================================
# PARSER SHADOWSOCKS (AMAN)
# ============================================
def parse_ss(uri):
    try:
        raw = uri[5:]
        name = "ss-node"

        if "#" in raw:
            raw, name = raw.split("#", 1)

        # buang plugin
        raw = raw.split("?", 1)[0]

        if "@" not in raw:
            decoded = base64.b64decode(raw).decode()
            if "@" not in decoded:
                return None
            cipher, rest = decoded.split(":", 1)
            password, host_port = rest.split("@", 1)
        else:
            left, host_port = raw.split("@", 1)
            try:
                decoded = base64.b64decode(left).decode()
                cipher, password = decoded.split(":", 1)
            except:
                cipher, password = left.split(":", 1)

        if ":" not in host_port:
            return None

        host, port = host_port.split(":", 1)

        return {
            "name": clean_name(name),
            "dialer-proxy": "LBCF",
            "type": "ss",
            "udp": True,
            "cipher": cipher,
            "password": password,
            "server": host,
            "port": int(port)
        }

    except:
        return None


# ============================================
# BUILD PROXIES
# ============================================
def build_proxies(nodes):
    proxies = []

    for n in nodes:
        try:
            p = None
            if n.startswith("vmess://"):
                p = parse_vmess(n)
            elif n.startswith("vless://"):
                p = parse_vless(n)
            elif n.startswith("trojan://"):
                p = parse_trojan(n)
            elif n.startswith("ss://"):
                p = parse_ss(n)

            if p:
                proxies.append(p)

        except Exception as e:
            print("Parsing gagal:", e)

    return {"proxies": proxies}


# ============================================
# SAVE YAML
# ============================================
def save_yaml(data, filename="dialer-proxy.yaml"):
    with open(filename, "w", encoding="utf-8") as f:
        yaml.dump(data, f, allow_unicode=True, sort_keys=False)
    print("[*] File saved:", filename)


# ============================================
# MAIN
# ============================================
def main():
    all_nodes = []

    for c in COUNTRY:
        try:
            sub_url = get_subscription_url(c)
            print(f"[+] {c.upper()} Subscription:", sub_url)

            raw = fetch_subscription(sub_url)
            decoded = decode_subscription(raw)
            nodes = parse_nodes(decoded)

            all_nodes.extend(nodes)

        except Exception as e:
            print(f"[!] Gagal {c.upper()}:", e)

    save_yaml(build_proxies(all_nodes))


if __name__ == "__main__":
    main()
