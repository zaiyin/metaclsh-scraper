import base64
import yaml
import requests
from urllib.parse import urlparse, parse_qs
import json


# ======================================================
# LIST SUBSCRIPTION (boleh lebih dari 1)
# ======================================================
URLS = [
    "https://www.v2nodes.com/subscriptions/country/sg/?key=AADB0E71BD506FF",
    # Tambah lagi jika mau:
    # "https://example.com/sub2",
]


# ======================================================
# SETTING FILTER
# ======================================================
REPLACE_SERVER = "bug.xcp"     # server override
FILTER_WS_ONLY = False         # True = hanya WS
FILTER_PORT_443 = False        # True = hanya port 443


# ======================================================
# FETCH SUBSCRIPTION
# ======================================================
def fetch_subscription(url):
    print(f"[*] Fetching: {url}")
    resp = requests.get(url, timeout=15)
    resp.raise_for_status()
    return resp.text.strip()


# ======================================================
# DECODE BASE64 JIKA PERLU
# ======================================================
def decode_subscription(data):
    try:
        return base64.b64decode(data).decode("utf-8")
    except:
        return data


def parse_nodes(text):
    return [l.strip() for l in text.splitlines() if l.strip()]


# ======================================================
# CLEAN NAME
# ======================================================
def clean_name(name):
    return name.replace("[www.v2nodes.com]", "").strip()


# ======================================================
# PARSER VMESS
# ======================================================
def parse_vmess(uri):
    raw = uri.replace("vmess://", "")
    decoded = base64.b64decode(raw).decode("utf-8")
    js = json.loads(decoded)

    net = js.get("net", "tcp")
    port = int(js.get("port", 0))

    if FILTER_WS_ONLY and net != "ws":
        return None
    if FILTER_PORT_443 and port != 443:
        return None

    proxy = {
        "name": clean_name(js.get("ps", "vmess")),
        "type": "vmess",
        "server": REPLACE_SERVER,
        "port": port,
        "uuid": js.get("id"),
        "alterId": int(js.get("aid", 0)),
        "cipher": "auto",
        "tls": js.get("tls", "") == "tls",
        "udp": True,
        "network": net,
    }

    if net == "ws":
        proxy["ws-opts"] = {
            "path": js.get("path", "/"),
            "headers": {"Host": js.get("host", "")}
        }

    if js.get("host"):
        proxy["servername"] = js.get("host")

    return proxy


# ======================================================
# PARSER VLESS
# ======================================================
def parse_vless(uri):
    uri = uri.replace("&amp;", "&")
    u = urlparse(uri)
    q = parse_qs(u.query)

    net = q.get("type", ["tcp"])[0]
    port = int(u.port)

    if FILTER_WS_ONLY and net != "ws":
        return None
    if FILTER_PORT_443 and port != 443:
        return None

    proxy = {
        "name": clean_name(u.fragment or "vless"),
        "type": "vless",
        "server": REPLACE_SERVER,
        "port": port,
        "uuid": u.username,
        "network": net,
        "tls": q.get("security", ["none"])[0] == "tls",
        "udp": True,
    }

    if "sni" in q:
        proxy["sni"] = q["sni"][0]

    if net == "ws":
        proxy["ws-opts"] = {
            "path": q.get("path", [""])[0],
            "headers": {"Host": q.get("host", [""])[0]}
        }

    return proxy


# ======================================================
# PARSER TROJAN
# ======================================================
def parse_trojan(uri):
    u = urlparse(uri)
    q = parse_qs(u.query)

    port = int(u.port)
    net = q.get("type", ["tcp"])[0]

    if FILTER_WS_ONLY and net != "ws":
        return None
    if FILTER_PORT_443 and port != 443:
        return None

    proxy = {
        "name": clean_name(u.fragment or "trojan"),
        "type": "trojan",
        "server": REPLACE_SERVER,
        "port": port,
        "password": u.username,
        "udp": True,
    }

    if "sni" in q:
        proxy["sni"] = q["sni"][0]

    if net == "ws":
        proxy["network"] = "ws"
        proxy["ws-opts"] = {
            "path": q.get("path", [""])[0],
            "headers": {"Host": q.get("host", [""])[0]}
        }

    return proxy


# ======================================================
# PARSER SS
# ======================================================
def parse_ss(uri):
    try:
        uri = uri.strip()
        raw = uri[5:]

        if "#" in raw:
            raw, name = raw.split("#", 1)
        else:
            name = "ss-node"

        if "@" in raw:
            left, host_port = raw.split("@", 1)
            try:
                decoded = base64.b64decode(left).decode()
                cipher, password = decoded.split(":", 1)
            except:
                cipher, password = left.split(":", 1)
            host, port = host_port.split(":", 1)
        else:
            decoded = base64.b64decode(raw).decode()
            cipher, rest = decoded.split(":", 1)
            password, host_port = rest.split("@", 1)
            host, port = host_port.split(":", 1)

        return {
            "name": clean_name(name),
            "type": "ss",
            "cipher": cipher,
            "password": password,
            "server": REPLACE_SERVER,
            "port": int(port),
            "udp": True
        }

    except Exception:
        return None


# ======================================================
# BUILD PROXIES
# ======================================================
def build_proxies(nodes):
    proxies = []

    for n in nodes:
        try:
            if n.startswith("vmess://"):
                p = parse_vmess(n)
            elif n.startswith("vless://"):
                p = parse_vless(n)
            elif n.startswith("trojan://"):
                p = parse_trojan(n)
            elif n.startswith("ss://"):
                p = parse_ss(n)
            else:
                p = None

            if p:
                proxies.append(p)

        except Exception as e:
            print("Error:", e)
            print("Node:", n)

    return {"proxies": proxies}


# ======================================================
# SAVE YAML
# ======================================================
def save_yaml(data, filename="dialer-proxy.yaml"):
    with open(filename, "w", encoding="utf-8") as f:
        yaml.dump(data, f, allow_unicode=True, sort_keys=False)
    print("[*] Saved:", filename)


# ======================================================
# MAIN
# ======================================================
def main():
    all_nodes = []

    for url in URLS:
        raw = fetch_subscription(url)
        decoded = decode_subscription(raw)
        all_nodes.extend(parse_nodes(decoded))

    result = build_proxies(all_nodes)
    save_yaml(result)


if __name__ == "__main__":
    main()
