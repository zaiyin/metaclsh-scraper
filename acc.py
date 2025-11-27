import base64
import yaml
import requests
from urllib.parse import urlparse, parse_qs
import json

# ============================================
# GANTI URL SUBSCRIPTION DI SINI
# ============================================
URL = "https://www.v2nodes.com/subscriptions/country/sg/?key=6FD0D31FB086C7C"


# --------------------------------------------
# FETCH SUBSCRIPTION
# --------------------------------------------
def fetch_subscription(url):
    print("[*] Fetching subscription…")
    resp = requests.get(url, timeout=10)
    resp.raise_for_status()
    return resp.text.strip()


# --------------------------------------------
# DECODE SUBSCRIPTION (jika base64)
# --------------------------------------------
def decode_subscription(data):
    try:
        return base64.b64decode(data).decode("utf-8")
    except:
        return data


def parse_nodes(text):
    return [l.strip() for l in text.splitlines() if l.strip()]


# ---------------------------------------------------------
# CLEAN NAME
# ---------------------------------------------------------
def clean_name(name):
    name = name.replace("[www.v2nodes.com]", "DP")
    return name.strip()


# --------------------------------------------
# PARSER VMESS
# --------------------------------------------
def parse_vmess(uri):
    raw = uri.replace("vmess://", "")
    decoded = base64.b64decode(raw).decode("utf-8")
    js = json.loads(decoded)

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


# --------------------------------------------
# PARSER VLESS
# --------------------------------------------
def parse_vless(uri):
    u = urlparse(uri)
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


# --------------------------------------------
# PARSER TROJAN
# --------------------------------------------
def parse_trojan(uri):
    u = urlparse(uri)
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


# --------------------------------------------
# PARSER SHADOWSOCKS (SS)
# --------------------------------------------
def parse_ss(uri):
    try:
        uri = uri.strip()
        raw = uri[5:]

        if "#" in raw:
            raw, name = raw.split("#", 1)
        else:
            name = "ss-node"

        # CASE 1: base64@host
        if "@" in raw:
            left, host_port = raw.split("@", 1)

            # coba decode
            try:
                decoded = base64.b64decode(left).decode()
                cipher, password = decoded.split(":", 1)
            except:
                cipher, password = left.split(":", 1)

            host, port = host_port.split(":", 1)

        # CASE 2: full base64
        else:
            decoded = base64.b64decode(raw).decode()
            cipher, rest = decoded.split(":", 1)
            password, host_port = rest.split("@", 1)
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

    except Exception as e:
        raise ValueError(f"Error parse SS: {str(e)}")


# --------------------------------------------
# BUILD PROXIES LIST
# --------------------------------------------
def build_proxies(nodes):
    proxies = []

    for n in nodes:
        try:
            if n.startswith("vmess://"):
                proxies.append(parse_vmess(n))
            elif n.startswith("vless://"):
                proxies.append(parse_vless(n))
            elif n.startswith("trojan://"):
                proxies.append(parse_trojan(n))
            elif n.startswith("ss://"):
                proxies.append(parse_ss(n))

        except Exception as e:
            print("Parsing gagal:", e)
            print("Node bermasalah:", n)

    return {"proxies": proxies}


# --------------------------------------------
# SAVE YAML TANPA JARAK ANTAR ITEM
# --------------------------------------------
def save_yaml(data, filename="dialer-proxy.yaml"):
    with open(filename, "w", encoding="utf-8") as f:
        yaml.dump(
            data,
            f,
            allow_unicode=True,
            sort_keys=False
        )
    print("[*] File saved:", filename)


# --------------------------------------------
# MAIN
# --------------------------------------------
def main():
    raw = fetch_subscription(URL)
    decoded = decode_subscription(raw)
    nodes = parse_nodes(decoded)
    result = build_proxies(nodes)
    save_yaml(result)


if __name__ == "__main__":
    main()
