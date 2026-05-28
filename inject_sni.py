import requests
import base64
import json
import socket
import concurrent.futures
import re
from urllib.parse import urlparse, parse_qs, urlunparse, urlencode

# ================= KONFIGURASI =================
URL_SUMBER = "https://raw.githubusercontent.com/ebrasha/free-v2ray-public-list/refs/heads/main/V2Ray-Config-By-EbraSha-All-Type.txt"
BUG_DOMAIN = "support.zoom.us"
OUTPUT_FILE = "akun_wildcard_aktif.txt"
MAX_THREADS = 30 # Kecepatan cek (semakin tinggi semakin cepat, tapi butuh CPU/Network stabil)
# ===============================================

def is_wildcard_active(domain):
    """Mengecek apakah domain kombinasi bisa di-resolve ke IP (Aktif)."""
    try:
        # PING (DNS Resolve) cepat
        socket.gethostbyname(domain)
        return True
    except socket.error:
        return False

def decode_base64(data):
    """Fungsi aman untuk decode base64 standar maupun urlsafe"""
    data = data.replace('-', '+').replace('_', '/')
    missing_padding = len(data) % 4
    if missing_padding:
        data += '=' * (4 - missing_padding)
    return base64.b64decode(data).decode('utf-8', errors='ignore')

def modify_url_hostname(parsed, new_hostname):
    """Fungsi helper untuk mengganti hostname pada URL tanpa merusak port/user"""
    netloc = new_hostname
    if parsed.port:
        netloc = f"{netloc}:{parsed.port}"
    if parsed.username:
        auth = parsed.username
        if parsed.password:
            auth += f":{parsed.password}"
        netloc = f"{auth}@{netloc}"
    return parsed._replace(netloc=netloc)

def process_vmess(link):
    try:
        b64_data = link[8:]
        data = json.loads(decode_base64(b64_data))

        orig_sni = data.get('sni') or data.get('host') or data.get('add')
        if not orig_sni: return None

        combined_domain = f"{BUG_DOMAIN}.{orig_sni}"
        if not is_wildcard_active(combined_domain): return None

        # Modifikasi VMESS
        data['add'] = combined_domain
        data['sni'] = combined_domain
        if 'host' in data and data['host']:
            data['host'] = combined_domain
        data['ps'] = f"[Wildcard] {data.get('ps', 'VMess')}"

        new_b64 = base64.b64encode(json.dumps(data).encode('utf-8')).decode('utf-8')
        return "vmess://" + new_b64
    except Exception:
        return None

def process_url_based(link, protocol):
    """Untuk Vless, Trojan, Hysteria2 (hy2), dan TUIC"""
    try:
        parsed = urlparse(link)
        qs = parse_qs(parsed.query)

        orig_sni = qs.get('sni', [parsed.hostname])[0]
        if not orig_sni: return None

        combined_domain = f"{BUG_DOMAIN}.{orig_sni}"
        if not is_wildcard_active(combined_domain): return None

        # Ubah SNI & Host
        qs['sni'] = [combined_domain]
        if 'host' in qs: qs['host'] = [combined_domain]
        
        # Hysteria/Tuic kadang menyimpan obfs/sni di field lain
        if 'obfs-host' in qs: qs['obfs-host'] = [combined_domain]

        # Ubah address server menjadi wildcard domain juga
        parsed = modify_url_hostname(parsed, combined_domain)

        new_query = urlencode(qs, doseq=True)
        new_fragment = f"[Wildcard] {parsed.fragment}" if parsed.fragment else f"[{protocol.upper()}] Wildcard"
        
        new_parsed = parsed._replace(query=new_query, fragment=new_fragment)
        return urlunparse(new_parsed)
    except Exception:
        return None

def process_ss(link):
    """Menangani Shadowsocks (ss://)"""
    try:
        fragment = link.split('#')[1] if '#' in link else "SS"
        main_part = link.split('#')[0][5:]
        
        # Jika tidak ada '@', berarti user:pass@host di-encode secara penuh
        if '@' not in main_part:
            parts = main_part.split('/?')
            main_part = decode_base64(parts[0])
            if len(parts) > 1:
                main_part += f"/?{parts[1]}"
                
        parsed = urlparse("ss://" + main_part)
        qs = parse_qs(parsed.query)
        orig_host = parsed.hostname

        # Ekstrak plugin host (misal: obfs-host=domain.com)
        plugin_str = qs.get('plugin', [''])[0]
        plugin_host = None
        if plugin_str:
            m = re.search(r'(obfs-host|host)=([^;]+)', plugin_str)
            if m: plugin_host = m.group(2)
        
        target_domain = plugin_host if plugin_host else orig_host
        if not target_domain: return None
        
        combined_domain = f"{BUG_DOMAIN}.{target_domain}"
        if not is_wildcard_active(combined_domain): return None
        
        # Ubah Host di plugin
        if plugin_str and plugin_host:
            new_plugin = re.sub(r'((?:obfs-host|host)=)[^;]+', r'\g<1>' + combined_domain, plugin_str)
            qs['plugin'] = [new_plugin]
            
        parsed = modify_url_hostname(parsed, combined_domain)
        new_query = urlencode(qs, doseq=True)
        
        # Encode balik userinfo ke base64 agar standar SIP002 tetap jalan (untuk Verge/v2rayN)
        if parsed.username:
            userinfo = f"{parsed.username}:{parsed.password}" if parsed.password else parsed.username
            b64_userinfo = base64.urlsafe_b64encode(userinfo.encode('utf-8')).decode('utf-8').rstrip('=')
            netloc = f"{b64_userinfo}@{parsed.hostname}"
            if parsed.port: netloc += f":{parsed.port}"
            parsed = parsed._replace(netloc=netloc)

        parsed = parsed._replace(query=new_query, fragment=f"[Wildcard] {fragment}")
        return urlunparse(parsed)
    except Exception:
        return None

def process_ssr(link):
    """Menangani ShadowsocksR (ssr://)"""
    try:
        b64_part = link[6:]
        decoded = decode_base64(b64_part)
        
        parts = decoded.split('/?')
        main_part = parts[0]
        query_part = parts[1] if len(parts) > 1 else ""
        
        main_split = main_part.split(':')
        if len(main_split) < 6: return None
        
        host = main_split[0]
        qs = parse_qs(query_part)
        
        # Ekstrak obfsparam (sebagai SNI/Host pada SSR)
        obfsparam_b64 = qs.get('obfsparam', [''])[0]
        obfsparam = decode_base64(obfsparam_b64) if obfsparam_b64 else ""
        
        target_domain = obfsparam if obfsparam else host
        if not target_domain: return None
        
        combined_domain = f"{BUG_DOMAIN}.{target_domain}"
        if not is_wildcard_active(combined_domain): return None
        
        # Terapkan wildcard
        main_split[0] = combined_domain
        if obfsparam:
            qs['obfsparam'] = [base64.urlsafe_b64encode(combined_domain.encode('utf-8')).decode('utf-8').rstrip('=')]
            
        # Remarks (Nama Akun)
        remarks_b64 = qs.get('remarks', [''])[0]
        if remarks_b64:
            remarks = decode_base64(remarks_b64)
            qs['remarks'] = [base64.urlsafe_b64encode(f"[Wildcard] {remarks}".encode('utf-8')).decode('utf-8').rstrip('=')]

        new_main = ":".join(main_split)
        new_query = urlencode(qs, doseq=True)
        new_decoded = f"{new_main}/?{new_query}"
        
        new_b64 = base64.urlsafe_b64encode(new_decoded.encode('utf-8')).decode('utf-8').rstrip('=')
        return "ssr://" + new_b64
    except Exception:
        return None

def process_single_link(line):
    """Distributor fungsi berdasarkan jenis protokol"""
    line = line.strip()
    if not line: return None
    
    if line.startswith("vmess://"):
        return process_vmess(line)
    elif line.startswith(("vless://", "trojan://", "hy2://", "hysteria2://", "tuic://")):
        protocol = line.split("://")[0]
        return process_url_based(line, protocol)
    elif line.startswith("ss://"):
        return process_ss(line)
    elif line.startswith("ssr://"):
        return process_ssr(line)
    
    return None

def main():
    print(f"Mengunduh akun dari Github...")
    try:
        response = requests.get(URL_SUMBER, timeout=15)
        response.raise_for_status()
    except Exception as e:
        print(f"Gagal mengunduh: {e}")
        return

    lines = response.text.splitlines()
    print(f"Berhasil mengunduh {len(lines)} akun.")
    print(f"Mengecek ping wildcard {BUG_DOMAIN} (VMess, Vless, Trojan, Hy2, Tuic, SS, SSR)...")
    print(f"Menggunakan {MAX_THREADS} Threads agar cepat. Harap tunggu...\n")

    valid_links = []
    
    with concurrent.futures.ThreadPoolExecutor(max_workers=MAX_THREADS) as executor:
        results = executor.map(process_single_link, lines)
        
        for res in results:
            if res:
                valid_links.append(res)

    print(f"\n--- SELESAI ---")
    print(f"Total akun yang CONNECT via Wildcard: {len(valid_links)} dari {len(lines)} akun.")

    if valid_links:
        with open(OUTPUT_FILE, "w", encoding="utf-8") as f:
            for link in valid_links:
                f.write(link + "\n")
        print(f"✅ Akun sukses disimpan ke: '{OUTPUT_FILE}'")
    else:
        print("❌ Tidak ada akun yang mendukung wildcard dns dari daftar tersebut.")

if __name__ == "__main__":
    main()
