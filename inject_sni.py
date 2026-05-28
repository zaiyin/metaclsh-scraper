import requests
import base64
import json
import socket
import concurrent.futures
from urllib.parse import urlparse, parse_qs, urlunparse, urlencode

# ================= KONFIGURASI =================
URL_SUMBER = "https://raw.githubusercontent.com/ebrasha/free-v2ray-public-list/refs/heads/main/V2Ray-Config-By-EbraSha-All-Type.txt"
BUG_DOMAIN = "support.zoom.us"
OUTPUT_FILE = "akun_wildcard_aktif.txt"
MAX_THREADS = 20 # Jumlah proses bersamaan agar ping cepat
# ===============================================

def is_wildcard_active(domain):
    """
    Mengecek apakah domain kombinasi bisa di-ping/di-resolve.
    Menggunakan socket.gethostbyname karena lebih cepat & cross-platform dibanding command 'ping'.
    """
    try:
        # Jika berhasil mendapat IP, berarti Wildcard DNS aktif
        ip = socket.gethostbyname(domain)
        return True
    except socket.error:
        # Jika gagal resolve (Host not found), berarti tidak support wildcard
        return False

def decode_base64(data):
    missing_padding = len(data) % 4
    if missing_padding:
        data += '=' * (4 - missing_padding)
    return base64.b64decode(data).decode('utf-8', errors='ignore')

def process_vmess(link):
    try:
        b64_data = link[8:]
        json_str = decode_base64(b64_data)
        data = json.loads(json_str)

        orig_sni = data.get('sni') or data.get('host') or data.get('add')
        
        if not orig_sni:
            return None

        # Gabungkan domain
        combined_domain = f"{BUG_DOMAIN}.{orig_sni}"

        # Cek aktif/tidaknya wildcard (Ping DNS)
        if not is_wildcard_active(combined_domain):
            return None # Skip jika tidak aktif

        # Jika aktif, ubah data dan encode ulang
        data['sni'] = combined_domain
        if 'host' in data and data['host']:
            data['host'] = combined_domain
        data['ps'] = f"[Wildcard Aktif] {data.get('ps', 'VMess')}"

        new_b64 = base64.b64encode(json.dumps(data).encode('utf-8')).decode('utf-8')
        return "vmess://" + new_b64
    except Exception:
        return None

def process_url_based(link, protocol):
    try:
        parsed = urlparse(link)
        qs = parse_qs(parsed.query)

        orig_sni = qs.get('sni', [parsed.hostname])[0]
        combined_domain = f"{BUG_DOMAIN}.{orig_sni}"

        # Cek aktif/tidaknya wildcard (Ping DNS)
        if not is_wildcard_active(combined_domain):
            return None # Skip jika tidak aktif

        qs['sni'] = [combined_domain]
        if 'host' in qs:
            qs['host'] = [combined_domain]

        new_query = urlencode(qs, doseq=True)
        new_fragment = f"[Wildcard Aktif] {parsed.fragment}" if parsed.fragment else f"[{protocol}] Wildcard"
        
        new_parsed = parsed._replace(query=new_query, fragment=new_fragment)
        return urlunparse(new_parsed)
    except Exception:
        return None

def process_single_link(line):
    """Fungsi helper untuk mengeksekusi masing-masing link"""
    line = line.strip()
    if line.startswith("vmess://"):
        return process_vmess(line)
    elif line.startswith("vless://"):
        return process_url_based(line, "vless")
    elif line.startswith("trojan://"):
        return process_url_based(line, "trojan")
    return None

def main():
    print(f"Mengunduh daftar akun V2Ray dari Github...")
    try:
        response = requests.get(URL_SUMBER, timeout=15)
        response.raise_for_status()
    except Exception as e:
        print(f"Gagal mengunduh: {e}")
        return

    lines = response.text.splitlines()
    print(f"Berhasil mengunduh {len(lines)} akun.")
    print(f"Memulai PING dan Pengecekan Wildcard ({BUG_DOMAIN}.[domain]) secara massal...")
    print("Harap tunggu, proses ini memakan waktu beberapa saat...\n")

    valid_links = []
    
    # Gunakan ThreadPoolExecutor untuk ping banyak domain sekaligus
    with concurrent.futures.ThreadPoolExecutor(max_workers=MAX_THREADS) as executor:
        # Map akan menjalankan process_single_link untuk setiap baris
        results = executor.map(process_single_link, lines)
        
        for res in results:
            if res: # Jika mengembalikan link (artinya aktif)
                valid_links.append(res)

    print(f"\n--- HASIL PENGECEKAN ---")
    print(f"Total akun yang support Wildcard: {len(valid_links)} dari {len(lines)} akun.")

    # Simpan ke file
    if valid_links:
        with open(OUTPUT_FILE, "w", encoding="utf-8") as f:
            for link in valid_links:
                f.write(link + "\n")
        print(f"✅ Akun yang aktif telah disimpan ke '{OUTPUT_FILE}'.")
    else:
        print("❌ Tidak ditemukan akun yang support wildcard di daftar ini.")

if __name__ == "__main__":
    main()
