import requests
import socket
import os
from typing import Dict, Any
import urllib.parse

os.system('cls' if os.name == 'nt' else 'clear')

print("\033[31m")
print("""
 ██▓ ██▓███      ███▄    █ ▓█████▄▄▄█████▓
▓██▒▓██░  ██▒    ██ ▀█   █ ▓█   ▀▓  ██▒ ▓▒
▒██▒▓██░ ██▓▒   ▓██  ▀█ ██▒▒███  ▒ ▓██░ ▒░
░██░▒██▄█▓▒ ▒   ▓██▒  ▐▌██▒▒▓█  ▄░ ▓██▓ ░
░██░▒██▒ ░  ░   ▒██░   ▓██░░▒████▒ ▒██▒ ░
░▓  ▒▓▒░ ░  ░   ░ ▒░   ▒ ▒ ░░ ▒░ ░ ▒ ░░
 ▒ ░░▒ ░        ░ ░░   ░ ▒░ ░ ░  ░   ░
 ▒ ░░░             ░   ░ ░    ░    ░
 ░                       ░    ░  ░

DEVELOPER: quantumpeak
https://github.com/quantumpeakk
""")
print("\033[0m")

def query_ip_info(ip: str, scan_ports: bool = False) -> Dict[str, Any]:
    result = {
        "ip": ip,
        "country": None,
        "region": None,
        "city": None,
        "district": None,
        "address": None,
        "isp": None,
        "asn": None,
        "ip_type": None,
        "reverse_dns": None,
        "latitude": None,
        "longitude": None,
        "google_maps": None,
        "services_ports": {},
        "abuse_info": None
    }

    url = f"http://ip-api.com/json/{ip}?fields=status,message,country,regionName,city,isp,org,asn,lat,lon,timezone"
    response = requests.get(url, timeout=10)
    data = response.json()

    if data.get("status") == "success":
        result["country"] = data.get("country")
        result["region"] = data.get("regionName")
        result["city"] = data.get("city")
        result["district"] = result["city"] if result["city"] else None
        result["address"] = f"{result['city']}, {result['region']}, {result['country']}" if result["city"] and result["region"] else None
        result["isp"] = data.get("isp")
        result["asn"] = data.get("asn")
        org = data.get("org", "").lower()
        if "mobile" in org or "cellular" in org:
            result["ip_type"] = "Mobil ağ"
        elif "hosting" in org or "cloud" in org:
            result["ip_type"] = "Hosting/Sunucu"
        elif any(x in org for x in ["dsl", "cable", "broadband"]):
            result["ip_type"] = "Kablolu/DSL"
        else:
            result["ip_type"] = "Dinamik/Statik (bilinmiyor)"
        result["latitude"] = data.get("lat")
        result["longitude"] = data.get("lon")
        if result["latitude"] and result["longitude"]:
            result["google_maps"] = f"https://www.google.com/maps?q={result['latitude']},{result['longitude']}"

    try:
        hostname = socket.gethostbyaddr(ip)[0]
        result["reverse_dns"] = hostname
    except socket.herror:
        result["reverse_dns"] = "Ters DNS kaydı yok"
    except:
        result["reverse_dns"] = "Sorgu başarısız"

    result["abuse_info"] = "AbuseIPDB için API key gerekli (ücretsiz kayıt olun)"

    if scan_ports:
        common_ports = [21, 22, 23, 25, 53, 80, 110, 143, 443, 993, 995, 3389]
        open_ports = []
        for port in common_ports:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(1)
                result_sock = sock.connect_ex((ip, port))
                if result_sock == 0:
                    open_ports.append(port)
                sock.close()
            except:
                pass
        if open_ports:
            result["services_ports"] = {p: "Açık" for p in open_ports}
        else:
            result["services_ports"] = "Hiçbiri (test edilen portlarda)"

    return result

def print_ip_info(info: Dict[str, Any]):
    print("\033[35m")
    print("╔" + "═" * 80 + "╗")
    print(f"║ {'IP Bilgileri':^78} ║")
    print("╠" + "═" * 80 + "╣")
    print(f"║ {'IP':<20} : {info['ip']:<57} ║")
    print(f"║ {'Ülke':<20} : {info['country'] or 'Bilinmiyor':<57} ║")
    print(f"║ {'Bölge/İl':<20} : {info['region'] or 'Bilinmiyor':<57} ║")
    print(f"║ {'Şehir/İlçe':<20} : {info['city'] or 'Bilinmiyor':<57} ║")
    print(f"║ {'Adres Tahmini':<20} : {info['address'] or 'Bilinmiyor':<57} ║")
    print(f"║ {'ISP':<20} : {info['isp'] or 'Bilinmiyor':<57} ║")
    print(f"║ {'ASN':<20} : {info['asn'] or 'Bilinmiyor':<57} ║")
    print(f"║ {'IP Tipi':<20} : {info['ip_type'] or 'Bilinmiyor':<57} ║")
    print(f"║ {'Ters DNS':<20} : {info['reverse_dns'] or 'Bilinmiyor':<57} ║")
    if info['latitude'] and info['longitude']:
        print(f"║ {'Koordinat':<20} : {info['latitude']}, {info['longitude']:<49} ║")
        print(f"║ {'Google Maps':<20} : {info['google_maps'] or 'Bilinmiyor':<57} ║")
    print(f"║ {'Açık Portlar':<20} : {str(info['services_ports']) or 'Bilinmiyor':<57} ║")
    print(f"║ {'Abuse/Blacklist':<20} : {info['abuse_info'] or 'Bilinmiyor':<57} ║")
    print("╚" + "═" * 80 + "╝")
    print("\033[0m")

ip_to_query = input("\033[32mIP adresini girin (ör: 31.31.31.31): \033[0m").strip()
if not ip_to_query:
    ip_to_query = "8.8.8.8"

scan = input("\033[32mPort tarama yapcan mı? (e/h, varsayılan h): \033[0m").strip().lower() == 'e'

info = query_ip_info(ip_to_query, scan_ports=scan)
print_ip_info(info)
