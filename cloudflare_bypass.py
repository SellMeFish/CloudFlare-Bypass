import requests
import socket
import json
import time
import shodan
import cloudscraper
import subprocess
from tqdm import tqdm
from dnsdumpster.DNSDumpsterAPI import DNSDumpsterAPI
from censys.search import CensysHosts

SHODAN_API_KEY = "YOUR_SHODAN_API_KEY"
SECURITYTRAILS_API_KEY = "YOUR_SECURITYTRAILS_API_KEY"
CENSYS_API_ID = "YOUR_CENSYS_ID"
CENSYS_API_SECRET = "YOUR_CENSYS_SECRET"

def show_banner():
    banner = """

    \033[0;36m       __     
    \033[0;36m    __(  )_   \033[1;97m\033[4;37mAdvanced CloudFlare Bypass Tool v5.1 \e[0;0m
    \033[0;36m __(       )_   \e[0;0mBypass Cloudflare & Find Real IP
    \033[0;36m(____________)  \e[0;0mAutomated Scanning & OSINT Extraction

    """
    print(banner)

def show_progress_bar():
    for _ in tqdm(range(100), desc="🔍 Scanning for real IP", ascii=True, ncols=75):
        time.sleep(0.01)

def clean_url(url):
    return url.replace("http://", "").replace("https://", "").replace("www.", "").strip("/")

def get_cloudflare_ip(domain):
    try:
        return socket.gethostbyname(domain)
    except:
        return None

def get_real_ip_shodan(domain):
    try:
        print("🔎 Searching Shodan for real IP...")
        api = shodan.Shodan(SHODAN_API_KEY)
        results = api.search(f"hostname:{domain}")

        if results["matches"]:
            return results["matches"][0]["ip_str"]
    except:
        return None

def get_real_ip_securitytrails(domain):
    try:
        print("🔎 Checking SecurityTrails for past DNS records...")
        url = f"https://api.securitytrails.com/v1/history/{domain}/dns/a"
        headers = {"APIKEY": SECURITYTRAILS_API_KEY}
        response = requests.get(url, headers=headers)

        if response.status_code == 200:
            data = response.json()
            return data["records"][0]["values"][0]["ip"]
    except:
        return None

def get_real_ip_censys(domain):
    try:
        print("🔎 Searching Censys for real IP...")
        censys_hosts = CensysHosts(api_id=CENSYS_API_ID, api_secret=CENSYS_API_SECRET)
        search_results = censys_hosts.search(domain)
        for result in search_results:
            return result["ip"]
    except:
        return None

def get_dns_ip(domain):
    try:
        return socket.gethostbyname(domain)
    except:
        return None

def bypass_cloudflare(url):
    try:
        print("🔎 Bypassing Cloudflare challenge...")
        scraper = cloudscraper.create_scraper()
        response = scraper.get(url)
        return response.text[:500]
    except:
        return None

def main():
    show_banner()

    target_url = input("🔗 Enter target website (e.g. example.com): ").strip()
    if not target_url:
        print("❌ Fehler: Ungültige Eingabe!")
        return

    show_progress_bar()

    print("\n\033[1;92mScanning:\033[1;97m", target_url)

    clean_domain = clean_url(target_url)

    cloudflare_ip = get_cloudflare_ip(clean_domain)

    real_ip = (
        get_real_ip_shodan(clean_domain)
        or get_real_ip_securitytrails(clean_domain)
        or get_real_ip_censys(clean_domain)
        or get_dns_ip(clean_domain)
    )

    if real_ip == cloudflare_ip:
        print("\n❌ Unable to Bypass Cloudflare - Only Cloudflare IPs found!")
        print(f"🔒 Cloudflare IP: {cloudflare_ip}")
        print("\n\033[1;92m-----------------------------------------------------\033[0;0m")
        return
    elif real_ip:
        print("\n✅ Real IP Address Found! Cloudflare Bypass Successful:")
        print(f"📌 Real IP Address: {real_ip}")
    else:
        print("\n❌ No Real IP Found. Cloudflare Bypass Failed.")

    bypass_result = bypass_cloudflare(f"https://{clean_domain}")
    if bypass_result:
        print("\n✅ Successfully bypassed Cloudflare! (Partial Response):")
        print(bypass_result)

    print("\n\033[1;92m-----------------------------------------------------\033[0;0m")
    print(f"🌍 Target Website  : {target_url}")
    print(f"🛡️  CloudFlare IP  : {cloudflare_ip}")
    print(f"📌 Real IP Address : {real_ip if real_ip else 'Not Found'}")
    print("\033[1;92m-----------------------------------------------------\033[0;0m")

if __name__ == "__main__":
    main()
