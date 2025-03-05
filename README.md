# 🚀 Advanced Cloudflare Bypass Tool v5.1

This **Advanced Cloudflare Bypass Tool** helps to find the **real IP address** of a website protected by **Cloudflare**.  
It automatically **scans multiple sources** and **compares the found IP with Cloudflare’s IP** to determine if bypassing is possible.

## 🛠 Features
✔ **Detects real server IP behind Cloudflare**  
✔ **Checks Cloudflare’s assigned IP and detects if bypass is successful**  
✔ **Uses multiple methods:**
   - `Shodan` API  
   - `SecurityTrails` API  
   - `Censys` API  
   - `DNS Lookup`  
   - `Subdomain Enumeration`  
   - `Cloudscraper Bypass`  
✔ **Scans forgotten subdomains that may not be protected**  
✔ **Fast & automated scanning process**  

## 🚀 Installation
To run the script, install the required dependencies:

```bash
pip install -r requirements.txt
```

## 📌 Usage
Run the script and enter the target website:

```bash
python cloudflare_bypass.py
```

🔹 Example:
```
🔗 Enter target website (e.g. example.com): scriptblox.com
```

If **only Cloudflare IPs** are found, the tool will **fail the bypass**:
```
❌ Unable to Bypass Cloudflare - Only Cloudflare IPs found!
```
If a **real IP is found**, the tool confirms the bypass success:
```
✅ Real IP Address Found! Cloudflare Bypass Successful!
```

## 🔑 API Keys (Required for Best Results)
For full functionality, you need API keys for the following services:
- **Shodan**: [Get API Key](https://www.shodan.io/)  
- **SecurityTrails**: [Get API Key](https://securitytrails.com/corp/api)  
- **Censys**: [Get API Key](https://censys.io/)  

After obtaining the keys, **edit the script** and replace:
```python
SHODAN_API_KEY = "YOUR_SHODAN_API_KEY"
SECURITYTRAILS_API_KEY = "YOUR_SECURITYTRAILS_API_KEY"
CENSYS_API_ID = "YOUR_CENSYS_ID"
CENSYS_API_SECRET = "YOUR_CENSYS_SECRET"
```

## 📄 `requirements.txt`
```text
requests
shodan
cloudscraper
tqdm
dnsdumpster
censys
```

## ⚠️ Disclaimer
**This tool is for educational & security research purposes only.**  
Using it on unauthorized systems may violate laws. **Use responsibly!**  

---
