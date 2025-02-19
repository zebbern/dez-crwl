<div align="center">

## Domain History Crawler

<img src="https://github.com/user-attachments/assets/94445e00-a6b1-4d6c-ae9a-7008307316e9" style="width:45%;">

![Python](https://img.shields.io/badge/Python-3.x-blue)
![Status](https://img.shields.io/badge/Status-Active-green)
![License](https://img.shields.io/badge/License-MIT-brightgreen)

<h6>dezcrwl is a `Web History Osint` tool for gathering URLs, subdomains, JavaScript endpoints, and sensitive information using various OSINT sources like Wayback Machine, Common Crawl, and VirusTotal.**</h6>

---

<h3 align="center">Features</h3>
<kbd align="left">
<br>

|- <kbd> Fetches URLs from Common Crawl, Wayback Machine, and VirusTotal</kbd>

|- <kbd> Discovers subdomains automatically</kbd>

|- <kbd> Extracts JavaScript endpoints and hidden APIs</kbd>

|- <kbd> Detects sensitive information such as API keys and JWT tokens</kbd>

|- <kbd> Supports status code filtering</kbd>

|- <kbd> Generates detailed reports in TXT or JSON format</kbd>

</kbd>
<br>|
<br>|
<br>|
<br>
<kbd>

<h3 align="left">

|- [Installation](#installation)

|- [Make .py Globally Accessible](#make-globally-accessible)  

|- [Usage](#usage) 

|- [Configuration](#configuration) 

|- [Showcase](#showcase)

</h3>
</kbd>
</div>

---

### Installation 
### 🐧 - Linux/macOS - 🐧
**Step 1: Run these commands:**
```
git clone https://github.com/zebbern/dezcrwl.git
chmod +x linuxinstall.sh
./linuxinstall.sh
```
**Now run `dezcrwl -h` anywhere in terminal**
### 🪟 - Windows - 🪟
**Step 1: Convert to executable:**
```
git clone https://github.com/zebbern/dezcrwl.git
windowsinstall.sh
```

## Usage:
1. Run the script with a domain:
```
python3 dezcrwl.py -t example.com -cw -js -sum -o output.txt
```
2. Extract JavaScript endpoints:
```
python3 dezcrwl.py -t example.com -js
```
3. Fetch results from Wayback and VirusTotal:
 ```
python3 dezcrwl.py -t example.com -cw -vt YOUR_VIRUSTOTAL_API_KEY
```
4. Filter specific file types:
```
python3 dezcrwl.py -t example.com -f "(\.json|\.env|\.bak|\.sql)"
```
6. How its supposed to run & with what:
```
dezCrwl target.com -dir -cw -js -ws -sum -o output.txt -f "(\.json|\.env|\.bak|\.backup|\.old|\.git|\.svn|\.swp|\.sql|\.db|\.sqlite|\.log|\.txt|\.zip|\.rar|\.tar\.gz|\.7z|\.pdf|\.docx|\.xlsx|\.conf|\.ini|\.yml|\.yaml|\.dump|\.sql\.dump|\.session|\.pem|\.key|\.crt|\.tmp)"
```

### Configuration:
 (`config.yaml`):
- `verbose: Enables detailed logging (true/false)`
- `output_format: Choose "txt" or "json"`
- `API keys: Configure URLScan and CertSpotter API keys`

## Showcase
Coming....

Developer:
- GitHub: https://github.com/zebbern
