<div align="center">

## Domain History Crawler

<img src="https://github.com/user-attachments/assets/94445e00-a6b1-4d6c-ae9a-7008307316e9" style="width:45%;">

![Python](https://img.shields.io/badge/Python-3.x-blue)
![Status](https://img.shields.io/badge/Status-Active-green)
![License](https://img.shields.io/badge/License-MIT-brightgreen)

<h6>dezCrawl is a `Web History Osint` tool for gathering URLs, subdomains, JavaScript endpoints, and sensitive information using various OSINT sources like Wayback Machine, Common Crawl, and VirusTotal.**</h6>
 
<kbd align="left">

<h1>Features</h1>

|- <kbd> Fetches URLs from Common Crawl, Wayback Machine, and VirusTotal</kbd>

|- <kbd> Discovers subdomains automatically</kbd>

|- <kbd> Extracts JavaScript endpoints and hidden APIs</kbd>

|- <kbd> Detects sensitive information such as API keys and JWT tokens</kbd>

|- <kbd> Supports status code filtering</kbd>

|- <kbd> Generates detailed reports in TXT or JSON format</kbd>

</kbd>

<br>

<kbd>

<h3 align="left">

[Click To Get Where You Want](#) 

|- [Installation](#installation)

|- [Make .py Globally Accessible](#make-globally-accessible)  

|- [Usage](#usage) 

|- [Configuration](#configuration) 

|- [Showcase](#showcase)

|- [Python 3.12+ Pip Fix](#python-312-pip-fix)

|- [ModuleNotFoundError Fix](#modulenotfounderror-fix)

</h3>
</kbd>
</div>

---

### Installation 
```
python3 -m venv venv && source venv/bin/activate
git clone https://github.com/zebbern/dez-crwl.git
pip3 install -r requirements.txt
cd ~/dez-crwl
```
## Make Globally Accessible?
### 🐧 - Linux/macOS - 🐧
**Step 1: Run these commands:**
```
chmod +x dezCrawl.py
sudo mv dezCrawl.py /usr/local/bin/dezCrawl
dezCrawl -h
```
**Now run `dezCrawl -h` anywhere in terminal**
### 🪟 - Windows - 🪟
**Step 1: Convert to executable:**
```
pip install pyinstaller
pyinstaller --onefile dezCrawl.py
```
**Step 2: Move exe to directory in your PATH like:**
```
move dist/dezCrawl.exe C:\Users\%USERPROFILE%\AppData\Local\Microsoft\WindowsApps\
dezCrawl -h
```

## Usage:
1. Run the script with a domain:
```
python3 dezCrawl.py -t example.com -cw -js -sum -o output.txt
```
2. Extract JavaScript endpoints:
```
python3 dezCrawl.py -t example.com -js
```
3. Fetch results from Wayback and VirusTotal:
 ```
python3 dezCrawl.py -t example.com -cw -vt YOUR_VIRUSTOTAL_API_KEY
```
4. Filter specific file types:
```
python3 dezCrawl.py -t example.com -f "(\.json|\.env|\.bak|\.sql)"
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

# Python 3.12+ Pip Fix:
### Create and Activate a Virtual Environment
#### For Linux/macOS:
```
python3 -m venv venv && source venv/bin/activate
```
#### For Windows:
```
python -m venv venv && .\venv\Scripts\activate
```
#### ModuleNotFoundError Fix
```
ModuleNotFoundError: No module named 'yaml'
```
**fix by running this same can be done if u get any other missing like this** 
```
python3 -m pip install --upgrade --force-reinstall pyyaml```
```
Developer:
- GitHub: https://github.com/zebbern
