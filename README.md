# dezCrawl - Web Reconnaissance Tool
![Python](https://img.shields.io/badge/Python-3.x-blue)
![Status](https://img.shields.io/badge/Status-Active-green)
![License](https://img.shields.io/badge/License-MIT-brightgreen)
Description:
dezCrawl is a web reconnaissance tool for gathering URLs, subdomains, JavaScript endpoints, and sensitive information using various OSINT sources like Wayback Machine, Common Crawl, and VirusTotal.

## Table of Contents
- [Features](#features)
- [Installation](#installation)
- [Make Globally Accessible](#make-globally-accessible)
- [Usage](#usage)
- [Configuration](#configuration)
- [Showcase](#showcase)
- [Potential Errors](#potential-errors)

## Features:
- Fetches URLs from Common Crawl, Wayback Machine, and VirusTotal
- Discovers subdomains automatically
- Extracts JavaScript endpoints and hidden APIs
- Detects sensitive information such as API keys and JWT tokens
- Supports status code filtering
- Generates detailed reports in TXT or JSON format

## Installation 
```
pip install -r requirements.txt
git clone https://github.com/zebbern/dez-crwl.git
cd dez-crwl
```
## Make Globally Accessible?
### 🐧 - Linux/macOS - 🐧
**Step 1: Download or clone repo if u havent done it:**
```
git clone https://github.com/zebbern/dez-crwl.git
```
**Step 2: Run these commands:**
```
chmod +x dezCrawl.py
sudo mv dezCrawl.py /usr/local/bin/dezCrawl
dezCrawl -h
```
**Now run `dezCrawl -h` anywhere in terminal**
### 🪟 - Windows - 🪟
**Step 1: Download or clone repos if u havent done it:**
```
git clone https://github.com/zebbern/dez-crwl.git
```
**Step 2: Convert to executable:**
```
pip install pyinstaller
pyinstaller --onefile dezCrawl.py
```
**Step 3: Move exe to directory in your PATH like:**
```
echo %PATH%
# Or use this path it usually works replace "Your-Username"
move dist/dezCrawl.exe C:\Users\Your-Username\AppData\Local\Microsoft\WindowsApps\ 
```
**Now run `dezCrawl -h` anywhere in terminal**

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

## Potential Errors
```
ModuleNotFoundError: No module named 'yaml'
```
fix by running this same can be done if u get any other missing like this 
```
python3 -m pip install --upgrade --force-reinstall pyyaml```
```
Developer:
- GitHub: https://github.com/zebbern
