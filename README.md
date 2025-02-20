<div align="center">

## Domain History Crawler

<img src="https://github.com/user-attachments/assets/94445e00-a6b1-4d6c-ae9a-7008307316e9" style="width:45%;">

![Python](https://img.shields.io/badge/Python-3.x-blue)
![Status](https://img.shields.io/badge/Status-Active-green)
![License](https://img.shields.io/badge/License-MIT-brightgreen)

<h6>dezcrwl is a `Web History Osint` tool for gathering URLs, subdomains, JavaScript endpoints, and sensitive information using various OSINT sources like Wayback Machine, Common Crawl, and VirusTotal.**</h6>

---

</div>

<div align="center">

<h3 align="center">Features ⁀➴ </h3>

<kbd>
<h3>
 
- Fetches URLs from Common Crawl, Wayback Machine, and VirusTotal

</h3>
</kbd>
<br>
<kbd>
<h3>
 
- Detects sensitive information such as API keys and JWT tokens

</h3>
</kbd>
<br>
<kbd>
<h3>
 
- Generates detailed reports in TXT or JSON format

</h3>
</kbd>
<br>
<kbd>
<h3>
 
- Extracts JavaScript endpoints and hidden APIs

</h3>
</kbd>
<br>
<kbd>
<h3>
 
- Discovers subdomains automatically

</h3>
</kbd>
<br>
<kbd>
<h3>
 
- Supports status code filtering

</h3>
</kbd>

</kbd>
<br>│
<br>│
<br>🢃<br>
<kbd>

<h3 align="left">
 
<kbd>$ </kbd> [Installation For Linux](#linux)

<kbd>$ </kbd> [Installation For Windows](#windows)

<kbd>$ </kbd> [Usage](#usage) 

<kbd>$ </kbd> [Configuration](#configuration) 

<kbd>$ </kbd> [Showcase](#showcase)

</h3>
</kbd>
</div>

</div>

<h1 align="center">🢇⁀🐧 ˗˗˗ˏˋ🖳ˎˊ˗˗˗ 🪟⁀🡾</h1>
  
<div align="center">

<kbd>

<h1 id="linux">Linux/macOS</h1>

### Run these commands:
<kbd>
<h3>

```
git clone https://github.com/zebbern/dezcrwl.git
cd dezcrawl
chmod +x linuxinstall.sh
./linuxinstall.sh
```
</h3>
</kbd>

</kbd>

<kbd>
 
<h1 id="windows">Windows</h1>

### Run these commands:
<kbd>
<h3>

```
git clone https://github.com/zebbern/dezcrwl.git
cd dezcrawl
windowsinstall.sh

```
</h3>
</kbd>

</kbd>

### Now run `dezcrwl -h` anywhere in terminal

</div>

<br>

## Usage:
### Run the script with a domain:
```
python3 dezcrwl.py -t example.com -cw -js -sum -o output.txt
```
### Extract JavaScript endpoints:
```
python3 dezcrwl.py -t example.com -js
```
### Fetch results from Wayback and VirusTotal:
 ```
python3 dezcrwl.py -t example.com -cw -vt YOUR_VIRUSTOTAL_API_KEY
```
### Filter specific file types:
```
python3 dezcrwl.py -t example.com -f "(\.json|\.env|\.bak|\.sql)"
```
### How its supposed to run & with what:
```
dezCrwl target.com -dir -cw -js -ws -sum -o output.txt -f "(\.json|\.env|\.bak|\.backup|\.old|\.git|\.svn|\.swp|\.sql|\.db|\.sqlite|\.log|\.txt|\.zip|\.rar|\.tar\.gz|\.7z|\.pdf|\.docx|\.xlsx|\.conf|\.ini|\.yml|\.yaml|\.dump|\.sql\.dump|\.session|\.pem|\.key|\.crt|\.tmp)"
```

## Configuration:

<kbd>

## `config.yaml`:
- <h3>verbose: Enables detailed logging (true/false)</h3>
 
- <h3>output_format: Choose "txt" or "json"</h3>
 
- <h3>API keys: Configure URLScan and CertSpotter API keys</h3>

</kbd>

## Showcase
Coming....

Developer:
- GitHub: https://github.com/zebbern
