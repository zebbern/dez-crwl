![Python](https://img.shields.io/badge/Python-3.x-blue)
![Status](https://img.shields.io/badge/Status-Active-green)
![License](https://img.shields.io/badge/License-MIT-brightgreen)
## Table of Contents
- [Installation](#installation)
- [Make Globally Accessible](#make-globally-accessible)
  - [Linux/macOS - Step 1: Clone Repo](#linuxmacos---step-1-clone-repo)
  - [Windows - Step 1: Clone Repo](#windows---step-1-clone-repo)

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
mv dezCrawl.py /usr/local/bin/dezCrawl
dezCrawl -h
```
### 🪟 - Windows - 🪟
**Step 1: Download or clone repo if u havent done it:**
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
**Now run**
```
dezCrawl -h
```
