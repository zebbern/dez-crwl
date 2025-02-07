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
