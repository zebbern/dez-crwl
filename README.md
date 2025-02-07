# dez-crwl
## Installation 




## Make Globally Accessible?
### 🐧 - Linux/macOS - 🐧
```
chmod +x dezCrawl.py
mv dezCrawl.py /usr/local/bin/dezCrawl
dezCrawl -h
```
### 🪟 - Windows - 🪟
Step 1: Convert to executable
```
pip install pyinstaller
pyinstaller --onefile dezCrawl.py
```
Step 2: Move exe to directory in your PATH like:
```
move dist/dezCrawl.exe C:\Users\Your-Username\AppData\Local\Microsoft\WindowsApps\
```
Now run
dezCrawl -h
