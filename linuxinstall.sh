#!/usr/bin/env bash

set -e  # Exit immediately on error

######################################
# Step 1: Clone or update the repository
######################################
if [ -d "$HOME/dez-crwl" ]; then
  echo "Directory ~/dez-crwl already exists. Pulling the latest changes..."
  cd "$HOME/dez-crwl"
  git pull
else
  echo "Cloning dez-crwl into ~/dez-crwl..."
  git clone https://github.com/zebbern/dez-crwl.git "$HOME/dez-crwl"
  cd "$HOME/dez-crwl"
fi

######################################
# Step 2: Create (or reuse) a Python venv
######################################
if [ ! -d "venv" ]; then
  echo "Creating Python 3 virtual environment..."
  python3 -m venv venv
fi

echo "Activating virtual environment..."
# shellcheck disable=SC1091
source venv/bin/activate

######################################
# Step 3: Install Python dependencies
######################################
echo "Installing required Python libraries..."
pip install --upgrade pip
pip install aiohttp argparse asyncio colorama python-dateutil logging pyyaml pystyle requests
pip3 install pystyle --break-system-packages

######################################
# Step 4: Convert line endings to Unix
######################################
if [ ! -f "dezCrawl.py" ]; then
  echo "Error: 'dezCrawl.py' not found in $(pwd)."
  exit 1
fi

if command -v dos2unix >/dev/null 2>&1; then
  echo "Converting line endings using dos2unix..."
  dos2unix dezCrawl.py
else
  echo "dos2unix not found. Using sed to remove carriage returns..."
  sed -i 's/\r$//' dezCrawl.py
fi

######################################
# Step 5: Rewrite the shebang to point to the venv python
######################################
# Example result: #!/home/username/dez-crwl/venv/bin/python3
VENV_PYTHON="$(realpath venv/bin/python3)"

# Replace ONLY the first line of dezCrawl.py with the new shebang:
sed -i "1s|^.*|#!${VENV_PYTHON}|" dezCrawl.py

# Make script executable
chmod +x dezCrawl.py

######################################
# Step 6: Move the script to a global bin directory
######################################
# We'll look for standard bin directories in the user's PATH.
# If none is found, fallback to /usr/local/bin or /usr/bin.

declare -a possible_dirs=(
  "/usr/local/bin"
  "/usr/bin"
)

install_dir=""

# Check each candidate to see if it's both a directory & in the user's PATH
for d in "${possible_dirs[@]}"; do
  if [[ -d "$d" && ":$PATH:" == *":$d:"* ]]; then
    install_dir="$d"
    break
  fi
done

# Fallback logic if no candidate was found in PATH
if [ -z "$install_dir" ]; then
  if [ -d "/usr/local/bin" ]; then
    install_dir="/usr/local/bin"
  elif [ -d "/usr/bin" ]; then
    install_dir="/usr/bin"
  else
    echo "No suitable global bin directory found. Install aborted."
    exit 1
  fi
fi

echo "Moving dezCrawl.py to $install_dir/dezCrawl (requires sudo)..."
sudo mv dezCrawl.py "$install_dir/dezCrawl"

echo "Installation complete!"
echo "You can now run:  dezCrawl -h"
