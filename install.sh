#!/bin/bash

echo "Starting iptracker installation..."

# --- ตรวจสอบ Python3 ---
if ! command -v python3 &> /dev/null; then
    echo "Python3 is not installed. Installing..."
    sudo apt update && sudo apt install -y python3 python3-venv python3-pip dos2unix
fi

# --- ตรวจสอบไฟล์ iptracker.py ---
SCRIPT_NAME="iptracker.py"
if [ ! -f "$SCRIPT_NAME" ]; then
    echo "Error: '$SCRIPT_NAME' not found in current directory."
    echo "Please make sure '$SCRIPT_NAME' exists here."
    exit 1
fi

# --- แปลงไฟล์ Python จาก CRLF (Windows) เป็น LF (Linux) ---
echo "Converting line endings to Linux format..."
dos2unix "$SCRIPT_NAME"

# --- ตั้ง shebang และ chmod +x ---
sed -i '1s|^|#!/usr/bin/env python3\n|' "$SCRIPT_NAME"
chmod +x "$SCRIPT_NAME"

# --- สร้าง Virtual Environment ---
VENV_DIR="$HOME/.iptracker-env"
if [ ! -d "$VENV_DIR" ]; then
    echo "Creating Python virtual environment at $VENV_DIR ..."
    python3 -m venv "$VENV_DIR"
fi

# --- เปิดใช้งาน Virtual Environment และติดตั้ง dependencies ---
echo "Installing Python dependencies in virtual environment..."
source "$VENV_DIR/bin/activate"
pip install --upgrade pip
pip install requests pytz colorama
deactivate

# --- สร้าง symlink ให้เรียกง่ายจากทุกที่ ---
sudo ln -sf "$(pwd)/$SCRIPT_NAME" /usr/local/bin/iptracker

# --- แจ้งผู้ใช้ ---
echo ""
echo "Installation completed!"
echo "You can now run 'iptracker' from any terminal."
echo "Virtual environment is stored at: $VENV_DIR"
echo "To manually run using venv: source $VENV_DIR/bin/activate && python $SCRIPT_NAME"
echo ""
echo "Example usage:"
echo "  iptracker -m           # Check your own IP"
echo "  iptracker -t google.com  # Check a domain IP"
