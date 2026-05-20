#!/bin/bash

# Aegis Automated Setup Script
set -e

echo "🛡️  Starting Aegis setup..."

# 1. Create virtual environment
if [ ! -d "venv" ]; then
    echo "[1/4] Creating virtual environment..."
    python3 -m venv venv
else
    echo "[1/4] Virtual environment already exists."
fi

# 2. Install dependencies
echo "[2/4] Installing dependencies..."
source venv/bin/activate
pip install --upgrade pip
pip install -r requirements.txt
pip install -r requirements-dev.txt

# 3. Initialize database
echo "[3/4] Initializing database..."
python scripts/seed_db.py

# 4. Run the application
echo "[4/4] Setup complete! Starting Aegis..."
echo "Access the dashboard at http://127.0.0.1:5001"
python app/main.py
