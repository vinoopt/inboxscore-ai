#!/bin/bash
# InboxScore - One-click start script

echo ""
echo "📨 InboxScore - Email Deliverability Diagnostic"
echo "================================================"
echo ""

# Check Python
if ! command -v python3 &> /dev/null; then
    echo "❌ Python 3 is required. Install from https://python.org"
    exit 1
fi

echo "📦 Installing dependencies..."
pip3 install -r requirements.txt --quiet --break-system-packages 2>/dev/null || pip3 install -r requirements.txt --quiet

echo ""
echo "🚀 Starting InboxScore..."
echo "   Open http://localhost:8000 in your browser"
echo "   Press Ctrl+C to stop"
echo ""

python3 app.py
