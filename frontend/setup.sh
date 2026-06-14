#!/bin/bash
# CTPPO React Frontend Setup Script

echo "🛡️ CTPPO Frontend Setup"
echo "========================"

# Check if we're in the right directory
if [ ! -f "package.json" ]; then
    echo "❌ Please run this script from the frontend directory"
    exit 1
fi

# Check for bun or npm
if command -v bun &> /dev/null; then
    PKG_MANAGER="bun"
    echo "✓ Using Bun package manager"
elif command -v npm &> /dev/null; then
    PKG_MANAGER="npm"
    echo "✓ Using npm package manager"
else
    echo "❌ Please install Node.js/npm or Bun"
    exit 1
fi

# Install dependencies
echo ""
echo "📦 Installing dependencies..."
if [ "$PKG_MANAGER" = "bun" ]; then
    bun install
else
    npm install
fi

# Check backend auth packages
echo ""
echo "🔐 Checking backend auth packages..."
cd ../
pip show PyJWT pyotp qrcode > /dev/null 2>&1
if [ $? -ne 0 ]; then
    echo "Installing auth packages..."
    pip install PyJWT pyotp "qrcode[pil]"
fi
cd frontend/

echo ""
echo "✅ Setup complete!"
echo ""
echo "📋 Next steps:"
echo ""
echo "1. Start the backend (in another terminal):"
echo "   cd ~/Downloads/ctppo"
echo "   python -m uvicorn api.server_secure:app --reload --port 8000"
echo ""
echo "2. Start the frontend:"
echo "   cd ~/Downloads/ctppo/frontend"
echo "   ${PKG_MANAGER} dev"
echo ""
echo "3. Open http://localhost:5173 in your browser"
echo ""
echo "🔐 Demo account: demo@ctppo.ai / demo123"
