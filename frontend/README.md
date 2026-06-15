# 🛡️ CTPPO React Frontend

A modern, secure React dashboard for CVE severity classification and network attack path analysis.

## ✨ Features

- 🔐 **Secure Authentication** - server-side session cookies (HttpOnly), no tokens in JS
- 🎯 **CVE Classification** - text-only severity prediction (0.73 held-out macro-F1)
- 🗺️ **Attack Paths** - Pareto-front visualization (react-three-fiber background)
- 📊 **Real-time Analytics** - TanStack Query for data fetching
- 🎨 **Modern UI** - Tailwind v4 + Motion animations

## 🛠️ Tech Stack

| Technology | Purpose |
|------------|---------|
| React 18 | UI Framework |
| TypeScript | Type Safety |
| TanStack Query | Data Fetching |
| TanStack Router | Type-safe Routing |
| Three.js / R3F | 3D Visualization |
| Tailwind CSS | Styling |
| Framer Motion | Animations |
| Zustand | State Management |

## 🚀 Quick Start

### Prerequisites

- Node.js 18+ or Bun
- CTPPO Backend running on port 8000

### Installation

```bash
# Navigate to frontend directory
cd ~/Downloads/ctppo/frontend

# Install dependencies (use bun for faster install)
bun install
# OR
npm install

# Start development server
bun dev
# OR
npm run dev
```

Open [http://localhost:5173](http://localhost:5173) in your browser.

### Backend Setup

Make sure the backend is running with auth support:

```bash
cd ~/Downloads/ctppo

# Install auth dependencies
pip install PyJWT pyotp "qrcode[pil]"

# Start secure API server
python -m uvicorn api.server_secure:app --reload --port 8000
```

## 📁 Project Structure

```
frontend/
├── src/
│   ├── api/
│   │   └── client.ts       # API client with TanStack Query
│   ├── components/
│   │   └── layout/
│   │       └── RootLayout.tsx
│   ├── routes/
│   │   ├── login.tsx       # Login with 2FA
│   │   ├── register.tsx    # Registration
│   │   ├── dashboard.tsx   # Main dashboard
│   │   ├── classify.tsx    # CVE classification
│   │   ├── attack-paths.tsx # 3D network viz
│   │   └── settings.tsx    # 2FA management
│   ├── stores/
│   │   └── auth.ts         # Zustand auth store
│   ├── lib/
│   │   └── utils.ts        # Utility functions
│   ├── routeTree.gen.ts    # Router configuration
│   ├── main.tsx            # Entry point
│   └── index.css           # Global styles
├── package.json
├── vite.config.ts
├── tailwind.config.js
└── tsconfig.json
```

## 🔐 Authentication Flow

1. **Register** → Create account (email, password, name)
2. **Login** → Enter credentials
3. **Setup 2FA** → Scan QR code with authenticator app
4. **Verify 2FA** → Enter 6-digit code to complete login

### Demo Account

```
Email: demo@ctppo.ai
Password: demo123
```

## 🎯 Pages

### Dashboard (`/dashboard`)
- System health status
- Quick actions
- Model performance metrics

### CVE Classification (`/classify`)
- Enter CVE description
- Configure CVSS vector
- Get severity prediction with confidence

### Attack Paths (`/attack-paths`)
- 3D network visualization
- Pareto-optimal path discovery
- Risk assessment

### Settings (`/settings`)
- Account management
- 2FA setup/disable
- Security settings

## 🔧 Configuration

### Environment Variables

Create `.env.local` for custom configuration:

```env
VITE_API_URL=http://localhost:8000
```

### Proxy Configuration

The Vite dev server proxies `/api` requests to the backend:

```typescript
// vite.config.ts
server: {
  proxy: {
    '/api': {
      target: 'http://localhost:8000',
      changeOrigin: true,
    },
  },
},
```

## 📦 Build for Production

```bash
# Build
bun run build
# OR
npm run build

# Preview production build
bun run preview
```

Output will be in `dist/` directory.

## 🎨 Theming

The app uses a dark theme by default. Colors are defined in `tailwind.config.js`:

```javascript
colors: {
  severity: {
    critical: "#dc2626",
    high: "#ea580c",
    medium: "#ca8a04",
    low: "#16a34a",
  },
}
```

## 🤝 Contributing

1. Fork the repository
2. Create feature branch
3. Commit changes
4. Push to branch
5. Open Pull Request

## 📝 License

MIT License - See LICENSE file

---

**Author:** Ruthvik Bandari  
**Email:** bandari.ru@northeastern.edu  
**Project:** CTPPO - Cyber Threat Prioritization & Path Optimization
