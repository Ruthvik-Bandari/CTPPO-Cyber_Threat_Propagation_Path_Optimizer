# 🛡️ CTPPO React Frontend

A modern, secure React dashboard for CVE severity classification and network attack path analysis.

## ✨ Features

- 🔓 **Open-source, local-first** - no login, no accounts, opens straight into the dashboard
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

Make sure the local API is running on port 8000:

```bash
cd ~/Downloads/ctppo

# Start the API server
python -m uvicorn api.server:app --reload --port 8000
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
│   │   ├── index.tsx       # Redirects to /dashboard
│   │   ├── dashboard.tsx   # Dashboard shell
│   │   ├── dashboard.classify.tsx     # CVE classification
│   │   ├── dashboard.attack-paths.tsx # Pareto-front viz
│   │   ├── dashboard.scan.tsx         # Scanning
│   │   └── dashboard.instances.tsx    # Instances CRUD
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

## 🎯 Pages

The app is open-source and local-first — `/` redirects straight to `/dashboard`, no account required.

### Dashboard (`/dashboard`)
- Quick links to each tool

### CVE Classification (`/dashboard/classify`)
- Enter a CVE description
- Get a severity prediction with confidence (text-only, no CVSS input)

### Attack Paths (`/dashboard/attack-paths`)
- Pareto-optimal path discovery
- Risk assessment

### Scan (`/dashboard/scan`)
- Probe a host or URL for exposure issues

### Instances (`/dashboard/instances`)
- Create scan and analysis workspaces (full CRUD)

## 🔧 Configuration

### Environment Variables

Create `.env.local` for custom configuration. `VITE_API_BASE` sets the API base URL
(defaults to the same-origin `/api`, which the dev server proxies to the local backend):

```env
VITE_API_BASE=http://localhost:8000/api
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
