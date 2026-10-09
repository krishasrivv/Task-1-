# ThreatIntel AI — Cybersecurity Threat Intelligence Dashboard

A professional cybersecurity threat intelligence dashboard that aggregates data from **VirusTotal** and **AlienVault OTX**, with an **NVIDIA AI-powered chatbot** to help analysts understand threat reports.

![Stack](https://img.shields.io/badge/React-Vite-blue) ![Backend](https://img.shields.io/badge/Flask-Python-green) ![AI](https://img.shields.io/badge/NVIDIA-AI-76B900)

---

## Features

- **Indicator Lookup** — Search IPs, domains, URLs, and file hashes
- **VirusTotal Integration** — Detection stats, reputation, tags, threat labels
- **AlienVault OTX Integration** — Pulse counts, adversaries, MITRE ATT&CK IDs
- **Interactive Charts** — Pie and bar charts (Recharts) driven by real API data
- **AI Chatbot** — NVIDIA-hosted LLM explains findings in simple language
- **Source Status** — Live health indicators for all intelligence sources
- **Responsive Design** — Professional dark theme, desktop and mobile layouts
- **Graceful Error Handling** — Partial failures don't hide valid data

---

## Project Structure

```
Task 1/
├── backend/
│   ├── app.py              # Flask API server
│   ├── requirements.txt    # Python dependencies
│   └── .env.example        # Environment variable template
├── frontend/
│   ├── src/
│   │   ├── components/     # React components
│   │   ├── App.jsx         # Main application
│   │   ├── index.css       # Design system & styles
│   │   └── main.jsx        # Entry point
│   ├── index.html
│   ├── vite.config.js      # Vite config with API proxy
│   └── package.json
├── .env.example            # Root-level env template
├── .gitignore
└── README.md
```

---

## Prerequisites

- **Node.js** 18+ and npm
- **Python** 3.10+
- API keys for:
  - [VirusTotal](https://www.virustotal.com/gui/join-us) (free tier available)
  - [AlienVault OTX](https://otx.alienvault.com/api) (free)
  - [NVIDIA AI](https://build.nvidia.com/) (for the chatbot)

---

## Installation

### 1. Clone the repository

```bash
git clone https://github.com/YOUR_USERNAME/threatintel-ai.git
cd threatintel-ai
```

### 2. Configure environment variables

```bash
cp backend/.env.example backend/.env
```

Edit `backend/.env` and add your real API keys:

```env
VIRUSTOTAL_API_KEY=your_key_here
ALIENVAULT_OTX_API_KEY=your_key_here
NVIDIA_API_KEY=your_key_here
NVIDIA_MODEL=meta/llama-3.1-70b-instruct
```

### 3. Install backend dependencies

```bash
cd backend
python -m pip install -r requirements.txt
```

### 4. Install frontend dependencies

```bash
cd frontend
npm install
```

---

## Running the Application

### Start the backend (terminal 1)

```bash
cd backend
python app.py
```

The Flask server starts on `http://localhost:5000`.

### Start the frontend (terminal 2)

```bash
cd frontend
npm run dev
```

The Vite dev server starts on `http://localhost:5173` with API requests proxied to the backend.

---

## API Endpoints

| Method | Endpoint       | Description                        |
|--------|----------------|------------------------------------|
| GET    | `/api/health`  | Health check & source status       |
| POST   | `/api/lookup`  | Look up an indicator (IP/domain/URL/hash) |
| POST   | `/api/chat`    | Chat with AI about threat reports  |

### Example: Lookup Request

```bash
curl -X POST http://localhost:5000/api/lookup \
  -H "Content-Type: application/json" \
  -d '{"indicator": "8.8.8.8"}'
```

### Example: Chat Request

```bash
curl -X POST http://localhost:5000/api/chat \
  -H "Content-Type: application/json" \
  -d '{"message": "Is this IP malicious?", "context": {"indicator": "8.8.8.8"}}'
```

---

## Security Notes

- API keys are read from environment variables only — never hardcoded
- `.env` is in `.gitignore` — never committed
- User input is validated and sanitized
- No files are uploaded or submitted to third-party services
- Missing data is never treated as proof of safety
- Safe error messages — no secrets in logs or responses

---

## Technology Stack

| Layer      | Technology                    |
|------------|-------------------------------|
| Frontend   | React.js (Vite)              |
| Styling    | Vanilla CSS (dark theme)     |
| Charts     | Recharts                     |
| Icons      | Lucide React                 |
| Backend    | Python Flask                 |
| HTTP       | Python Requests              |
| Config     | python-dotenv                |
| Intel      | VirusTotal v3, AlienVault OTX|
| AI         | NVIDIA-hosted LLM            |

---

## License

MIT
