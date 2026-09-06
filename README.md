# SPECTRA — One-Way Network Threat Monitoring

```
spectra/
├── backend/     Flask API (see backend/README.md for endpoint reference)
└── frontend/    React + Vite dashboard
```

## Run IT (two terminals)

**Terminal 1 — backend**
```bash
cd backend
python3 -m venv venv && source venv/bin/activate   # Windows: venv\Scripts\activate
pip install -r requirements.txt
python run.py
```
Runs on **http://localhost:5000**. Check it's up: `curl http://localhost:5000/api/health`

**Terminal 2 — frontend**
```bash
cd frontend
npm install
npm run dev
```
Runs on **http://localhost:5173**. It's already pointed at the backend via
`frontend/.env` (`VITE_API_BASE=http://localhost:5000/api`) and
`frontend/src/api.js` has a function for every backend endpoint.

Open http://localhost:5173 — leave both terminals running.

