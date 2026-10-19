# SENTINEL — Philippine Scam Detection AI

SENTINEL is a web-based Philippine scam detection system for SMS, email, and text-message analysis. It combines machine learning and rule-based detection to produce explainable four-level risk assessments from **SAFE** to **CRITICAL**, while supporting feedback-driven retraining and model-version auditing.

The system was designed as a full-stack applied machine learning project with a Flask REST API, browser-based frontend, Supabase-backed persistence, and an automated self-learning workflow.

## Highlights

- Implements a **four-layer hybrid detection pipeline** combining:
  1. TF-IDF structural similarity and cosine similarity
  2. Weighted urgency and psychological-pressure signals
  3. Brand/agency impersonation detection
  4. Red-flag, suspicious-link, and composite risk scoring
- Uses **52 Philippine brand and agency impersonation targets** and **67 red-flag / URL detection rules**.
- Produces transparent risk classifications across `SAFE`, `SUSPICIOUS`, `DANGER`, and `CRITICAL` levels.
- Exposes REST endpoints for message analysis, feedback, manual scam reporting, statistics, model history, and manual retraining.
- Stores analysis logs, verified scam reports, and model-version records in Supabase/PostgreSQL.
- Automatically checks for retraining after **10 newly verified scam reports** using APScheduler.
- Includes retraining validation and rollback safeguards to prevent degraded model versions from replacing the active model.
- Supports offline analysis when Supabase is unavailable, allowing the core detection pipeline to continue functioning locally.

## Project Structure

```text
sentinel-public/
├── backend/
│   ├── app.py                    # Flask API and application entry point
│   ├── database/
│   │   └── supabase_client.py    # Supabase persistence layer
│   ├── engine/
│   │   ├── analyzer.py           # Four-layer detection and retraining engine
│   │   ├── corpus.py             # Baseline scam and safe-message corpus
│   │   ├── lexicon.py            # Urgency, impersonation, URL, and red-flag rules
│   │   └── self_learning.py      # Scheduled feedback-driven retraining
│   ├── models/                   # Generated local model artifacts
│   ├── requirements.txt
│   └── .env.example
├── frontend/
│   ├── css/
│   │   └── style.css
│   ├── js/
│   │   └── app.js
│   └── index.html
├── supabase/
│   └── schema.sql
├── .gitignore
└── README.md
```

## Tech Stack

### Backend & API
- Python
- Flask
- Flask-CORS
- REST API architecture

### Machine Learning & Analysis
- scikit-learn
- TF-IDF Vectorization
- Cosine Similarity
- NumPy
- Hybrid ML + rule-based detection
- Automated retraining and validation

### Frontend
- JavaScript
- HTML5
- CSS3

### Database & Scheduling
- Supabase
- PostgreSQL
- APScheduler

## Detection Pipeline

### Layer 1 — Structural Pattern Matching

Incoming messages are vectorized using TF-IDF and compared with the known scam corpus using cosine similarity. This layer identifies structural resemblance to known phishing and scam-message patterns.

### Layer 2 — Psychological Pressure & Urgency Analysis

The message is evaluated against weighted urgency triggers such as credential requests, account threats, time pressure, financial lures, and personal-information requests.

The same layer identifies possible impersonation of Philippine banks, e-wallets, government agencies, telecommunications providers, e-commerce services, logistics companies, and utilities.

### Layer 3 — Red Flag & Malicious Link Detection

Regex and phrase-based rules detect suspicious URL structures, link shorteners, credential requests, manipulation phrases, excessive capitalization, and other common scam indicators.

### Layer 4 — Composite Risk Fusion

The system combines the previous layer scores using weighted contributions:

```text
Structural Similarity     40%
Urgency / Pressure        35%
Red Flags / URLs          25%
```

The resulting score is mapped to one of four risk bands:

```text
SAFE        0.00 – 0.28
SUSPICIOUS  0.28 – 0.50
DANGER      0.50 – 0.72
CRITICAL    0.72 – 1.00
```

## Self-Learning Workflow

Verified scam reports can be incorporated into the model's training corpus.

```text
Message Analysis
      ↓
User Feedback / Verified Scam Report
      ↓
Supabase scam_reports
      ↓
10 New Verified Reports Reached
      ↓
TF-IDF Retraining
      ↓
Keyword Recalibration & Trigger Discovery
      ↓
Validation Against Known Scam Samples
      ↓
Pass → Save New Model Version
Fail → Roll Back to Previous Model
```

The scheduler checks for new verified reports every 30 minutes and records successful model-version updates in the database.

## Environment Setup

Create a local backend environment file from the provided template:

```bash
cp backend/.env.example backend/.env
```

Configure it with credentials from your own Supabase project.

Example:

```env
SUPABASE_URL=https://YOUR_PROJECT.supabase.co
SUPABASE_KEY=YOUR_SUPABASE_KEY
PORT=5000
FLASK_DEBUG=false
```

Do not commit the resulting `.env` file. Use only credentials belonging to your own development environment.

## Database Setup

Create a Supabase project and apply the schema contained in:

```text
supabase/schema.sql
```

The application uses database structures for:

- analysis logs
- user feedback
- verified scam reports
- model-version history
- retraining metadata

Review and configure appropriate Row Level Security and access policies for your own environment before exposing the database to external clients.

## Local Setup

### 1. Clone the repository

```bash
git clone https://github.com/kenzoIS/sentinel-public.git
cd sentinel-public
```

### 2. Create a Python virtual environment

```bash
python -m venv .venv
```

Activate it using your operating system's standard virtual-environment command.

### 3. Install dependencies

```bash
pip install -r backend/requirements.txt
```

### 4. Configure environment variables

```bash
cp backend/.env.example backend/.env
```

Add your own Supabase configuration if database-backed feedback and retraining are required.

### 5. Start SENTINEL

```bash
python backend/app.py
```

The application runs on:

```text
http://localhost:5000
```

The Flask server also serves the included frontend.

## API Overview

| Method | Endpoint | Purpose |
|---|---|---|
| `GET` | `/api/health` | System, model, database, and learner status |
| `POST` | `/api/analyze` | Analyze a message through the four-layer pipeline |
| `POST` | `/api/feedback` | Submit confirmation or correction feedback |
| `POST` | `/api/report` | Add a manually verified scam message |
| `POST` | `/api/retrain` | Trigger a manual retraining cycle |
| `GET` | `/api/stats` | Retrieve detection and model statistics |
| `GET` | `/api/model-history` | Retrieve stored model-version history |

## Security & Data Notes

- Production credentials and local `.env` files are excluded from version control.
- Generated model files, logs, caches, and temporary runtime artifacts should remain local.
- The application stores submitted message content when database-backed analysis or feedback is enabled; use synthetic or non-sensitive data during development.
- Supabase access policies should follow least-privilege principles and be reviewed before production deployment.
- The detection result is a decision-support signal and should not be treated as a substitute for independent verification of suspicious communications.
