# SENTINEL — Philippine Scam Detection AI

SENTINEL is a web-based scam-detection system for SMS, email, and text messages. It uses an explainable four-layer hybrid analysis pipeline to classify suspicious content across a four-level risk scale from SAFE to CRITICAL.

## Highlights

- Four-layer hybrid detection using TF-IDF similarity, weighted urgency scoring, impersonation targets, and regex-based red-flag rules
- Flask REST API for analysis, feedback, manual reporting, retraining, statistics, and model history
- Feedback-driven learning workflow with model-version tracking
- Supabase-backed storage for analysis logs, verified scam reports, and retraining history
- Lightweight browser frontend for interactive testing and result visualization

## Tech Stack

- Python / Flask
- JavaScript / HTML / CSS
- scikit-learn
- Supabase / PostgreSQL
- APScheduler

## Project Structure

```text
backend/
  app.py
  database/
  engine/
  models/
  requirements.txt
frontend/
  css/
  js/
  index.html
supabase/
  schema.sql
  fix_rls.sql
```

## Environment Setup

This public repository intentionally contains no production credentials.

1. Copy `backend/.env.example` to `backend/.env`.
2. Add your own Supabase project values.
3. Never commit the resulting `.env` file.

```bash
pip install -r backend/requirements.txt
python backend/app.py
```

The backend can also run in offline analysis mode when Supabase is unavailable.

## Security Note

Secrets, local environment files, logs, generated model artifacts, caches, and temporary files are intentionally excluded from this public portfolio repository. Use only your own development credentials when running the project.

## Portfolio Context

This repository is a sanitized public snapshot intended to demonstrate system design, applied machine learning, API development, database integration, and secure configuration practices without exposing private development credentials or operational data.
