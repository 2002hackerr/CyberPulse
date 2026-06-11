# CyberPulse SaaS 🌐
**Enterprise Attack Surface Analyzer & Threat Dashboard**

<p align="center">
  <img src="https://img.shields.io/badge/Security-Attack_Surface_Management-darkred.svg?style=for-the-badge" alt="Security Badge">
  <img src="https://img.shields.io/badge/Frontend-React%20%2B%20Vite-blue.svg?style=for-the-badge" alt="React Badge">
  <img src="https://img.shields.io/badge/Backend-FastAPI_Python-green.svg?style=for-the-badge" alt="FastAPI Badge">
</p>

## The Problem
Organizations lose track of their public-facing infrastructure. Exposed database ports (RDP, MySQL) and missing security headers (HSTS, CSP) account for the majority of initial breach vectors. Enterprise reconnaissance tools are prohibitively expensive and highly complex.

## The Solution: CyberPulse SaaS
CyberPulse is a lightning-fast, full-stack Web Application that provides an instant security posture analysis of any domain. It marries a high-performance Python/FastAPI scanning engine with a stunning, premium Glassmorphism React frontend to visualize threat intelligence in real-time.

### Core Architecture
1. **The Engine (`/backend`)**: Built with FastAPI. It performs concurrent port scanning across common threat vectors, evaluates HTTP header security posture, and calculates a proprietary **Threat Score (0-100)**.
2. **The Dashboard (`/frontend`)**: Built with Vite and React. Features dynamic risk-level color coding, responsive glassmorphism panels, and a seamless user experience.

## Quick Start (Local Deployment)

### 1. Start the Scanning Engine
```bash
cd backend
python -m venv venv
source venv/bin/activate  # On Windows: .\venv\Scripts\activate
pip install -r requirements.txt
uvicorn main:app --reload
```

### 2. Launch the Dashboard
```bash
cd frontend
npm install
npm run dev
```

Navigate to `http://localhost:5173` to access the CyberPulse Recon Interface.

---
*Developed to democratize enterprise-grade attack surface management.*
