# SIH-Project 2025 / RYNO: Always on Guard
Presented by Team Dharohar: 
**AI/ML-based Automated Vulnerability Assessment & Penetration Testing Tool for CCTV and DVR Systems**

---

## Table of Contents

- [Introduction](#introduction)  
- [Features](#features)  
- [Architecture & Modules](#architecture--modules)  
- [Installation & Setup](#installation--setup)  
- [Usage](#usage)  
- [Data & Models](#data--models)  
- [Evaluation / Results](#evaluation--results)  
- [Limitations & Future Work](#limitations--future-work)  
- [Contributing](#contributing)  
- [License](#license)  
- [Contact](#contact)  

---

## Introduction

Surveillance systems (CCTVs, DVRs) are increasingly targeted due to exposed vulnerabilities. Many tools in the market are generic, manual, or costly — lacking specialization for camera/DVR contexts.

**RYNO** is our solution: a specialized, automated tool for discovering, assessing, and exploiting vulnerabilities in CCTV & DVR devices using AI/ML methods and known CVE databases. It aims to improve security postures, reduce manual effort, and provide real-time actionable reports.

---

## Features

- Network scanning & device discovery  
- Vendor / model fingerprinting  
- AI/ML-based vulnerability prediction (LSTM, CNN etc.)  
- CVE lookup & exploit mapping  
- Automated recommendation & remediation guidance  
- Web dashboard interface for reports & controls  
- Modular architecture for easier updates & expansion  

---

## Architecture & Modules

Here is a high-level breakdown of modules/files in the repository:

| Module / File                  | Purpose / Functionality |
|-------------------------------|--------------------------|
| `cctv_scanner.py`             | Performs network scanning, port scanning, and device discovery |
| `cctv_ml_model.py`            | Defines and trains the ML models to predict vulnerabilities |
| `cctv_dashboard.py`           | Backend logic for the dashboard / web interface |
| `cctv_integrated_app.py`      | The orchestrator — ties scanning, ML, CVE lookup, and dashboard together |
| `simple_server.py`            | Lightweight HTTP server setup (for demo or hosting) |
| `test_framework.py`           | Test scripts / frameworks for unit / integration testing |
| `cctv_dashboard.html`         | Frontend HTML for the dashboard UI |
| `requirements.txt`            | List of required Python packages and versions |

You may also add other modules (e.g., data parsers, CVE updaters) as needed.

---

## Installation & Setup

Below is a suggested setup guide. Adjust paths, versions, or instructions to your environment.

### Prerequisites

- Python 3.8 or above  
- pip (Python package manager)  
- (Optional) Virtual environment tool, e.g., `venv` or `conda`

### Steps

1. Clone the repository:  
   ```bash
   git clone https://github.com/altruismm1989-code/SIH-Project.git
   cd SIH-Project
pip install -r requirements.txt

© 2025 Team Dharohar / Vaishali Tripathi
