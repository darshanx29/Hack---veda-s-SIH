
# 🛡️ RakshaNetra

> **Passive AI-Driven Network Threat Detection for Critical Infrastructure**

**RakshaNetra** is an intelligent, passive network security system designed to detect suspicious activities and cyber threats across critical network infrastructure **without actively interacting with, modifying, or re-contacting network endpoints**.

The system analyzes mirrored network traffic and network-flow metadata to identify anomalies, malicious patterns, and potential threats in near real time. By combining **network traffic analysis, feature engineering, machine learning, and rule-based detection**, RakshaNetra provides security teams with actionable threat intelligence while maintaining a **read-only monitoring architecture**.

### 🎯 Core Principle

> **Observe → Analyze → Detect → Alert**

RakshaNetra transforms passive network observations into actionable security intelligence without interfering with the monitored network.

---

## 🚨 Problem Statement

Critical infrastructure networks require continuous monitoring to identify cyber threats such as:

- Distributed Denial-of-Service (DDoS) attacks
- Network scanning and reconnaissance
- Abnormal traffic patterns
- Suspicious DNS activity
- TLS/QUIC-based anomalies
- Communication with potentially malicious infrastructure
- Traffic spikes and behavioral anomalies
- Unknown or previously unseen threats

Traditional security solutions may depend heavily on payload inspection, endpoint interaction, or decryption.

However, highly restricted environments may rely on:

- Passive network taps
- SPAN/mirror ports
- Hardware data diodes
- NetFlow/IPFIX/sFlow
- Network telemetry

RakshaNetra addresses this challenge by providing a **passive threat detection system capable of extracting meaningful security intelligence without inspecting encrypted payloads or actively contacting network sources**.

---

## 💡 Our Solution

RakshaNetra follows a **Traffic → Intelligence → Action** architecture.

```text
┌─────────────────────┐
│   NETWORK TRAFFIC   │
│                     │
│ PCAP / NetFlow      │
│ IPFIX / sFlow       │
└──────────┬──────────┘
           │
           ▼
┌─────────────────────┐
│ Traffic Collection  │
│ & Preprocessing     │
└──────────┬──────────┘
           │
           ▼
┌─────────────────────┐
│ Feature Extraction  │
│                     │
│ Flow • DNS • TLS    │
│ Timing • Statistics │
└──────────┬──────────┘
           │
           ▼
┌─────────────────────┐
│ THREAT DETECTION    │
│                     │
│ Rules + ML Models   │
│ Anomaly Detection   │
└──────────┬──────────┘
           │
           ▼
┌─────────────────────┐
│ Risk Scoring        │
│ & Classification    │
└──────────┬──────────┘
           │
           ▼
┌─────────────────────┐
│ ALERTS & DASHBOARD  │
│                     │
│ Detection → Action  │
└─────────────────────┘
```

---

## ✨ Key Features
### 🔍 Passive Network Monitoring

RakshaNetra can analyze traffic obtained through passive sources such as:

- PCAP captures
- Network taps
- SPAN/mirror ports
- NetFlow
- IPFIX
- sFlow
- Derived network metadata

### 🧠 AI/ML-Based Threat Detection

Machine learning models identify unusual network behavior and patterns that may not be captured by static signatures.

Detection capabilities include:

- Anomaly detection
- Classification
- Behavioral analysis
- Traffic profiling
- Risk scoring

### 📊 Network Flow Analysis

RakshaNetra extracts meaningful features without requiring payload inspection.

Example features include:

- Source/destination IP
- Source/destination port
- Protocol
- Packet count
- Byte count
- Flow duration
- Packet rate
- Byte rate
- Connection frequency
- TCP flags
- Flow direction
- Inter-arrival characteristics

### 🌐 Encrypted Traffic Intelligence

RakshaNetra is designed to extract security signals from observable metadata even when application payloads are encrypted.

Relevant signals include:

- DNS metadata
- TLS metadata
- QUIC metadata
- Flow statistics
- Connection behavior
- Timing characteristics

This enables detection **without requiring payload decryption.**

### 🚨 Threat Detection

| Threat Category | Detection Approach |
|---|---|
| DDoS | Traffic volume & flow behavior |
| Port Scanning | Connection/port patterns |
| Network Reconnaissance | Destination & flow analysis |
| Anomalous Traffic | ML-based anomaly detection |
| Suspicious DNS | DNS behavior & metadata |
| TLS/QUIC Anomalies | Protocol metadata |
| Traffic Flooding | Rate & volume analysis |
| Unknown Behavior | Behavioral/anomaly models |

### ⚡ Near Real-Time Detection

```

Traffic
   ↓
Capture
   ↓
Preprocessing
   ↓
Feature Extraction
   ↓
ML Inference
   ↓
Threat Classification
   ↓
Risk Score
   ↓
Alert

```

### 📈 Security Dashboard

The dashboard can provide:

- Live traffic statistics
- Detected threats
- Threat severity
- Risk scores
- Source/destination information
- Protocol distribution
- Traffic trends
- Detection history
- Alert information
---
## 🔐 Security Design Principles
### 1. Read-Only Architecture

RakshaNetra observes network activity without modifying network traffic.

### 2. No Active Source Interaction

The detection system does not need to contact suspicious hosts to perform basic detection.

### 3. Metadata-First Detection

Detection relies on traffic characteristics and metadata rather than requiring access to application payloads.

### 4. Encryption-Aware

The system extracts useful security signals from observable characteristics of encrypted traffic.

### 5. Modular Detection

Individual detection modules can be developed, tested, and deployed independently.

---

## 🧰 Technology Stack
### Programming & Data Processing
- Python
- Pandas
- NumPy
- Scikit-learn
### Network Analysis
- PCAP
- NetFlow
- IPFIX
- sFlow
- DNS metadata
- TLS/QUIC metadata
### Machine Learning
- Supervised Learning
- Unsupervised Learning
- Anomaly Detection
- Feature Engineering
- Model Evaluation
### Backend
- REST/API-based architecture
- Real-time processing pipeline
- Modular detection services
### Frontend
- Web-based security dashboard
- Real-time threat visualization
- Security analytics
---
## 🏆 Smart India Hackathon

**RakshaNetra** is developed as part of **Smart India Hackathon (SIH) 2026**, under SIH26145.

The project focuses on developing a practical, scalable, and passive approach to detecting cyber threats in environments where active probing and payload inspection may not be suitable.

---
## Team Details 
### Team Name - HackVedas
### Team Members - 
- Darshan Patil
- Siddesh Tungar
- Om Suryawanshi
- Sakshi Patil
- Mrunal Amrutkar
- Dhanish H Poojary
---
## 📜 License

This project is intended for educational, research, and authorized cybersecurity applications.

---
## Authors

| Name | Profiles |
|------|----------|
| **Dhanish H. Poojary** | [LinkedIn](www.linkedin.com/in/dhanish-harish-poojary) · [GitHub](https://github.com/dhanishp-design) |
