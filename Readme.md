# Real-Time Network Anomaly Detection System
**MS-CISBA Capstone Project**

A modular, locally deployable cybersecurity solution that leverages stream processing, machine learning, and automated threat response for real-time network anomaly detection.

---

## 🚀 Features

- **Dockerized pipeline**: Kafka, Suricata IDS, and Python modules orchestrated with Docker Compose.
- **Real-time traffic analysis**: DBSCAN clustering on streaming network features.
- **Mock firewall API**: Automated (simulated) IP blocking for detected anomalies.
- **Hybrid data storage**: Structured features in SQLite, Suricata alerts in JSON logs.
- **Attack simulation**: Built-in traffic generator for testing detection logic.

---

## 🛠️ Installation

Clone the repository
git clone https://github.com/suhailjamil/Capstone_Project.git
cd Capstone_Project

Start required services
docker-compose up -d --build

Install Python dependencies
pip install -r requirements.txt

text

---

## ⚡ Usage

Run the anomaly detection system with simulated traffic
python src/main.py --simulate

(Optional) View Suricata alerts in real time
tail -f data/processed/suricata.log

text

---

## 📁 Project Structure

├── data/
│ ├── raw/ # Place CIDDS-001 dataset here
│ └── processed/ # Processed features, logs, and SQLite DB
├── src/
│ ├── data_processing/ # ETL and feature extraction scripts
│ ├── models/ # Anomaly detection (DBSCAN)
│ ├── network/ # Kafka producer, firewall API
│ └── main.py # System orchestration
├── docker-compose.yml # Kafka, Zookeeper, Suricata services
├── Dockerfile # Python runtime
├── suricata.yaml # IDS rules/config
└── README.md # This file

text

---

## 🔑 Key Technologies

- **Stream Processing**: Apache Kafka
- **Machine Learning**: Scikit-learn (DBSCAN)
- **Containerization**: Docker, Docker Compose
- **Cybersecurity**: Suricata IDS
- **Data Storage**: SQLite, JSON logs

---

## 📊 Metrics & Future Work

- **Detection metrics** (F1-score, precision, recall) and firewall response time will be included in future releases as the evaluation pipeline is finalized.
- Plans include:
  - Adaptive clustering algorithms
  - Performance benchmarking (throughput, latency)
  - Cloud-native deployment options

---
