# AI-Based Network Security System for LTE/5G Using NS-3 Simulation

![Python](https://img.shields.io/badge/Python-3.x-3776AB?style=flat&logo=python) ![TensorFlow](https://img.shields.io/badge/TensorFlow-2.x-FF6F00?style=flat&logo=tensorflow) ![PyTorch](https://img.shields.io/badge/PyTorch-2.x-EE4C2C?style=flat&logo=pytorch) ![NS-3](https://img.shields.io/badge/NS--3-Simulator-green?style=flat) ![License](https://img.shields.io/badge/License-MIT-blue?style=flat)

A deep learning-based network intrusion detection system for LTE/5G networks. The system generates realistic attack traffic using the **NS-3 network simulator**, extracts meaningful features, and classifies attacks using **LSTM** and **TabTransformer** models. Model robustness is evaluated using **FGSM adversarial attacks**.

---

## Project Report

Full project report is available in the `report/` folder.

---

## Detected Attack Types

| Class ID | Attack Type | Description |
|----------|-------------|-------------|
| 0 | Brute Force | Repeated unauthorized access attempts |
| 1 | DoS | Floods network with excessive traffic |
| 2 | Insider | Malicious activity by authorized users |
| 3 | Manipulation | Alters or injects false data into communication |
| 4 | MITM | Intercepts communication between nodes |
| 5 | Normal | Normal network behavior (no attack) |
| 6 | Probe | Scans network for vulnerabilities |

---

## Project Structure

```
ai-network-security-lte5g/
├── ns3-simulations/
│   ├── lte-normal-traffic-6.cc        # Normal LTE traffic simulation
│   ├── lte-dos-attack-3.cc            # DoS attack simulation
│   ├── lte-brute-force-attack-2.cc    # Brute Force attack simulation
│   ├── lte-insider-attack-4.cc        # Insider attack simulation
│   ├── lte-mitm-attack-5.cc           # MITM attack simulation
│   ├── lte-probe-attack-7.cc          # Probe attack simulation
│   └── lte-slow-dos-attack-8.cc       # Slow DoS attack simulation
├── dataset/
│   └── lte_7attacks_augmented.csv     # Generated dataset (7 attack types)
├── feature-extraction/
│   └── extractfeatures-8.py           # Feature extraction script
├── models/
│   └── adversialmlattacks-8.ipynb     # LSTM + TabTransformer + FGSM notebook
├── report/
│   └── FinalReport.pdf                # Complete project report
├── .gitignore
└── README.md
```

---

## System Architecture

```
NS-3 Network Simulation
         ↓
Network Statistics Collection
(TxPackets, RxPackets, Delay, Loss)
         ↓
Feature Extraction & Preprocessing
(Normalization, Sequence Generation)
         ↓
Deep Learning Model Training
(LSTM + TabTransformer)
         ↓
Attack Detection & Classification
(7 Classes)
         ↓
Adversarial Testing (FGSM)
         ↓
Visualization & Result Analysis
```

---

## Models Used

### LSTM (Long Short-Term Memory)
- Captures **temporal patterns** in network traffic sequences
- Bidirectional LSTM with attention mechanism
- Built using **TensorFlow/Keras**
- Accuracy before FGSM: **60.39%**
- Accuracy after FGSM: **35.76%**

### TabTransformer
- Learns **feature relationships** using attention mechanisms
- Transformer encoder layers with embedding
- Built using **PyTorch**
- Accuracy before FGSM: **69.67%**
- Accuracy after FGSM: **34.27%**

---

## Adversarial Testing — FGSM

The **Fast Gradient Sign Method (FGSM)** is used to evaluate model robustness by introducing small perturbations to the input data.

```python
# FGSM for TabTransformer (PyTorch)
X_adv = X + epsilon * sign(gradient of loss w.r.t. X)
```

Both models show significant accuracy drops after FGSM, highlighting the need for adversarial training in real-world deployments.

---

## Tech Stack

| Technology | Purpose |
|------------|---------|
| Python 3.x | Core programming language |
| NS-3 (C++) | LTE network simulation |
| TensorFlow / Keras | LSTM model implementation |
| PyTorch | TabTransformer implementation |
| Scikit-learn | Preprocessing & evaluation |
| NumPy & Pandas | Data handling |
| Matplotlib & Seaborn | Visualization |
| Google Colab / VS Code | Development environment |

---

## Hardware Requirements

- Processor: Intel i5 or higher
- RAM: Minimum 8 GB
- Storage: 256 GB
- Internet connection (64-bit OS)
- Optional: GPU for faster model training

---

## How to Run

### 1. NS-3 Simulations (Generate Dataset)

```bash
# Copy .cc files to NS-3 scratch folder
cp ns3-simulations/*.cc /path/to/ns3/scratch/

# Run simulation (example: normal traffic)
cd /path/to/ns3
./ns3 run scratch/lte-normal-traffic-6
```

### 2. Feature Extraction

```bash
cd feature-extraction
python extractfeatures-8.py
```

### 3. Train Models & Run Adversarial Testing

```bash
# Open in Jupyter or Google Colab
cd models
jupyter notebook adversialmlattacks-8.ipynb
```

---

## Results Summary

| Model | Before FGSM | After FGSM |
|-------|-------------|------------|
| LSTM | 70.39% | 35.76% |
| TabTransformer | 79.67% | 34.27% |

TabTransformer outperforms LSTM before adversarial attack, but both models show sensitivity to FGSM perturbations — indicating the need for adversarial robustness improvements in future work.

---

## Dataset

The dataset (`lte_7attacks_augmented.csv`) was generated using NS-3 LTE simulation and contains the following features:

- `TxPackets` — Transmitted packets
- `RxPackets` — Received packets
- `LostPackets` — Packet loss count
- `PacketDeliveryRatio` — PDR value
- `PacketLossRate` — Loss rate
- `TrafficIntensity` — Total traffic
- `Label` — Attack class (7 types)

---

## Future Enhancements

- Real-time intrusion detection integration with live LTE/5G networks
- Adversarial training to improve model robustness against FGSM
- Support for 5G-specific attack scenarios
- Automated alert and response mechanisms
- Larger dataset with more attack variations

---

## Authors

Surya Maran - GitHub: [https://github.com/surya-sde48/] 

---

