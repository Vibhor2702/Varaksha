# Datasets — Varaksha V2 Training Pipeline

This file is reconciled to the **actual loaders in**
`services/local_engine/train_ensemble.py` (the production training pipeline).

All datasets are **non-PII / synthetic or public research datasets**.
Files are stored under `data/datasets/` and auto-discovered by the trainer.

---

## Core training datasets (used by `train_ensemble.py`)

| File | Purpose | Source |
|---|---|---|
| `PS_20174392719_1491204439457_log.csv` | PaySim synthetic mobile money fraud | Kaggle PaySim (CC0) — https://www.kaggle.com/datasets/ealaxi/paysim1 |
| `Untitled spreadsheet - upi_transactions.csv` | Synthetic UPI transactions | Self-generated (matches hackathon brief dataset spec) |
| `Customer_DF (1).csv` + `cust_transaction_details (1).csv` | Customer behavior (joined on customerEmail) | Kaggle credit-fraud behavior dataset (URL not recorded) |
| `realtime_cdr_fraud_dataset.csv` | Telecom CDR fraud dataset | Kaggle telecom fraud dataset (URL not recorded) |
| `supervised_dataset.csv` | API behavior anomaly (classification=outlier) | API behavior anomaly dataset (URL not recorded) |
| `remaining_behavior_ext.csv` | Extended behavior (outlier/bot/attack) | Extended behavior dataset (URL not recorded) |
| `ton-iot.csv` | IoT/IIoT network intrusion (label) | ToN-IoT — https://research.unsw.edu.au/projects/toniot-datasets |

> **If you know the missing URLs**, add them here so the source list is complete.

---

## Optional loaders in code (only used if the file exists)

`train_ensemble.py` also has optional loaders for these filenames. They are not
present in the repo right now, but the loader will include them if added:

| File | Purpose | Source |
|---|---|---|
| `momtsim.csv` | MoMTSim synthetic mobile money simulator | Source URL not recorded |
| `digital_payment_fraud.csv` | Digital payment fraud dataset | Source URL not recorded |
| `usa_banking_2023.csv` | USA banking 2023-2024 transactions | Source URL not recorded |

---

## Notes

- The **prompt injection / jailbreak** datasets in this folder are **legacy V1**
	artefacts and are **not used by the V2 training pipeline**.
- If you want these removed or moved to an archive folder, say the word.
