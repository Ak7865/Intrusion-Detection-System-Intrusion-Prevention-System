
RUNTIME_FEATURES = [
    "Destination Port",
    "Flow Duration",
    "Total Fwd Packets",
    "Total Backward Packets",
    "Total Length of Fwd Packets",
    "Total Length of Bwd Packets",
    "Flow Bytes/s",
    "Flow Packets/s",
    "Fwd Packets/s",
    "Bwd Packets/s",
    "Down/Up Ratio",
]

# Original CIC-IDS2017 label column.
TARGET_COLUMN = "Label"

# Features requiring additional packet-level extraction.
PACKET_LEVEL_FEATURES = [
    "Fwd Packet Length Max",
    "Fwd Packet Length Min",
    "Fwd Packet Length Mean",
    "Fwd Packet Length Std",
    "Bwd Packet Length Max",
    "Bwd Packet Length Min",
    "Bwd Packet Length Mean",
    "Bwd Packet Length Std",
    "Flow IAT Mean",
    "Flow IAT Std",
    "Flow IAT Max",
    "Flow IAT Min",
    "FIN Flag Count",
    "SYN Flag Count",
    "RST Flag Count",
    "ACK Flag Count",
    "PSH Flag Count",
    "URG Flag Count",
]

# Features excluded from the initial deployment schema
# pending further investigation.
INVESTIGATION_FEATURES = [
    "Fwd Avg Bytes/Bulk",
    "Fwd Avg Packets/Bulk",
    "Fwd Avg Bulk Rate",
    "Bwd Avg Bytes/Bulk",
    "Bwd Avg Packets/Bulk",
    "Bwd Avg Bulk Rate",
    "Fwd Header Length.1",
]

# Dataset metadata
DATASET_NAME = "CIC-IDS2017"

MODEL_FEATURE_VERSION = "1.0"


