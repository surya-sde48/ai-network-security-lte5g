import pandas as pd
import numpy as np

# =========================================================
# 1. LOAD DATA
# =========================================================
df = pd.read_csv("lte_7attacks_augmented.csv")

print("Columns:", df.columns)
print("Shape:", df.shape)

# =========================================================
# 2. CLEANING
# =========================================================
df = df.replace([np.inf, -np.inf], np.nan)
df = df.fillna(0)

# =========================================================
# 3. BASIC FEATURES
# =========================================================
df['LostPackets'] = df['TxPackets'] - df['RxPackets']

# =========================================================
# 4. RATIO FEATURES
# =========================================================
df['PacketDeliveryRatio_calc'] = df['RxPackets'] / (df['TxPackets'] + 1)
df['LossRate_calc'] = df['LostPackets'] / (df['TxPackets'] + 1)

# =========================================================
# 5. TRAFFIC FEATURES
# =========================================================
df['TrafficIntensity'] = df['TxPackets'] + df['RxPackets']
df['PacketDiff'] = df['TxPackets'] - df['RxPackets']

# =========================================================
# 6. TEMPORAL FEATURES (IMPORTANT FOR LSTM)
# =========================================================
df['Delta_Tx'] = df['TxPackets'].diff().fillna(0)
df['Delta_Rx'] = df['RxPackets'].diff().fillna(0)
df['Delta_Loss'] = df['LostPackets'].diff().fillna(0)

df['PacketVariation'] = df['PacketDiff'].diff().fillna(0)

# =========================================================
# 7. ROLLING FEATURES (VERY POWERFUL)
# =========================================================
df['Rolling_Tx_Mean'] = df['TxPackets'].rolling(3).mean().fillna(0)
df['Rolling_Rx_Mean'] = df['RxPackets'].rolling(3).mean().fillna(0)

df['Rolling_Tx_Std'] = df['TxPackets'].rolling(3).std().fillna(0)
df['Rolling_Rx_Std'] = df['RxPackets'].rolling(3).std().fillna(0)

# =========================================================
# 8. BEHAVIOR FEATURES (ATTACK DETECTION)
# =========================================================
df['NetworkStress'] = df['LossRate_calc'] * df['TrafficIntensity']
df['Efficiency'] = df['RxPackets'] / (df['TrafficIntensity'] + 1)

df['AnomalyScore'] = (
    df['LossRate_calc'] +
    abs(df['Delta_Tx']) +
    abs(df['PacketVariation'])
)

# =========================================================
# 9. FINAL FEATURE SELECTION
# =========================================================
features = [
    'TxPackets',
    'RxPackets',
    'LostPackets',

    'PacketDeliveryRatio',
    'PacketLossRate',

    'PacketDeliveryRatio_calc',
    'LossRate_calc',

    'TrafficIntensity',
    'PacketDiff',

    'Delta_Tx',
    'Delta_Rx',
    'Delta_Loss',

    'PacketVariation',

    'Rolling_Tx_Mean',
    'Rolling_Rx_Mean',
    'Rolling_Tx_Std',
    'Rolling_Rx_Std',

    'NetworkStress',
    'Efficiency',
    'AnomalyScore'
]

# Keep only available
features = [f for f in features if f in df.columns]

df = df[features + ['Label']]

# =========================================================
# 10. ENCODE LABELS
# =========================================================
from sklearn.preprocessing import LabelEncoder

le = LabelEncoder()
df['Label'] = le.fit_transform(df['Label'])

print("\nEncoded Classes:", list(le.classes_))

# =========================================================
# 11. CREATE SEQUENCES FOR LSTM
# =========================================================
def create_sequences(df, window_size=20):
    data = df.drop('Label', axis=1).values
    labels = df['Label'].values

    X, y = [], []

    for i in range(len(data) - window_size):
        X.append(data[i:i+window_size])
        y.append(labels[i+window_size-1])

    return np.array(X), np.array(y)

X, y = create_sequences(df, window_size=20)

# =========================================================
# 12. SAVE FOR MODELS
# =========================================================
np.save("X.npy", X)
np.save("y.npy", y)

print("\nDATA PREPARATION COMPLETE")
print("X shape:", X.shape)
print("y shape:", y.shape)

