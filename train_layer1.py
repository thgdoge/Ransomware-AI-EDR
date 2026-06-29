import os
import pandas as pd
import joblib
from sklearn.model_selection import train_test_split
from xgboost import XGBClassifier
from sklearn.metrics import classification_report
from sklearn.preprocessing import LabelEncoder

# ==========================================
# CONFIGURATION PATHS
# ==========================================
BASE_DIR = r"D:\iam"
DATA_FILE = os.path.join(BASE_DIR, 'data', 'raw', 'data_file.csv')
FEATURES_FILE = os.path.join(BASE_DIR, 'models', 'layer1_features.pkl')

def train_layer1_models():
    print("="*65)
    print("[*] STARTING PHASE 1: STATIC TRAINING (4 ENSEMBLE ALGORITHMS)")
    print("="*65)

    if not os.path.exists(DATA_FILE):
        print(f"[!] Error: Data file not found at: {DATA_FILE}")
        return

    # Load raw dataset
    df = pd.read_csv(DATA_FILE)

    # Clean missing values in target column
    label_col_name = df.columns[-1]
    df = df.dropna(subset=[label_col_name])

    # Extract and save targeted static features
    features_names = list(df.columns[2:-1])
    joblib.dump(features_names, FEATURES_FILE)

    X = df.iloc[:, 2:-1]
    y = df.iloc[:, -1]

    # Split Train (80%) and Test (20%) with stratified sampling
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y
    )

    # 1. Random Forest Classifier
    from sklearn.ensemble import RandomForestClassifier
    print("[*] Training Random Forest model...")
    rf = RandomForestClassifier(n_estimators=100, random_state=42)
    rf.fit(X_train, y_train)
    joblib.dump(rf, os.path.join(BASE_DIR, 'models', 'layer1_rf_model.pkl'))

    # 2. XGBoost Classifier
    print("[*] Training XGBoost model...")
    xgb = XGBClassifier(n_estimators=100, max_depth=6, random_state=42, eval_metric='logloss')
    xgb.fit(X_train, y_train)
    joblib.dump(xgb, os.path.join(BASE_DIR, 'models', 'layer1_xgb_model.pkl'))

    # 3. LightGBM Classifier
    from lightgbm import LGBMClassifier
    print("[*] Training LightGBM model...")
    lgbm = LGBMClassifier(n_estimators=100, random_state=42, verbose=-1)
    lgbm.fit(X_train, y_train)
    joblib.dump(lgbm, os.path.join(BASE_DIR, 'models', 'layer1_lgbm_model.pkl'))

    # 4. Isolation Forest (Anomaly Detection)
    from sklearn.ensemble import IsolationForest
    print("[*] Training Isolation Forest model...")
    iso_forest = IsolationForest(contamination=0.1, random_state=42)
    iso_forest.fit(X_train)
    joblib.dump(iso_forest, os.path.join(BASE_DIR, 'models', 'layer1_if_model.pkl'))

    print("[+] Layer 1 base models trained and exported successfully.")

if __name__ == "__main__":
    train_layer1_models()