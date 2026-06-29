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
RANSOMSET_FILE = os.path.join(BASE_DIR, 'data', 'raw', 'ransomset-multiclass-dataset.csv')
MODEL_L2_OUTPUT = os.path.join(BASE_DIR, 'models', 'layer2_xgb_model.pkl')
LABEL_ENCODER_OUTPUT = os.path.join(BASE_DIR, 'models', 'label_encoder.pkl')

def retrain_layer2():
    print("="*65)
    print("[*] STARTING PHASE 2: BEHAVIORAL TRAINING (XGBOOST MULTI-CLASS)")
    print("="*65)

    if not os.path.exists(RANSOMSET_FILE):
        print(f"[!] Error: Ransomset file not found at: {RANSOMSET_FILE}")
        return

    # Load multiclass behavior data
    print("[*] Loading dataset from ransomset-multiclass-dataset.csv...")
    df = pd.read_csv(RANSOMSET_FILE)
    
    # Identify label column name dynamically
    label_column = None
    possible_label_names = ['label', 'class', 'family', 'target', 'type']
    
    for col in df.columns:
        if col.lower() in possible_label_names:
            label_column = col  
            break

    if label_column is None:
        label_column = df.columns[-1]

    print(f"[+] Identified label column: '{label_column}'")
    
    # Drop rows missing labels
    df = df.dropna(subset=[label_column])
    
    X = df.drop(columns=[label_column])
    y = df[label_column]

    # Remove non-numeric identifier columns
    for col in X.columns:
        if X[col].dtype == 'object':
            X = X.drop(columns=[col])

    # Encode text categories to sequential integers
    le = LabelEncoder()
    y_encoded = le.fit_transform(y.astype(str))
    
    print(f" -> Targeted ransomware families: {list(le.classes_)}")
    print(f" -> Number of behavioral attributes: {X.shape[1]}")

    # Split Train (80%) and Test (20%) datasets
    X_train, X_test, y_train, y_test = train_test_split(
        X, y_encoded, test_size=0.2, stratify=y_encoded, random_state=42
    )

    # Train Multiclass XGBoost model
    print("[*] Computing matrix weights and fitting XGBoost...")
    xgb_model = XGBClassifier(
        n_estimators=100,
        max_depth=6,
        learning_rate=0.1,
        objective='multi:softprob',  
        random_state=42,
        n_jobs=-1
    )
    xgb_model.fit(X_train, y_train)
    print("[+] Layer 2 training completed.")

    # Performance Evaluation
    y_pred = xgb_model.predict(X_test)
    print("\n" + "="*18 + " RANSOMWARE CLASSIFICATION REPORT " + "="*18)
    print(classification_report(y_test, y_pred, target_names=le.classes_))
    print("="*69)

    # Export artifacts
    print(f"[*] Serializing Layer 2 artifacts to 'models' folder...")
    joblib.dump(xgb_model, MODEL_L2_OUTPUT)
    joblib.dump(le, LABEL_ENCODER_OUTPUT)
    print("[+] Success: Multiclass classification model successfully updated.")

if __name__ == "__main__":
    retrain_layer2()