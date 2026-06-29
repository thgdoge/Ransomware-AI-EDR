import os
import glob
import pandas as pd
import joblib

BASE_DIR = r"D:\iam"
RAW_DIR = os.path.join(BASE_DIR, 'data', 'raw')
PROCESSED_DIR = os.path.join(BASE_DIR, 'data', 'processed')
PROCESSED_FILE = os.path.join(PROCESSED_DIR, 'unified_dataset.csv')
FEATURES_FILE = os.path.join(BASE_DIR, 'models', 'layer1_features.pkl')

os.makedirs(RAW_DIR, exist_ok=True)
os.makedirs(PROCESSED_DIR, exist_ok=True)

def batch_parse_csv_v3():
    print("="*60)
    print("[*] BATCH PARSER V3 - FALSE POSITIVE ANTI-MITIGATION ENGINE")
    print("="*60)
    
    try:
        # Load system features matrix
        current_features = list(joblib.load(FEATURES_FILE))
        raw_features = current_features + ['NumberOfImports', 'NumberOfExports']
        
        # Deduplicate features preserving sequence order
        extended_features = list(dict.fromkeys(raw_features))
        print(f" -> Loaded base structure: {len(extended_features)} unique features.")
    except Exception as e:
        print(f"[!] Feature synchronization error: {e}")
        return

    csv_files = glob.glob(os.path.join(RAW_DIR, "*.csv"))
    if not csv_files:
        print(f"[!] Processing directory empty: {RAW_DIR}")
        return

    all_processed_data = []

    for file_path in csv_files:
        file_name = os.path.basename(file_path)
        print(f"[*] Standardizing file: {file_name}...")
        try:
            raw_df = pd.read_csv(file_path)
            if raw_df.empty: continue

            processed_df = pd.DataFrame()

            # Align static features
            for feature in extended_features:
                if feature in raw_df.columns:
                    processed_df[feature] = raw_df[feature]
                else:
                    processed_df[feature] = 0 

            # Map dynamic target labels
            label_col = None
            for col in raw_df.columns:
                if col in ['Benign', 'legitimate', 'malware', 'Label', 'Class']:
                    label_col = col
                    break
            
            if label_col:
                if label_col in ['Benign', 'legitimate']:
                    processed_df['is_malware'] = raw_df[label_col].apply(lambda x: 0 if str(x).strip() in ['1', '1.0', 'True', 'Legitimate', 'Benign'] else 1)
                else:
                    processed_df['is_malware'] = raw_df[label_col].apply(lambda x: 0 if str(x).strip().lower() in ['0', '0.0', 'false', 'normal', 'benign'] else 1)
            else:
                processed_df['is_malware'] = 1

            processed_df.fillna(0, inplace=True)
            all_processed_data.append(processed_df)
            print(f"  [+] Structural alignment complete: {len(processed_df):,} rows integrated.")

        except Exception as e:
            print(f"  [!] Skipped {file_name}: {e}")

    if all_processed_data:
        final_df = pd.concat(all_processed_data, ignore_index=True)
        final_df.drop_duplicates(inplace=True)
        final_df.to_csv(PROCESSED_FILE, index=False)
        print(f"\n[+] Processing complete: {len(final_df):,} rows aggregated.")
        
        # Serialize extended feature matrices
        joblib.dump(extended_features, FEATURES_FILE)
        print(f" -> System features schema updated: '{FEATURES_FILE}'")

if __name__ == "__main__":
    batch_parse_csv_v3()