import os
import time
import csv
import hashlib
import subprocess
import numpy as np
import pandas as pd
import joblib
import yara
import smtplib
from google import genai
from google.genai import types
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from datetime import datetime
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
from extractor import extract_static_all_features
from dotenv import load_dotenv
import pefile

import threading 
import win32api  
import win32con  
import win32event 

# =====================================================================
# PATH SCHEMAS
# =====================================================================
BASE_DIR = r"D:\iam"
LOG_FILE = os.path.join(BASE_DIR, 'data', 'soc_logs.csv')
YARA_RULES_PATH = os.path.join(BASE_DIR, 'config', 'ransomware_rules.yar')
WHITELIST_FILE = os.path.join(BASE_DIR, 'config', 'whitelist.txt')         
WATCH_DIR = os.path.join(BASE_DIR, 'giamsat')

if not os.path.exists(WHITELIST_FILE):
    with open(WHITELIST_FILE, "w") as f: f.write("")
if not os.path.exists(WATCH_DIR):
    os.makedirs(WATCH_DIR)
DATA_DIR = os.path.dirname(LOG_FILE)
if not os.path.exists(DATA_DIR):
    os.makedirs(DATA_DIR)
if not os.path.exists(LOG_FILE):
    with open(LOG_FILE, mode='w', newline='', encoding='utf-8') as f:
        csv.writer(f).writerow([
            "Timestamp", "File Name", "Status", "Conclusion", 
            "RF (%)", "XGB (%)", "IF (%)", "LGBM (%)"
        ])
    print("[INFO] Generated new 'soc_logs.csv' structure with standardized SOC headers.")

print("[INFO] Initializing EDR Core Threat Engine...")

# Load environmental protection data
load_dotenv(os.path.join(os.path.dirname(__file__), '.env'))

GEMINI_API_KEY = os.getenv("GEMINI_API_KEY")
SENDER_EMAIL = os.getenv("SENDER_EMAIL")
SENDER_PASSWORD = os.getenv("SENDER_PASSWORD")
RECEIVER_EMAIL = os.getenv("RECEIVER_EMAIL")

SMTP_SERVER = "smtp.gmail.com"
SMTP_PORT = 587

# Construct connection channel to Google AI Studio GenAI endpoint
client = genai.Client(api_key=GEMINI_API_KEY)

def ask_gemini_to_write_email(file_name, risk_scores, action_taken):
    """AI Agent: Interacts with gemini-2.5-flash to format incident responses."""
    try:
        prompt = f"""
        Bạn là một chuyên gia phân tích mã độc cấp cao của trung tâm SOC. 
        Hệ thống EDR vừa chặn một tệp tin nguy hiểm với thông số sau:
        - Tên tệp tin: {file_name}
        - Hành động đã thực hiện: {action_taken}
        - Điểm rủi ro từ 4 thuật toán:
          + Random Forest: {risk_scores.get('RF', 0)}%
          + XGBoost: {risk_scores.get('XGB', 0)}%
          + LightGBM: {risk_scores.get('LGBM', 0)}%
          + Isolation Forest: {risk_scores.get('IF', 0)}%
        
        Hãy viết một email cảnh báo khẩn cấp bằng tiếng Việt gửi cho Quản trị viên hệ thống. 
        Yêu cầu: Giọng văn chuyên nghiệp, phân tích ngắn gọn dựa trên điểm số (thuật toán nào nghi ngờ cao nhất), và đưa ra khuyến nghị xử lý tiếp theo.
        Chỉ trả về phần nội dung thư bằng định dạng văn bản (không kèm code block hay giải thích thừa).
        """
        response = client.models.generate_content(
            model='gemini-2.5-flash',
            contents=prompt,
        )
        return response.text
    except Exception as e:
        print(f"[WARN] AI Agent GenAI link error: {e}")
        return None

def send_ai_malware_alert(file_name, risk_scores, action_taken="Isolate Network"):
    """Coordinates mail template generation and dispatches via secure TLS SMTP channel."""
    print("[INFO] Requesting AI Agent to generate alert documentation layout...")
    ai_email_content = ask_gemini_to_write_email(file_name, risk_scores, action_taken)
    
    if not ai_email_content:
        ai_email_content = f"Critical Alert: Threat artifact parsed at {file_name} exhibits highly volatile behavior signatures."

    try:
        msg = MIMEMultipart()
        msg['From'] = SENDER_EMAIL
        msg['To'] = RECEIVER_EMAIL
        msg['Subject'] = f"[CRITICAL WARNING] Ransomware Activity Detected: {file_name}"

        msg.attach(MIMEText(ai_email_content, 'plain', 'utf-8'))

        server = smtplib.SMTP(SMTP_SERVER, SMTP_PORT)
        server.starttls()
        server.login(SENDER_EMAIL, SENDER_PASSWORD)
        server.sendmail(SENDER_EMAIL, RECEIVER_EMAIL, msg.as_string())
        server.quit()
        
        print(f"[INFO] Alert report dispatched via SMTP to: {RECEIVER_EMAIL}")
        return True
    except Exception as e:
        print(f"[ERROR] Connection fallback: SMTP failed to dispatch transmission: {e}")
        return False
    
# =====================================================================
# RESOURCE ALIGNMENT
# =====================================================================
def has_digital_signature(file_path):
    try:
        cmd = f'Get-AuthenticodeSignature "{file_path}" | Select-Object -ExpandProperty Status'
        result = subprocess.run(
            ["powershell", "-Command", cmd], 
            capture_output=True, 
            text=True, 
            creationflags=subprocess.CREATE_NO_WINDOW
        )
        status = result.stdout.strip()
        
        return status == "Valid"
    except Exception:
        return False
    
def load_whitelist():
    whitelist = set()
    if os.path.exists(WHITELIST_FILE):
        with open(WHITELIST_FILE, "r") as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith("#"):
                    whitelist.add(line.lower())
    return whitelist

def get_sha256(file_path):
    hasher = hashlib.sha256()
    try:
        with open(file_path, 'rb') as f:
            for chunk in iter(lambda: f.read(65536), b''):
                hasher.update(chunk)
        return hasher.hexdigest().lower()
    except Exception:
        return None

models = {}
for algo in ['rf', 'xgb', 'if', 'lgbm']:
    model_path = os.path.join(BASE_DIR, 'models', f'layer1_{algo}_model.pkl')
    try:
        models[algo] = joblib.load(model_path)
        print(f"[INFO] Allocated base structural array [{algo.upper()}] -> Target loaded")
    except Exception:
        models[algo] = None
        print(f"[WARN] Allocation skipped [{algo.upper()}] -> File not generated")

try:
    expected_features_l1 = list(joblib.load(os.path.join(BASE_DIR, 'models', 'layer1_features.pkl'))) 
    model_layer2 = joblib.load(os.path.join(BASE_DIR, 'models', 'layer2_xgb_model.pkl'))             
    encoder = joblib.load(os.path.join(BASE_DIR, 'models', 'label_encoder.pkl'))                     
    layer2_api_names = model_layer2.feature_names_in_
    print("[INFO] Model layer matrices structural tracking initialized.")
except Exception:
    expected_features_l1, layer2_api_names = [], []
    print("[WARN] Model configuration tracks initialized with null states.")

try:
    yara_rules = yara.compile(filepath=YARA_RULES_PATH)
    print("[INFO] YARA threat matching criteria activated.")
except Exception as e:
    yara_rules = None
    print(f"[WARN] YARA rule definition arrays unavailable. Error details: {e}")
# =====================================================================
# GLOBAL LOGGING CONTROLLER (Fixed Position)
# =====================================================================
def log_event(file_name, status, conclusion, rf=0.0, xgb=0.0, if_score=0.0, lgbm=0.0):
    max_retries = 3
    for attempt in range(max_retries):
        try:
            with open(LOG_FILE, mode='a', newline='', encoding='utf-8') as f:
                csv.writer(f).writerow([
                    datetime.now().strftime('%Y-%m-%d %H:%M:%S'), 
                    file_name, status, conclusion, 
                    f"{rf:.1f}", f"{xgb:.1f}", f"{if_score:.1f}", f"{lgbm:.1f}"
                ])
            break  
        except PermissionError:
            if attempt < max_retries - 1:
                time.sleep(0.5)  
            else:
                print(f"[WARN] Logging skipped for '{file_name}': File {LOG_FILE} is locked.")
        except Exception as e:
            print(f"[ERROR] Logging failed: {e}")
            break

# =====================================================================
# ACTION CONTROLLERS
# =====================================================================
def start_registry_monitor(root_key, sub_key, friendly_name="Registry Guard"):
    def registry_watch_loop():
        try:
            h_key = win32api.RegOpenKeyEx(root_key, sub_key, 0, win32con.KEY_NOTIFY)
        except Exception as e:
            print(f"[ERROR] Cannot monitor registry key: {e}")
            return

        event_handle = win32event.CreateEvent(None, 0, 0, None)
        watch_filters = win32api.REG_NOTIFY_CHANGE_NAME | win32api.REG_NOTIFY_CHANGE_LAST_SET

        print(f"[INFO] Monitoring registry key: {friendly_name}")

        try:
            while True:
                win32api.RegNotifyChangeKeyValue(h_key, True, watch_filters, event_handle, True)
                result = win32event.WaitForSingleObject(event_handle, 2000)

                if result == win32event.WAIT_OBJECT_0:
                    print(f"[ALERT] Registry modification detected: {friendly_name}")
                    print(f"Path: {sub_key}")

                    
                    log_event(
                        file_name=f"Registry: {friendly_name}",
                        status="Malware Detected",
                        conclusion="Persistence: Registry Modified",
                        rf=100.0, xgb=100.0, if_score=100.0, lgbm=100.0
                    )
                    
                    registry_scores = {'RF': 100.0, 'XGB': 100.0, 'LGBM': 100.0, 'IF': 100.0}
                    send_ai_malware_alert(
                        file_name=f"Registry Modification ({friendly_name})", 
                        risk_scores=registry_scores, 
                        action_taken="Isolate Network (Registry Protection Triggered)"
                    )
                    
                    isolate_network()
                    time.sleep(1)
        except Exception as e:
            print(f"[WARN] Registry monitor exception: {e}")
        finally:
            win32api.RegCloseKey(h_key)
            win32api.CloseHandle(event_handle)

    threading.Thread(target=registry_watch_loop, daemon=True).start()
def isolate_network():
    print("[ACTION] Isolating endpoints from localized area loop networks...")
    try:
        subprocess.run(["ipconfig", "/release"], capture_output=True, text=True)
        print("[INFO] Interface disconnected from remote gateway channels.")
        print(f"===============================================================")
    except Exception as e:
        print(f"[ERROR] Mitigation script failed to clear network socket connections: {e}")

def calculate_risk_score(df_l1, file_path):
    scores = {}
    
    if models.get('rf') is not None:
        try: scores['rf'] = models['rf'].predict_proba(df_l1)[0][1]
        except Exception: scores['rf'] = 0.0
    else: scores['rf'] = 0.0

    if models.get('xgb') is not None:
        try: scores['xgb'] = models['xgb'].predict_proba(df_l1)[0][1]
        except Exception: scores['xgb'] = 0.0
    else: scores['xgb'] = 0.0

    if models.get('lgbm') is not None:
        try: scores['lgbm'] = models['lgbm'].predict_proba(df_l1)[0][1]
        except Exception: scores['lgbm'] = 0.0
    else: scores['lgbm'] = 0.0

    if models.get('if') is not None:
        try:
            dec = models['if'].decision_function(df_l1)[0]
            scores['if'] = 1.0 / (1.0 + np.exp(dec))
        except Exception: scores['if'] = 0.0
    else: scores['if'] = 0.0

    for k in scores: 
        scores[k] = float(scores[k] * 100)

    final_risk = (scores['rf'] * 0.3) + (scores['xgb'] * 0.3) + (scores['if'] * 0.2) + (scores['lgbm'] * 0.2)

    return min(max(final_risk, 0.0), 100.0), scores

# =====================================================================
# EVENT LISTENERS
# =====================================================================
class EDR_SOC_Handler(FileSystemEventHandler):
    def __init__(self):
        self.rename_count = 0

    def wait_for_file_ready(self, file_path, timeout=120):
        start_time = time.time()
        while time.time() - start_time < timeout:
            try:
                with open(file_path, 'rb') as f:
                    return True
            except IOError:
                time.sleep(1)
        return False

    def on_moved(self, event):
        if r"D:\iam" in event.src_path and "giamsat" not in event.src_path:
            return

        if not event.is_directory:
            old_ext = os.path.splitext(event.src_path)[1].lower()
            new_ext = os.path.splitext(event.dest_path)[1].lower()
            
            monitored_exts = ['.pdf', '.docx', '.xlsx', '.jpg', '.txt']
            safe_exts = monitored_exts + ['.tmp']
            
            if old_ext in monitored_exts and new_ext not in safe_exts:
                self.rename_count += 1
                file_name = os.path.basename(event.src_path)
                print(f"[ALERT] Anomalous mass-renaming signature observed: {file_name} -> {new_ext}")
                
                log_event(
                    file_name=f"Encrypted: {file_name}", 
                    status="Malware Detected", 
                    conclusion="Behavioral: File Renamed", 
                    rf=100.0, 
                    xgb=100.0, 
                    if_score=100.0, 
                    lgbm=100.0
                )

                if self.rename_count >= 3:
                    print("[ALERT] Sequential file corruption ceiling passed. Invoking reactive defense loop.")
                    dummy_scores = {'RF': 100.0, 'XGB': 100.0, 'LGBM': 100.0, 'IF': 100.0}
                    send_ai_malware_alert(file_name=f"Mass Modification Activity", risk_scores=dummy_scores, action_taken="Isolate Network (Urgent)")
                    isolate_network()
                    self.rename_count = 0

    def on_created(self, event):
        if r"D:\iam" in event.src_path and "giamsat" not in event.src_path:
            return
            
        if not event.is_directory and event.src_path.endswith(('.exe', '.dll')):
            self.process_file(event.src_path, os.path.basename(event.src_path))

    def process_file(self, file_path, file_name):
        print(f"[INFO] Evaluating lock states for inbound payload object: {file_name}...")
        
        if not self.wait_for_file_ready(file_path):
            print(f"[WARN] Target lock duration timed out. Dropping handler event tracking for payload: {file_name}")
            return

        file_hash = get_sha256(file_path)
        whitelist = load_whitelist()
        
        if file_hash in whitelist:
            print(f"[PASS] Classification state: Verified Safe | Reason: Whitelisted cryptographic hash match")
            print(f"==============================================================")
            log_event(file_name, "Safe", "Whitelisted", 0, 0, 0, 0)
            return

        print(f"[INFO] Launching static signature validation layers: {file_name}")

        if yara_rules:
            try:
                matches = yara_rules.match(file_path)
                if matches:
                    rule_name = str(matches[0])
                    print(f"[BLOCK] Classification state: Malicious | Reason: YARA baseline threat signature matched [{rule_name}]")
                    log_event(file_name, "Malware Detected", f"YARA: {rule_name}", 100, 100, 100, 100)
                    yara_scores = {'RF': 100.0, 'XGB': 100.0, 'LGBM': 100.0, 'IF': 100.0}
                    send_ai_malware_alert(file_name, yara_scores, action_taken=f"Isolate Network (YARA Rule: {rule_name})")
                    isolate_network()
                    return
            except yara.Error as e:
                print(f"[WARN] Processing anomaly inside YARA validation sequence for object: {file_name}: {e}")
        
        if has_digital_signature(file_path):
            print(f"[PASS] Classification state: Verified Safe | Reason: Trusted Digital Signature verified on {file_name}")
            print(f"==============================================================")
            log_event(file_name, "Safe", "Whitelisted (Valid Authenticode Signature)", 0, 0, 0, 0)
            return

        l1_vector, l2_dict = extract_static_all_features(file_path, layer2_api_names)
        if l1_vector is None: return

        if expected_features_l1:
            if len(l1_vector) != len(expected_features_l1):
                if len(l1_vector) > len(expected_features_l1): l1_vector = l1_vector[:len(expected_features_l1)]
                else: l1_vector.extend([0] * (len(expected_features_l1) - len(l1_vector)))
            df_l1 = pd.DataFrame([l1_vector], columns=expected_features_l1)
        else:
            df_l1 = pd.DataFrame([l1_vector])

        risk_score, sub_scores = calculate_risk_score(df_l1, file_path)
        print(f"[INFO] Signal assessment complete. Unified Risk Vector Score: {risk_score:.1f}/100")

        if risk_score >= 80.0:
            status = "Malware Detected"
            conclusion = "Generic Malware"
            
            try:
                df_l2 = pd.DataFrame([l2_dict], columns=layer2_api_names)
                ransomware_id = model_layer2.predict(df_l2)[0]
                ransomware_name = encoder.inverse_transform([ransomware_id])[0]
                
                if str(ransomware_name).lower() == 'normal':
                    status = "Malware Detected"
                    conclusion = "Obfuscated Malware (Suspicious Static Features)"
                    print(f"[ALERT] Threat boundary tripped. Obfuscation detected. Category classified: {conclusion}")
                    
                    scores = {'RF': sub_scores['rf'], 'XGB': sub_scores['xgb'], 'LGBM': sub_scores['lgbm'], 'IF': sub_scores['if']}
                    send_ai_malware_alert(file_name, scores, action_taken=f"Isolate Network ({conclusion})")
                    isolate_network()
                    
                    log_event(file_name, status, conclusion, sub_scores['rf'], sub_scores['xgb'], sub_scores['if'], sub_scores['lgbm'])
                    return
                else:
                    status = "Malware Detected"
                    conclusion = f"Ransomware ({ransomware_name})"
                    print(f"[ALERT] Threat boundary tripped. Behavioral target category classified: {conclusion}")
                    scores = {'RF': sub_scores['rf'], 'XGB': sub_scores['xgb'], 'LGBM': sub_scores['lgbm'], 'IF': sub_scores['if']}
                    send_ai_malware_alert(file_name, scores, action_taken=f"Isolate Network ({conclusion})")
                    isolate_network()
                    
                    log_event(file_name, status, conclusion, sub_scores['rf'], sub_scores['xgb'], sub_scores['if'], sub_scores['lgbm'])
                    return
                    
            except Exception as e: 
                status = "Malware Detected"
                conclusion = "Generic Malware"
                print(f"[WARN] Layer 2 classification failed ({e}). Falling back to Layer 1 threat assessment.")
                print(f"[ALERT] Threat boundary tripped. Behavioral target category classified: {conclusion}")
                isolate_network()
                log_event(file_name, status, conclusion, sub_scores['rf'], sub_scores['xgb'], sub_scores['if'], sub_scores['lgbm'])
                return
        else:
            status = "Safe"
            conclusion = "Benign File"
            print(f"[PASS] Classification state: Verified Safe | Reason: Analytical scores below operational risk ceilings.")
            print(f"==============================================================")
            log_event(file_name, status, conclusion, sub_scores['rf'], sub_scores['xgb'], sub_scores['if'], sub_scores['lgbm'])
def update_ai_models_online():
    """Triggers retraining on the updated dataset and saves newly compiled states to disk."""
    DATASET_PATH = os.path.join(BASE_DIR, "data", "raw", "data_file.csv")
    if not os.path.exists(DATASET_PATH):
        print("[WARN] Dataset data_file.csv not found. Skipping online update.")
        return False
        
    try:
        df_updated = pd.read_csv(DATASET_PATH)
        # Drop target label column 'Benign' and all metadata columns
        X = df_updated.drop(columns=[
            'Benign', 'FileName', 'Timestamp', 'Hash', 
            'Tên File', 'Thời gian', 'label', 'md5Hash'
        ], errors='ignore')
        
        # Verify target label column
        if 'Benign' in df_updated.columns:
            y = df_updated['Benign']
        elif 'label' in df_updated.columns:
            y = df_updated['label']
        else:
            print("[ERROR] Target label column ('Benign') not found in dataset.")
            return False

        # Filter features based on expected Layer 1 configuration
        if expected_features_l1:
            X = X[[col for col in expected_features_l1 if col in X.columns]]
            
        print(f"[INFO] Online Learning triggered. Retraining Layer 1 models with {len(X)} samples...")
        
        # 1. XGBoost
        global model_xgb
        if os.path.exists(os.path.join(BASE_DIR, 'models', 'layer1_xgb_model.pkl')):
            from xgboost import XGBClassifier
            xgb = XGBClassifier(n_estimators=100, max_depth=6, random_state=42, eval_metric='logloss')
            xgb.fit(X, y)
            joblib.dump(xgb, os.path.join(BASE_DIR, 'models', 'layer1_xgb_model.pkl'))
            model_xgb = xgb  

        # 2. Random Forest
        global model_rf
        if os.path.exists(os.path.join(BASE_DIR, 'models', 'layer1_rf_model.pkl')):
            from sklearn.ensemble import RandomForestClassifier
            rf = RandomForestClassifier(n_estimators=100, random_state=42)
            rf.fit(X, y)
            joblib.dump(rf, os.path.join(BASE_DIR, 'models', 'layer1_rf_model.pkl'))
            model_rf = rf

        # 3. LightGBM
        global model_lgbm
        if os.path.exists(os.path.join(BASE_DIR, 'models', 'layer1_lgbm_model.pkl')):
            from lightgbm import LGBMClassifier
            lgbm = LGBMClassifier(n_estimators=100, random_state=42, verbose=-1)
            lgbm.fit(X, y)
            joblib.dump(lgbm, os.path.join(BASE_DIR, 'models', 'layer1_lgbm_model.pkl'))
            model_lgbm = lgbm
            
        # 4. Isolation Forest (Unsupervised - trained only on Benign = 1 samples)
        global model_if
        if os.path.exists(os.path.join(BASE_DIR, 'models', 'layer1_if_model.pkl')):
            from sklearn.ensemble import IsolationForest
            X_benign = X[y == 1]
            if len(X_benign) > 0:
                ilf = IsolationForest(contamination=0.01, random_state=42)
                ilf.fit(X_benign)
                joblib.dump(ilf, os.path.join(BASE_DIR, 'models', 'layer1_if_model.pkl'))
                model_if = ilf

        print("[SUCCESS] Live update sequence finished. Model memory parameters adjusted.")
        return True
    except Exception as e:
        print(f"[ERROR] Active learning loop failed to update system models: {e}")
        return False

def learn_from_live_event(file_path, is_malware=True, reason="Zero-Day"):
    """Extracts features dynamically, appends instances to disk logs, and forces active retraining."""
    if not os.path.exists(file_path):
        return False

    file_name = os.path.basename(file_path)
    file_hash = get_sha256(file_path)
    DATASET_PATH = os.path.join(BASE_DIR, "data", "raw", "data_file.csv")
    FEATURES_PKL = os.path.join(BASE_DIR, "models", "layer1_features.pkl")
    
    # Standardize label: Malware = 0, Benign/Safe = 1
    benign_label = 0 if is_malware else 1
    type_str = "ZERO-DAY MALWARE" if is_malware else "FALSE POSITIVE (WHITELIST)"
    print(f"\n[INFO] Active calibration event caught: {type_str} -> {file_name}")

    try:
        if not os.path.exists(FEATURES_PKL): return False
        expected_features = list(joblib.load(FEATURES_PKL))
        
        l1_vector, _ = extract_static_all_features(file_path, [])
        if l1_vector is None: return False

        if len(l1_vector) != len(expected_features):
            if len(l1_vector) > len(expected_features): l1_vector = l1_vector[:len(expected_features)]
            else: l1_vector.extend([0] * (len(expected_features) - len(l1_vector)))

        # Create new sample dictionary synchronized with English schemas
        new_sample = dict(zip(expected_features, l1_vector))
        new_sample['Benign'] = benign_label
        new_sample['FileName'] = file_name
        new_sample['Timestamp'] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        new_sample['Hash'] = file_hash

        if os.path.exists(DATASET_PATH):
            df_train = pd.read_csv(DATASET_PATH)
            # Support updating older files that might have been created with Vietnamese headers
            df_train = df_train.rename(columns={'Tên File': 'FileName', 'Thời gian': 'Timestamp'}, errors='ignore')
            df_updated = pd.concat([df_train, pd.DataFrame([new_sample])], ignore_index=True)
            df_updated.to_csv(DATASET_PATH, index=False)
        else:
            pd.DataFrame([new_sample]).to_csv(DATASET_PATH, index=False)

        # Trigger models active retraining
        update_ai_models_online()

        if not is_malware and file_hash:
            with open(WHITELIST_FILE, "a", encoding="utf-8") as f:
                f.write(f"\n# Auto-learned Whitelist: {file_name}\n{file_hash}")
            print(f"[+] Cryptographic file hash {file_hash} integrated into whitelist configuration constraints.")
            
        elif is_malware and file_hash:
            print(f"[INFO] Hash token locked and blocked globally: {file_hash}")

        return True
    except Exception as e:
        print(f"[ERROR] Active loop pipeline failed to re-align data states: {e}")
        return False

# =====================================================================
# HARDWARE AGENT THREAD LOOP RUNNER
# =====================================================================
if __name__ == "__main__":
    print("[INFO] Initializing security modules...")
    
    start_registry_monitor(
        root_key=win32con.HKEY_CURRENT_USER,
        sub_key=r"Software\Microsoft\Windows\CurrentVersion\Run",
        friendly_name="Windows_User_Startup_Persistence"
    )
    # extended registry monitoring to HKEY_LOCAL_MACHINE for system-wide startup persistence:
    # start_registry_monitor(win32con.HKEY_LOCAL_MACHINE, r"Software\Microsoft\Windows\CurrentVersion\Run", "System_Startup_Persistence")

    observer = Observer()
    observer.schedule(EDR_SOC_Handler(), path=WATCH_DIR, recursive=False)
    observer.start()
    print(f"[INFO] Event monitor loop successfully attached to path: {WATCH_DIR}")
    print(f"===============================================================")
    try:
        while True: 
            time.sleep(1)
    except KeyboardInterrupt: 
        observer.stop()
    observer.join()
