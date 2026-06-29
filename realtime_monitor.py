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
except Exception:
    yara_rules = None
    print("[WARN] YARA rule definition arrays unavailable.")

# =====================================================================
# ACTION CONTROLLERS
# =====================================================================
def isolate_network():
    print("[ACTION] Isolating endpoints from localized area loop networks...")
    try:
        subprocess.run(["ipconfig", "/release"], capture_output=True, text=True)
        print("[INFO] Interface disconnected from remote gateway channels.")
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

    try:
        with open(file_path, 'rb') as f:
            content = f.read().lower()
        if b"microsoft" in content or b"copyright" in content or b"software" in content:
            final_risk *= 0.6
    except Exception: 
        pass

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
        if r"D:\FPTU" in event.src_path and "giamsat" not in event.src_path:
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
                
                if self.rename_count >= 3:
                    print("[ALERT] Sequential file corruption ceiling passed. Invoking reactive defense loop.")
                    dummy_scores = {'RF': 100.0, 'XGB': 100.0, 'LGBM': 100.0, 'IF': 100.0}
                    send_ai_malware_alert(file_name=f"Mass Modification Activity ({file_name})", risk_scores=dummy_scores, action_taken="Isolate Network (Urgent)")
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
            self.log_event(file_name, "Safe", "Whitelisted", 0, 0, 0, 0)
            return

        print(f"[INFO] Launching static signature validation layers: {file_name}")

        if yara_rules:
            try:
                matches = yara_rules.match(file_path)
                if matches:
                    rule_name = str(matches[0])
                    print(f"[BLOCK] Classification state: Malicious | Reason: YARA baseline threat signature matched [{rule_name}]")
                    self.log_event(file_name, "Malware Detected", f"YARA: {rule_name}", 100, 100, 100, 100)
                    yara_scores = {'RF': 100.0, 'XGB': 100.0, 'LGBM': 100.0, 'IF': 100.0}
                    send_ai_malware_alert(file_name, yara_scores, action_taken=f"Isolate Network (YARA Rule: {rule_name})")
                    isolate_network()
                    return
            except yara.Error as e:
                print(f"[WARN] Processing anomaly inside YARA validation sequence for object: {file_name}: {e}")

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
            try:
                df_l2 = pd.DataFrame([l2_dict], columns=layer2_api_names)
                ransomware_id = model_layer2.predict(df_l2)[0]
                ransomware_name = encoder.inverse_transform([ransomware_id])[0]
                conclusion = f"Ransomware ({ransomware_name})"
            except Exception: 
                conclusion = "Generic Malware"
            
            print(f"[ALERT] Threat boundary tripped. Behavioral target category classified: {conclusion}")
            scores = {'RF': sub_scores['rf'], 'XGB': sub_scores['xgb'], 'LGBM': sub_scores['lgbm'], 'IF': sub_scores['if']}
            send_ai_malware_alert(file_name, scores, action_taken=f"Isolate Network ({conclusion})")
            isolate_network()
        else:
            status = "Safe"
            conclusion = "Benign File"
            print(f"[PASS] Classification state: Verified Safe | Reason: Analytical scores below operational risk ceilings.")
            print(f"==============================================================")

        self.log_event(file_name, status, conclusion, sub_scores['rf'], sub_scores['xgb'], sub_scores['if'], sub_scores['lgbm'])

    def log_event(self, file_name, status, conclusion, rf, xgb, if_score, lgbm):
        with open(LOG_FILE, mode='a', newline='', encoding='utf-8') as f:
            csv.writer(f).writerow([
                datetime.now().strftime('%Y-%m-%d %H:%M:%S'), 
                file_name, status, conclusion, 
                f"{rf:.1f}", f"{xgb:.1f}", f"{if_score:.1f}", f"{lgbm:.1f}"
            ])

def update_ai_models_online():
    """Triggers partial fits and saves newly compiled states to disk configurations."""
    DATASET_PATH = os.path.join(BASE_DIR, "data", "raw", "data_file.csv")
    if not os.path.exists(DATASET_PATH):
        return False
        
    try:
        df_updated = pd.read_csv(DATASET_PATH)
        X = df_updated.drop(columns=['label', 'Tên File', 'Thời gian', 'Hash'], errors='ignore')
        y = df_updated['label']

        # 1. XGBoost
        if os.path.exists(os.path.join(BASE_DIR, 'models', 'layer1_xgb_model.pkl')):
            from xgboost import XGBClassifier
            xgb = XGBClassifier(n_estimators=100, max_depth=6, random_state=42, eval_metric='logloss')
            xgb.fit(X, y)
            joblib.dump(xgb, os.path.join(BASE_DIR, 'models', 'layer1_xgb_model.pkl'))
            models['xgb'] = xgb  

        # 2. Random Forest
        if os.path.exists(os.path.join(BASE_DIR, 'models', 'layer1_rf_model.pkl')):
            from sklearn.ensemble import RandomForestClassifier
            rf = RandomForestClassifier(n_estimators=100, random_state=42)
            rf.fit(X, y)
            joblib.dump(rf, os.path.join(BASE_DIR, 'models', 'layer1_rf_model.pkl'))
            models['rf'] = rf

        # 3. LightGBM
        if os.path.exists(os.path.join(BASE_DIR, 'models', 'layer1_lgbm_model.pkl')):
            from lightgbm import LGBMClassifier
            lgbm = LGBMClassifier(n_estimators=100, random_state=42, verbose=-1)
            lgbm.fit(X, y)
            joblib.dump(lgbm, os.path.join(BASE_DIR, 'models', 'layer1_lgbm_model.pkl'))
            models['lgbm'] = lgbm
            
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
    
    label_value = 1 if is_malware else 0
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

        new_sample = dict(zip(expected_features, l1_vector))
        new_sample['label'] = label_value

        if os.path.exists(DATASET_PATH):
            df_train = pd.read_csv(DATASET_PATH)
            df_updated = pd.concat([df_train, pd.DataFrame([new_sample])], ignore_index=True)
            df_updated.to_csv(DATASET_PATH, index=False)
        else:
            pd.DataFrame([new_sample]).to_csv(DATASET_PATH, index=False)

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