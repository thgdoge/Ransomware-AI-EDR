import joblib
import os

FEATURES_FILE = r"D:\iam\models\layer1_features.pkl"

clean_features = [
    'Machine', 'DebugSize', 'DebugRVA', 'MajorImageVersion', 'MajorOSVersion', 
    'ExportRVA', 'ExportSize', 'IatVRA', 'MajorLinkerVersion', 'MinorLinkerVersion', 
    'NumberOfSections', 'SizeOfStackReserve', 'DllCharacteristics', 'ResourceSize', 
    'BitcoinAddresses', 'NumberOfImports', 'NumberOfExports'
]

joblib.dump(clean_features, FEATURES_FILE)
print("[OK] Feature schema layer1_features.pkl cleaned and serialized successfully (17 columns unique).")