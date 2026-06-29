import pefile
import joblib
import os

BASE_DIR = r"D:\iam"
expected_features_l1 = joblib.load(os.path.join(BASE_DIR, 'models', 'layer1_features.pkl'))

def extract_static_all_features(file_path, layer2_api_names=None):
    """
    Hệ thống trích xuất tĩnh Siêu cấp: 
    - PE Headers & IAT (Gốc)
    - Số lượng Imports/Exports (Kháng báo động giả)
    - Tần suất Từ khóa Chuỗi nhạy cảm (String Keywords)
    - Entropy chi tiết theo Phân vùng (Section Entropies)
    """
    try:
        pe = pefile.PE(file_path, fast_load=False)
        l1_data = {}
        
        # 1. Các đặc trưng PE Header cơ bản
        l1_data['Machine'] = pe.FILE_HEADER.Machine
        l1_data['NumberOfSections'] = pe.FILE_HEADER.NumberOfSections
        l1_data['MajorLinkerVersion'] = pe.OPTIONAL_HEADER.MajorLinkerVersion
        l1_data['MinorLinkerVersion'] = pe.OPTIONAL_HEADER.MinorLinkerVersion
        l1_data['MajorImageVersion'] = pe.OPTIONAL_HEADER.MajorImageVersion
        l1_data['MajorOSVersion'] = pe.OPTIONAL_HEADER.MajorOperatingSystemVersion
        l1_data['SizeOfStackReserve'] = pe.OPTIONAL_HEADER.SizeOfStackReserve
        l1_data['DllCharacteristics'] = pe.OPTIONAL_HEADER.DllCharacteristics

        for k in ['DebugRVA', 'DebugSize', 'ExportRVA', 'ExportSize', 'IatVRA', 'ResourceSize']:
            l1_data[k] = 0

        if hasattr(pe.OPTIONAL_HEADER, 'DATA_DIRECTORY'):
            for entry in pe.OPTIONAL_HEADER.DATA_DIRECTORY:
                if entry.name == 'IMAGE_DIRECTORY_ENTRY_DEBUG':
                    l1_data['DebugRVA'] = entry.VirtualAddress
                    l1_data['DebugSize'] = entry.Size
                elif entry.name == 'IMAGE_DIRECTORY_ENTRY_EXPORT':
                    l1_data['ExportRVA'] = entry.VirtualAddress
                    l1_data['ExportSize'] = entry.Size
                elif entry.name == 'IMAGE_DIRECTORY_ENTRY_IAT':
                    l1_data['IatVRA'] = entry.VirtualAddress
                elif entry.name == 'IMAGE_DIRECTORY_ENTRY_RESOURCE':
                    l1_data['ResourceSize'] = entry.Size

        l1_data['BitcoinAddresses'] = 0 

        # 2. Đặc trưng Kháng báo động giả (Imports & Exports)
        num_imports = len(pe.DIRECTORY_ENTRY_IMPORT) if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT') else 0
        num_exports = len(pe.DIRECTORY_ENTRY_EXPORT.symbols) if hasattr(pe, 'DIRECTORY_ENTRY_EXPORT') and hasattr(pe.DIRECTORY_ENTRY_EXPORT, 'symbols') else 0
        l1_data['NumberOfImports'] = num_imports
        l1_data['NumberOfExports'] = num_exports

        # 3. [CẢI TIẾN 1] - Đếm từ khóa chuỗi tĩnh ẩn trong mã nhị phân
        with open(file_path, "rb") as f:
            raw_bytes = f.read().lower()
        
        l1_data['str_bitcoin'] = raw_bytes.count(b"bitcoin")
        l1_data['str_encrypt'] = raw_bytes.count(b"encrypt")
        l1_data['str_decrypt'] = raw_bytes.count(b"decrypt")
        l1_data['str_vssadmin'] = raw_bytes.count(b"vssadmin")
        l1_data['str_shadowcopy'] = raw_bytes.count(b"shadowcopy")
        l1_data['str_readme'] = raw_bytes.count(b"readme")

        # 4. [CẢI TIẾN 2] - Phân tách Entropy theo từng phân vùng chính
        l1_data['text_entropy'] = 0.0
        l1_data['data_entropy'] = 0.0
        l1_data['rsrc_entropy'] = 0.0
        l1_data['num_packed_sections'] = 0

        for section in pe.sections:
            try:
                sect_name = section.Name.decode('utf-8', errors='ignore').strip('\x00').lower()
                entropy = section.get_entropy()
                
                if '.text' in sect_name or '.code' in sect_name:
                    l1_data['text_entropy'] = entropy
                elif '.data' in sect_name:
                    l1_data['data_entropy'] = entropy
                elif '.rsrc' in sect_name:
                    l1_data['rsrc_entropy'] = entropy
                
                if entropy > 7.2:
                    l1_data['num_packed_sections'] += 1
            except Exception:
                pass

        # Gộp tất cả vector theo đúng thứ tự mở rộng phục vụ cho train nâng cao
        l1_vector = [l1_data.get(col, 0) for col in expected_features_l1]
        
        # Bọc lót mở rộng cho các thuộc tính mới sinh nếu file pkl chưa đồng bộ kịp
        extra_features_values = [
            num_imports, num_exports,
            l1_data['str_bitcoin'], l1_data['str_encrypt'], l1_data['str_decrypt'],
            l1_data['str_vssadmin'], l1_data['str_shadowcopy'], l1_data['str_readme'],
            l1_data['text_entropy'], l1_data['data_entropy'], l1_data['rsrc_entropy'],
            l1_data['num_packed_sections']
        ]
        
        # --- PHẦN 5: ĐẶC TRƯNG LỚP 2 (IAT) ---
        l2_vector = {}
        if layer2_api_names is not None:
            l2_vector = {api: 0 for api in layer2_api_names}
            if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
                for entry in pe.DIRECTORY_ENTRY_IMPORT:
                    for imp in entry.imports:
                        if imp.name:
                            try:
                                api_name = imp.name.decode('utf-8', errors='ignore')
                                if api_name in l2_vector:
                                    l2_vector[api_name] = 1
                            except Exception:
                                pass
                                
        return l1_vector, l2_vector

    except Exception as e:
        print(f"  [❌ Lỗi Phân Tích Tĩnh]: {e}")
        return None, None