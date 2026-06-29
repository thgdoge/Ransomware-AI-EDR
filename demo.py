import os
import time

# Đường dẫn tới thư mục giám sát
WATCH_DIR = r"D:\iam\giamsat"

def run_ransomware_demo():
    print("[INFO] Bắt đầu kích hoạt kịch bản mô phỏng hành vi Ransomware...")
    
    # Đảm bảo thư mục giám sát tồn tại
    if not os.path.exists(WATCH_DIR):
        os.makedirs(WATCH_DIR)
        
    # Bước 1: Tạo ra 5 file dữ liệu giả lập ban đầu
    test_files = []
    print("[INFO] Tạo các file dữ liệu mục tiêu trong thư mục giám sát:")
    for i in range(1, 6):
        file_path = os.path.join(WATCH_DIR, f"tailieu_quantrong_{i}.txt")
        with open(file_path, "w", encoding="utf-8") as f:
            f.write(f"Day la du lieu quan trong thu {i} cua he thong.")
        test_files.append(file_path)
        print(f"  -> Đã tạo: {file_path}")
        
    # Chờ 2 giây để hệ thống ổn định trạng thái ghi nhận file sạch ban đầu
    print("[INFO] Chờ kích hoạt hành vi mã hóa động...")
    time.sleep(2)
    
    print("\n[ALERT] Ransomware bộc phát: Tiến hành đổi đuôi mã hóa hàng loạt...")
    
    # Bước 2: Duyệt qua từng file và đổi tên sang đuôi .locked tuần tự
    for file_path in test_files:
        if os.path.exists(file_path):
            new_path = file_path.replace(".txt", ".locked")
            try:
                os.rename(file_path, new_path)
                print(f"[ACTION] Đã đổi tên (Mã hóa): {os.path.basename(file_path)} -> {os.path.basename(new_path)}")
            except Exception as e:
                print(f"[ERROR] Không thể thay đổi tệp (Có thể do mạng đã bị cô lập): {e}")
                break
            
            # Giả lập độ trễ mã hóa giữa các file là 0.5 giây
            time.sleep(0.5)

    print("\n[INFO] Kết thúc kịch bản mô phỏng.")

if __name__ == "__main__":
    run_ransomware_demo()