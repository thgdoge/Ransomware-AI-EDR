@echo off
title SOC Ransomware Detection System
echo KHOI DONG HE THONG GIAM SAT VA DASHBOARD...

:: Bật Real-time Monitor ở một cửa sổ ẩn hoặc cửa sổ mới
start cmd /k "python realtime_monitor.py"

:: Chờ 3 giây để core khởi động xong
timeout /t 3 /nobreak >nul

:: Bật giao diện Streamlit UI
start cmd /c "streamlit run dashboard.py"

exit