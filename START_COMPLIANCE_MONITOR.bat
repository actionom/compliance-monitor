@echo off
title SME Compliance Monitor
color 1F
echo.
echo  ====================================================
echo   SME Compliance Monitor v1.0.0
echo   Opoku Mensah (w25035430) - Northumbria University
echo  ====================================================
echo.
echo  Installing / checking required libraries...
pip install streamlit pandas plotly fpdf2 faker python-dateutil --quiet
echo.
echo  Launching Compliance Monitor Dashboard...
echo  Your browser will open at http://localhost:8501
echo.
start http://localhost:8501
streamlit run "%~dp0app.py" --server.port 8501 --server.headless false
pause
