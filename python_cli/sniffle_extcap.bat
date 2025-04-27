@echo off
set SNIFFLE_LOG_FILE=D:\VM\Sniffle\sniffle_debug.log
set SNIFFLE_LOG_LEVEL=DEBUG
python.exe "%~dp0sniffle_extcap.py" %*