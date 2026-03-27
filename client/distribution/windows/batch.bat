pip install pyinstaller
pyinstaller --onefile --hidden-import=flask --hidden-import=psutil --hidden-import=getmac ../../probe.py