import subprocess
import time

subprocess.Popen(['sudo', 'bash', 'lynis_audit.sh'], shell=False)

while True:
    lynis = subprocess.Popen(['pgrep', '-f', 'lynis_audit.sh'], stdout=subprocess.PIPE).communicate()[0]

    if lynis == b'':
        break
    else:
        time.sleep(300)
