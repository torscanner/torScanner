from subprocess import call
import glob
import os
import sys
import datetime
import shutil


nameDir =  datetime.datetime.now().strftime("%Y-%m-%d--%H-%M-%S")
nameDir="/opt/torLogs/"+nameDir
call(["mkdir", nameDir])

for mvfile in glob.glob(os.path.join("/mnt/ramfs/", "*")):
	shutil.move(mvfile, nameDir)

call(["python", "/root/backupTor02-07-2013/torScannerDecide.py"])

for infile in glob.glob(os.path.join('/mnt/ramfs/', '*.todo')):
	call(["python", "/root/backupTor02-07-2013/torScannerExec.py"])

	# Riavvio il mio tor
	call(["/etc/init.d/tor", "restart"])
	# alla fine, per evitare che non trovi exit all'inizio
