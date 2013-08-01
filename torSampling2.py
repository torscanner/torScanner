#!/usr/bin/pyton
import simplejson
import MySQLdb
import urllib2
import json
import pprint
import sys
import random
import time
from datetime import datetime, timedelta, date


import db2

db_user='tor'
db_pass='torkskan369'
db_name='tor'
db_host='localhost'


data=''


# Indirizzo json dal quale grabbiamo tutte le info
url = "https://onionoo.torproject.org/details?running=true"


# Connect to database
conn = MySQLdb.connect(host=db_host,
			 user=db_user,
			 passwd=db_pass,
			 db=db_name
			 )


def downlaodNodes_web():
	"Scarichiamo i superdati"
	connection = urllib2.urlopen(url)
	data_raw=connection.read()
	try:
		data = json.loads(data_raw)
	except Exception as e:
		print "\n [!] Exception: \n", e
		sys.exit()
	return data
	

	
def newnodes():
	# ora vediamo di gestire i nuovi nodi della rete
	for i in data['relays']:
			lastRestarted	= i['last_restarted']
			fp						= i['fingerprint']	
			tor_version = i['platform']
			db2.insertSample2(conn,fp,scanDateString,lastRestarted,tor_version)		
	

scanDate = datetime.fromtimestamp(time.time())
scanDateString = datetime.strftime(scanDate, "%Y-%m-%d %H:%M:%S")

print "Start [K]",scanDateString

print "Downloading current active nodes",
data=downlaodNodes_web()  		#ok
print " [K]"

print "Sampling and saving nodes",
newnodes()
print " [K]"

print ("Everything's fine.")
sys.exit()






