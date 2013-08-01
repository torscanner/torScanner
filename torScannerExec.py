#!/usr/bin/pyton
# coding=<utf-8>

import pprint
import sys
import random
import Queue
import time
import socket
from math import floor,ceil
from TorCtl import TorCtl
import findexit
import datetime
import sys
import ConfigParser
import decoClass 
import pickle
import os
from shutil import move
import glob

import db2	
from torHelper import *
from logic import *


configFile = "/opt/config.ini" 
configPar = ConfigParser.ConfigParser()
configDic={}

scanDate=''			# Quella che mi dice la giornata di scan, non il timestamp vero e proprio


####################################
####################################
####################################
####################################



class Unbuffered:
   def __init__(self, stream):
       self.stream = stream
   def write(self, data):
       self.stream.write(data)
       self.stream.flush()
   def __getattr__(self, attr):
       return getattr(self.stream, attr)

@timeMeasure
def getAndSetConfig():
	""" Reading config from file"""
	print "-> Reading conf from file",
	configDic={}
	global torPortSockList
	global torPortCtlList
	configPar.read(configFile)
	options = configPar.options("Scanner")
	for option in options:
		try:
			configDic[option] = configPar.get("Scanner", option)
			if configDic[option] == -1:
				DebugPrint("skip: %s" % option)
		except Exception as e:
			print e
			print("exception on %s!" % option)
			configDic[option] = None
      
	options = configPar.options("Tor")
	for option in options:
		try:
			configDic[option] = configPar.get("Tor", option)
			if configDic[option] == -1:
				DebugPrint("skip: %s" % option)
		except Exception as e:
			print e
			print("exception on %s!" % option)
			configDic[option] = None
	
	options = configPar.options("DB")
	for option in options:
		try:
			configDic[option] = configPar.get("DB", option)
			if configDic[option] == -1:
				DebugPrint("skip: %s" % option)
		except Exception as e:
			print e
			print("exception on %s!" % option)
			configDic[option] = None

	configDic["torportsock"]=int(configDic["torportsock"])
	configDic["torportctl"]=int(configDic["torportctl"])
	return configDic

@timeMeasure
def chooseFile():
	print "-> Seleziono un file con le info da scannare", 
	path = '/mnt/ramfs'
	for infile in glob.glob( os.path.join(path, '*.todo') ):
		return infile
		#lol return
		
@timeMeasure
def moveFile(filez):
	print "-> Moving file to /var/log/torscanner", 
	strName=time.strftime("%Y-%m-%d %H:%M:%S",time.gmtime())
	move(filez, '/var/log/torscanner/'+strName)
	return

@timeMeasure
def deleteIfLastRound():
	print "-> Cancello il file di ip da scannare",
	path = '/mnt/ramfs'
	files = glob.glob( os.path.join(path, '*.todo') )             
	print "(ancora", len(files), "to delete)",


def getExitRoutesFromPickle():
	f=open("/mnt/ramfs/my.exits", "rb")
	exitList = pickle.load(f)
	f.close()
	return exitList



#######################################
#######################################

sys.stdout=Unbuffered(sys.stdout)
scanDate = datetime.datetime.fromtimestamp(time.time())
timestart =time.time()

print "-> Start at ", scanDate, " [K]"

# Questa cosa server per leggere la configurazione da file e metterla in 
# un dictionary apposito.
configDic = getAndSetConfig() #k


# creiamo un'istanza al db per le porcate iniziali
conn = db2.dbConnectz(configDic["db_host"],configDic["db_user"],configDic["db_pass"],configDic["db_name"])			#ok

readMe=chooseFile()

print "-> Working with ", readMe

f=open(readMe, "rb")
iplist = pickle.load(f)
f.close()

exitRoutes=getExitRoutesFromPickle()
print "- Number of exit routes",  len(exitRoutes)
print "- Number of ip to scan", len(iplist)

filename1="/mnt/ramfs/lookupdict"
f=open(filename1, 'rb')
dictionarylookup = pickle.load(f)


print "..:: Starting scan ::.."

run(iplist, scanDate, exitRoutes, configDic, dictionarylookup)

print "..:: Scan Finished ::.."

print "-> Moving files to log"
moveFile(readMe)

print "-> Deleting .todo file"
deleteIfLastRound()


print "Exiting: [K]"
sys.exit()
