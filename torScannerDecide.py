#!/usr/bin/pyton
# coding=<utf-8>

import pprint
import sys
import random
import Queue
import threading
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
import glob
import os


import db2	
from torHelper import *
from logic import *

# sometimes I believe compiler ignores all my comments

configFile = "/opt/config.ini" 
configPar = ConfigParser.ConfigParser()
configDic={}

torPortSockList=[]
torPortCtlList=[]

nodesWeb=''			# nodi da l'internet
nodesRelevant=''			# nodi dal db rileventi
nodesFiltered=[]    # nodi (internet intercept rilevanti)
nodesFiltered2=[]  # IP x porte - (IP x porte)scannati

scanDate=''			# Quella che mi dice la giornata di scan, non il timestamp vero e proprio

workQueueList=[]# la vera e propria lista di code che uso per il lavoro sporco
usedExitRoute=[] #lista per vedere quali ho gia scelto


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


# Connect to socks proxy tor 
#s = socks.socksocket()
#s.setblocking(0)
#s.setproxy(socks.PROXY_TYPE_SOCKS5, 'localhost', 9050)
#s.settimeout(30)

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
def getPortToScan():
   "Legge da file la lista di porte da scannare"
   print "-> Reading port from file",
   files=open(configDic['portfile'], "r")
   ports=files.read()
   porte=ports.split( )
   return porte[0]
   
  
 
# Remove the first line from the ports.conf file.
# that's because we used the first port in the file for the scan
@timeMeasure
def saveCurrentStatus(configDic):
	print "-> Removing port ", port, "from ", configDic['portfile'],
	lines = open(configDic['portfile']).readlines()	
	open(configDic['portfile'], 'w').writelines(lines[1:])
		
#Estraggo i nodi RILEVANTI per la rete tor
@timeMeasure
def getRelevantNodes(conn):
	print "-> Querying DB for discovering relevant nodes",
	nodesRelevant = db2.getRelevantNodesDb(conn)         #ok
	return nodesRelevant

# Leggo i NODI che hanno gia' avuto quella porta scannata
@timeMeasure
def getAlreadyScannedComb(conn, port):
	print "-> Reading already scanned results: ",
	scannedComb = db2.getScannedCombDb(conn, port)		#ok
	print " ( ", len(scannedComb), " )", 
	return scannedComb
	
#Estraggo i nodi che ho gia' usato per qualche connessione
@timeMeasure
def filterUsedExitNodes(conn, exitLists):
	"""
	Qui attenzione: seleziono solo i nodi usati per scannare nodi per i quali non ho ancora terminato la scansione.
	In questo modo non "perdo" in questo passaggio gli exit usati per scannare un nodo per il quale
	ho terminato la scansione. Se ho scannato tutte le porte del nodo A con 100 exit e' inutile che scarti questi
	100 exit. Mentre e' utile che scarti gli exit gia' usati per un nodo dove il count distinct delle porte e' 
	minore del numero di porte che devo scannare.
	"""
	
	# This is O(scary), but seems quick enough in practice.  
	print "-> Querying DB for discovering, and then filtering all used exit nodes",
	usedExits = db2.getUsedExitNodesDb(conn)         #ok
	usedExitsUnicode=[]
	
	# creo una lista decente sulla quale fare il filtro
	for i in usedExits:
		usedExitsUnicode.append(i[0])
	filteredExits=[a for a in exitLists if a[1] not in usedExitsUnicode ]	
	
	print "- ExitNodes was", len(exitLists), ", we got from DB ", len(usedExits), ", and now we have: ", len(filteredExits)
	#print "exitList"
	#print exitLists
	#print "usedExits"
	#print usedExits
	#print "filteredExits"
	#print filteredExits
	return filteredExits
	
def deleteExitpickledFiles():
	path = '/mnt/ramfs'
	for rmfile in glob.glob( os.path.join(path, '*.exits') ):
		os.remove(rmfile)         
	
	
#######################################
#######################################
############# START ###################
#    Autogenerated, do not edit.     ##
#    All changes will be undone.     ##
#######################################
#######################################

sys.stdout=Unbuffered(sys.stdout)
scanDate = datetime.datetime.fromtimestamp(time.time())
timestart =time.time()

#When I wrote this, only God and I understood what I was doing
#Now, God only knows
print "-> Start at ", scanDate, " [K]"


# Leggo la configurazione da un file di testo in formato .ini
# contiene le informazioni sull'accesso al db e su tor
#
configDic = getAndSetConfig() #k

# Configure tor for us
# Rimuovo tutti gli exit node impostati automaticamente
# e imposto i parametri in modo che non crei altri circuits
configTor(configDic["torportctl"], configDic["password"])


# Leggiamo da un file le porte da scannare
# Dovrebbero essere 120 circa
# Sono state selezionate da un file di nmap, ordinate per priorita'
port=getPortToScan() #k 
print "- The port is: ", port


# Connettiamoci al database
# Questo handle servira' successivamente per prendere
# informazioni che serviranno per decidere che cosa fare.
conn = db2.dbConnectz(configDic["db_host"],configDic["db_user"],configDic["db_pass"],configDic["db_name"])			#ok

# Capiamo quali sono gli host che in assoluto,
# dopo il nostro campionamento, sono meritevoli di scansione.
# I parametri sono impostabili nel file db2
relevantNodes=getRelevantNodes(conn)
if (len(relevantNodes)==0):
	sys.exit("[!] There are no relevant nodes to scan...")

	
# Istanzio un oggetto che servira' per prendere 
# tutte le decisioni necessarie alla scansione
#
obj=Logic() #k
	
# Scarico i nodi che sono attualmente attivi e connessi alla 
# rete tor, dal sito onionoo e le sue api json
# i dati sono all'interno dell'oggetto
obj.downlaodNodes_web() #k

# visto che siamo scarsissimi, con i nodi che abbiamo 
# scaricato dal web facciamo un dictionary per assicurarci 
# di avere i fingerprint che ci servono
assigndict=obj.createDictionary()
filename1="/mnt/ramfs/lookupdict"
output1 = open(filename1, "wb")
pickle.dump(assigndict, output1)

# Trovo l'intersezione tra l'insieme dei nodi attivi
# e dei nodi che devo scannare.
#
obj.filterRelevantAndPresent(relevantNodes) #k
	
# Creo una struttura dati che mi contiene gli ip 
# dei nodi da scannare, ai quali abbino la porta che
# ho deciso di scansionare in questo giro.
obj.cartesian(port)

# Verifico che, per questa determinata porta, in un intervallo di tempo
# deciso a priori, la porta non sia gia' stata scannata e salvata nel db.
# Eventualmente posso filtrare le porte con esito socks error 1
scannedComb = getAlreadyScannedComb(conn, port)		#ok

# dato tmp
tmp_oldLen=obj.getLenCombToScan()

# Filtro le porte che ho gia' scannato dalla struttura dati
# creata pochi passi prima.
#
obj.filterScannedComb(scannedComb)     # ok


print "- Cartesian product was: ", tmp_oldLen
print "- Scanned combination are: ", len(scannedComb)
print "- Cartesian product are: ", obj.getLenCombToScan()

# Se non ho nulla da fare chiudo.
#
#
if (obj.getLenCombToScan() <= 0):
	print "-> Skipping this port (already scanned this port for each host)"
	saveCurrentStatus(configDic)
	print "Exiting: [K]"
	sys.exit()
	

# Ora che so quali nodi devo raggiungere, mi assicuro 
# di poter uscire per degli exit node che me lo permettano
# e uso uno script esterno per poterlo fare.
exitRouteList=findExitRoute(obj.cartProd, configDic["varlibtor"], assigndict) 

# Elimino dalla lista di exitnode usabili
# quelli che ho gia' usato di recente, selezionandoli 
# dalle scansioni del database.
exitRouteListFiltered=filterUsedExitNodes(conn, exitRouteList)

# se non ho exit, chiudo
if (len(exitRouteListFiltered)<=0):
	print "[!] Non abbiamo exit node usabili: chiudo."
	sys.exit()


# this one returns the list of exit route selected (2)
# that must be pickled
topickle=setExitRoute(configDic["torportctl"], configDic['torportsock'],configDic["password"], exitRouteListFiltered,assigndict)

# se non ho settato un exit, chiudo
if (len(topickle)<=0):
	print "[!] Non abbiamo exit funzionanti testati, chiudo."
	sys.exit()



deleteExitpickledFiles()
filename1="/mnt/ramfs/my.exits"
output1 = open(filename1, "wb")
pickle.dump(topickle, output1)

		
print "Ip da scannare questo giro: ", len(obj.cartProd)

#fileExit="/mnt/ramfs/exit.node"
#outputExit = open(fileExit, "wb")
#pickle.dump(exitRouteListFiltered, outputExit)

print "-> Start serialization with: ", int(ceil(len(obj.cartProd)/30.)), "files"
for k in range(int(ceil(len(obj.cartProd)/30.))):
	iplist=obj.cartProd[0:30]
	del obj.cartProd[0:30]
	filename1="/mnt/ramfs/torscan"+str(k)+".todo"
	output1 = open(filename1, "wb")
	pickle.dump(iplist, output1)
	

saveCurrentStatus(configDic)
print "Exiting: [K]"
sys.exit()
