#!/usr/bin/pyton
# coding=<utf-8>

import simplejson
import urllib2
import json
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
import numpy
from IPy import IP

import db2	
from torHelper import *



def timeMeasure(function_to_decorate):
	result=""
	def a_wrapper_accepting_arbitrary_arguments(*args, **kwargs):
		d1=datetime.datetime.now()
		result=function_to_decorate(*args, **kwargs)
		d2=datetime.datetime.now()
		print "(", (d2-d1).seconds,"sec) [K]"
		return result
	return a_wrapper_accepting_arbitrary_arguments

class Logic:
	""" The class that contains all the logic of the program"""
	
	# Dear maintainer: 
	# Once you are done trying to 'optimize' this routine,
	# and have realized what a terrible mistake that was,
	# please increment the following counter as a warning
	# to the next guy:
	#
	# total_hours_wasted_here = 42
	
	# Indirizzo json dal quale grabbiamo tutte le info
	url = "https://onionoo.torproject.org/details?running=true"
	#url = "https://onionoo.torproject.org/details?search=hack"
	
	nodesWeb=[]
	relevantNodes=[]
	relevantAndPresent=[]
	cartProd=[]
	lenCartProd=''
	dictionaryAssociation={}
	
	torPortSockList=[]
	torPortCtlList=[]

	nodesWeb=''			# nodi da l'internet
	nodesRelevant=''			# nodi dal db rileventi
	relevantAndPresent=[]    #filterRelevantAndPresent
	nodesFiltered2=[]  # IP x porte - (IP x porte)scannati

	FpInScan=[]			# Nodi che sto correntemente scannando. Mi serve per questioni di operations per il mio algoritmo

	scanlists=[]		#
	workQueueList=[]# la vera e propria lista di code che uso per il lavoro sporco
	usedExitRoute=[] #lista per vedere quali ho gia scelto
	
	
	
	
	def __init__(self):
	    self.data = []
	    
	def comp_dates(d1, d2):
		# Date format: %Y-%m-%d %H:%M:%S
		return time.mktime(time.strptime(d2,"%Y-%m-%d %H:%M:%S"))-\
    	time.mktime(time.strptime(d1, "%Y-%m-%d %H:%M:%S"))
    	
	def getLenCombToScan(self):
		return len(self.cartProd)
		
	@timeMeasure
	def createDictionary(self):
		print "-> Creating associative dictionary 'ip' -> fp using onionoo",
		for i in self.nodesWeb['relays']:
			if i.has_key('exit_addresses'):
				for y in i['exit_addresses']:				
					self.dictionaryAssociation[y]=i['fingerprint']
			else:
				for y in i['or_addresses']:
					tmpIP=y.split(":")
					try:
						IP(tmpIP[0])
						self.dictionaryAssociation[tmpIP[0]]=i['fingerprint']
					except:
						# ipv6 stinks
						pass
		#pp = pprint.PrettyPrinter(depth=6)
		#pp.pprint(self.dictionaryAssociation)
		return self.dictionaryAssociation
		

	@timeMeasure
	def downlaodNodes_web(self):
		"""Scarichiamo da onionoo i dati da usare nella computazione"""
		print "-> Downloading current active nodes from ", self.url, 
		try:
			connection = urllib2.urlopen(self.url)
			data_raw=connection.read()
			data = json.loads(data_raw)
		except Exception as e:
			print ("[!] Errore nel download dei nodi: ", e)
			sys.exit()
		self.nodesWeb=data
		return 0
		
	@timeMeasure
	def filterRelevantAndPresent(self, relevantNodes):
		"""
		Calcola l'intersezione tra nodi online e nodi rilevanti
		In questo modo ottengo tutti i nodi online che sono anche rilevanti
		"""
		print "-> Finding interception between online nodes and relevant nodes",
		
		self.relevantNodes=relevantNodes
		dataReturn=[]
		datatmp=dict(self.nodesWeb)
		
		self.relevantAndPresent= [a for a in datatmp['relays'] for j in relevantNodes if a['fingerprint'].encode('ascii')==j[0].encode('ascii')]
				
		
		#print "- Nodes downloaded from the web are: ", len(self.nodesWeb['relays'])
		#print "- Nodes selected from the db are: ", len(self.relevantNodes)
		#print "- Nodes relevant AND present are: ", len(self.relevantAndPresent)		
		return 0
		

	@timeMeasure
	def cartProdSplitter(self, numinstances):
		tmp=numpy.array(self.cartProd)
		print "len cartprod",len(self.cartProd)
		print "numinstances", numinstances
		print "ceil roba", ceil(len(self.cartProd)/numinstances)
		print "roba nuova", numinstances*ceil(len(self.cartProd)/numinstances)
		reshaped=tmp.reshape(numinstances, ceil(len(self.cartProd)/numinstances))
		print reshaped
		print "reshaped in ", len(reshaped), " arary"
		return reshaped
	
	@timeMeasure
	def filterScannedComb(self,scannedComb):
		""" Mi toglie le tuple gia' registrate nel db da quelle che ho computato io """
		print "-> Filtering nodes again, with already scanned combination",
		
		for i in scannedComb:
			for j in self.cartProd:
				# cartesianFP == scannedFP && cartesianPORT == scannedPORT
				if ((i[1].encode('ascii') == j[0].encode('ascii')) and (str(i[3]) == j[2])):
					#print i[1], " - ", j[0], " | ", str(i[3]), " - ", j[2]	
					self.cartProd.remove(j)
		return 0
	
	
	def createQueue(self):	
		ipqueue=Queue.Queue(len(self.cartProd))
		# riempiamo la lista di code :)
		for i in self.cartProd:
			ipqueue.put(i)
		return ipqueue

	@timeMeasure
	def cartesian(self,port):
		""" Fa il prodotto cartesiano IP x Porta"""
		print "-> Creating  couple (IP,port) for ", len(self.relevantAndPresent), "hosts",
		d1=datetime.datetime.now()
		
		cartProd=[]	
		for i in self.relevantAndPresent:
			
			# in case we have more than one ip address, won't work with ip6			
			for x in i['or_addresses']:   
				tmpIP=x.split(":")
				# inserisco in una tupla (fingerprint, ip, porta)
				try:
					IP(tmpIP[0])
					couple=(i['fingerprint'], tmpIP[0].encode('ascii'), port)
					cartProd.append(couple)
				except:
					# beccato n'ipv6 
					pass
		self.cartProd=cartProd
		return 0
