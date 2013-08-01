#!/usr/bin/pyton
import simplejson
import MySQLdb
import urllib2
import json
import pprint
import sys
import random
import Queue
import threading
import time
import socket
import datetime


def dbConnectz(db_host, db_user, db_pass, db_name):
	print "-> Connecting to db",
	try:
		connz = MySQLdb.connect(db_host, db_user, db_pass,db_name)				#ok
	except Exception as x:
		print "[!] Could not connect to db: ", x
	print " [K]"
	return connz

def getScannedCombDb(conn, port):
	"""Connect to db and extract valid data:
	ip already scanned within 15 days
	that i'm goint to subtract to the whole combination of IP on a given port
	"""
	query="""SELECT * FROM results2 WHERE scandate > DATE_SUB(CURDATE(),INTERVAL 65 DAY) AND port = %s AND state != '1';"""
	cursore = conn.cursor()
	cursore.execute(query, [port])
	db_lista=cursore.fetchall()
	cursore.close()
	return db_lista
	
def getRelevantNodesDb(conn):
	"""
	Mi ritorna la lista di nodi rilevanti per la rete
	ovvero quelli che hanno un uptime medio maggiore di 3
	e che sono stati attivi per piu' di 15 giorni nell'ultimo mese 
	"""
	query="""SELECT * 
	FROM   (SELECT fp, 
               Sum(Timestampdiff(day, `last_restarted`, `maxscandate`)) AS 
               uptime, 
               Avg(Timestampdiff(day, `last_restarted`, `maxscandate`)) AS 
               average 
        FROM   (SELECT *, 
                       Max(scandate) AS MaxScanDate 
                FROM   torSample2 
                WHERE  `scandate` >= Date_sub(Curdate(), INTERVAL 60 day) 
                GROUP  BY Round(Unix_timestamp(`last_restarted`) / 10, -1), 
                          fp) AS correctTuple 
        GROUP  BY fp) AS filterMe 
        WHERE  uptime >= 45 AND average >= 20;"""     
	cursore = conn.cursor()
	cursore.execute(query)
	db_lista=cursore.fetchall()
	cursore.close()
	return db_lista
	
	
def getUsedExitNodesDb(conn):
	"""
	Mi dice quai nodi ho gia usato come exits in un intervallo di tempo ragionevole
	"""
	query="""SELECT DISTINCT exitNode FROM results2 WHERE scandate > DATE_SUB(CURDATE(),INTERVAL 15 DAY)"""
	cursore = conn.cursor()
	cursore.execute(query)
	db_lista=cursore.fetchall()
	cursore.close()
	return db_lista
	
	
def insertDataRaw(conn, fp, port, state, scandate, banner, usedExit ):
	"""
	fp,scandate,port,state,now(),banner
	"""
	query="""INSERT INTO results2 (fp,scandate,port,state,scantime,banner,exitNode) VALUES (%s, %s, %s, %s, NOW(), %s, %s);"""	
	cursore = conn.cursor()
	try:
		varlist= [fp, scandate, port, state, banner, usedExit]
		cursore.execute(query, varlist)
	except Exception as e:
		print "[!] Insertdata", e
		for row in cursore:
			print(row)
	cursore.close()	
	return 0	
	
def insertData(conn, f):
	if (hasattr(f, 'sockbuffer')):
			insertDataRaw(conn, f.fp, f.port, f.state, f.scanDate, f.sockbuffer, f.currentlyExit)
	else:
			insertDataRaw(conn, f.fp, f.port, f.state, f.scanDate, None, f.currentlyExit)
				
	
def insertSample2(conn,fp,scanDate,lastRestarted, platform):
	"""
	Questo fa parte della libreria del campionatore, non c'entra con lo scan!!! NON TOGLIERE
	"""
	query4="""INSERT INTO torSample2 (fp,scanDate,last_restarted,platform) VALUES (%s, %s, %s, %s);"""
	cursore=conn.cursor()
	
	try:
		varlist= [fp, scanDate, lastRestarted, platform]
		cursore.execute(query4, varlist)
	except Exception as e:
		print "\n Error inserting value: ", e
	cursore.close()	
	return 0
	
	
def insertPortUsed(conn,fp,or_addresses,dir_address):
        """
        Questo fa parte della libreria del campionatore, non c'entra con lo scan!!! NON TOGLIERE
        """
        query4="""INSERT INTO torPortUsed (fp,or_addresses,dir_address,timeinsert) VALUES (%s, %s, %s, NOW());"""
        cursore=conn.cursor()
        
        try:
                varlist= [fp, or_addresses,dir_address]
                cursore.execute(query4, varlist)
        except Exception as e:
                print "\n Error inserting value: ", e
        cursore.close()
        return 0	
	
	
	
	
	
	
	
	
