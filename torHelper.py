import urllib2
import pprint
import sys
import random
import Queue
import re
import socks
import time
from math import floor,ceil
import stem
import stem.connection
import stem.socket
from stem.control import Controller
import findexit
import datetime
import base64


from twisted.internet import reactor, defer
from twisted.internet.protocol import Protocol, Factory
from twisted.internet.endpoints import TCP4ClientEndpoint
from txsocksx.client import SOCKS5ClientEndpoint

import db2	
from logic import *


class SScan(Protocol):
    addr = ""
    port = ""
    scanDate=""
    currentlyExit=""
    internalConn=""
    portfForHTTPGet=[80,443,8080,2000]
    currentlyExit=""
    
    def connectionMade(self):
    	"""
    	Ok, we established a connection, now we have to save the results
    	or, if the port is 80,443,8080, make a get
		"""
    	#print "[K] Connect effettuata", self.port
    	self.factory.state="0 open"
    	if (self.port in self.portfForHTTPGet):
		self.transport.write("GET / HTTP/1.1\r\n\r\n")
    		#self.transport.write("GET /index.html HTTP/1.1\r\n\r\n")
	def	connectionLost(self, reason):
		"""
		Questa viene chiamata sse la connessione viene chiusa (implica che la connessione prima
		e' stata effettuata. Nel caso in cui 
		"""
		print "[:)] Connectionlost con reason: ", reason, self.addr, self.port

    		
    def buildProtocol(self):
        return self

    def dataReceived(self, data):
	#yep, i didn't had time to know how to do query properly, so fuck it!
    	self.factory.sockbuffer=base64.b64encode(data[:1024])

class SScanFactory(Factory):
	#Magic. Do not touch.
	def __init__(self, fingerprint, addr, port, scanDate, internalConn ):
		self.fp=fingerprint
		self.addr = addr
		self.port = int(port)
		self.scanDate = scanDate
		self.internalConn = internalConn
		self.state = ''
    
	def clientConnectionFailed(self, connector, reason):
		print "clientConnectionFailed inside factory"

	def buildProtocol(self,coso):
		#print "Eseguo il buildProtocol della factory con", self.addr
		p = SScan()
		p.addr = self.addr
		p.port = self.port
		p.scanDate= self.scanDate
		p.internalConn = self.internalConn
		p.factory=self
		return p


def _gotError(error, f):
    """
    In this case the port wont respond and the connection will have a timeout
    """          
    
    if ("errNumber" in dir(error.type)):
    	# I'm sorry.
    	#print "mmm sommethng went wrong"
    	if (error.type.errNumber==1):
    		f.state="1"
    	elif (error.type.errNumber==2):
     		f.state="2"
    	elif (error.type.errNumber==3):
    		f.state="3"
    	elif (error.type.errNumber==4):
    		f.state="4"   #host unreachable
    	elif (error.type.errNumber==5):
    		f.state="5"   #icmprefused/closed
    	elif (error.type.errNumber==6):
    		f.state="6"   # ttlexpired
    	elif (error.type.errNumber==7):
    		f.state="7"
    	elif (error.type.errNumber==8):
    		f.state="8"
    	elif (error.type.errNumber==9):
    		f.state="9"
    	elif (error.type.errNumber==10):
    		f.state="10"
    	else:
    		print "[!!!] txsocksx error unhandled", error.type.errNumber
    else:
    	print "[!!!] Another kind of strange error has occoured "
    	f.factory.state="???"
	return error

def checkCurrentIP(torportsock):
	ipPattern = re.compile('\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}')
	s = socks.socksocket()
	s.setproxy(socks.PROXY_TYPE_SOCKS5, '127.0.0.1', torportsock)
	s.connect(('checkip.dyndns.com', 80))
	message = "GET / HTTP/1.1\r\n\r\n"
	try :
		s.sendall(message)
	except socket.error:
		#sys.exit()				
		print "[!] Problem in getting ip from exitnode.."
	reply = s.recv(4096)
	foundIP = re.findall(ipPattern,reply)
	return foundIP

# drunk, fix later
def run(nodeScanList, scanDate, exitRouteList, configDic, dictionarylookup):
	internalConn = db2.dbConnectz(configDic["db_host"],configDic["db_user"],configDic["db_pass"],configDic["db_name"])		
	try:
		ipPre=checkCurrentIP(configDic["torportsock"])
		print "Scanning with ip", ipPre
	except Exception as e:
		print "[!!!] Error in checkdns ip ", e
		sys.exit(-1)

	du=[]
	dd=[]
	i=0
	TCPPoint = TCP4ClientEndpoint(reactor, "127.0.0.1", configDic["torportsock"])
	print "..:: Starting ::.."
	for dst_addr in nodeScanList:
		#tmp_string="Now I'm scanning:  "+dst_addr[1]+ ":"+dst_addr[2]+"\n"
		#sys.stdout.write(str(tmp_string))
		SOCKSPoint = SOCKS5ClientEndpoint(dst_addr[1], int(dst_addr[2]), TCPPoint)					
		f = SScanFactory(dst_addr[0], dst_addr[1], dst_addr[2], scanDate, internalConn)
		dd.append(f)
		du.append(SOCKSPoint.connect(f))
		du[i].addErrback(_gotError, f)
		i=i+1
	reactor.callLater(int(configDic['scantimeout']), reactor.stop)
	reactor.run() #installSignalHandlers=0

	ipPost=checkCurrentIP(configDic["torportsock"])
	
	# if i haven't changed ip
	if (ipPost==ipPre):
		print "- IP isn't changed during the scan: OK!"
		realIpPost=ipPost.pop()
		if (realIpPost in exitRouteList):
			print "- The ip we used is in the selected list, OK!"
			fingerprintExit=dictionarylookup[realIpPost]
			print "-> Saving data to db"
			for i in dd:
				i.currentlyExit=fingerprintExit
				db2.insertData(internalConn, i)
			return #ok
		else:
			print "[!] The ip is not in the exitrouteList!!!"
			return
	else:
		print "The exit route has changed during scan. Throw up all the results"
		sys.exit()

##############################################################################


@timeMeasure
def createTorInstance(toruser, instances, torPortSock, torPortCtl):
	print "-> Creating tor processes",
	# su debian-tor bash /opt/torLauncher.sh instances portsock portctl	
	tu=(toruser, instances, torPortSock, torPortCtl)
	formatString='/opt/torLauncher.sh {1} {2} {3} {0}'.format(*tu)
	print "(",formatString, " )" ,
	subprocess.call([formatString], shell=True)
	return 0
	


def sanitizeExitListElement(element, assigndict):
	print element
	tmp=element.split(":")
	exit=None
	exitstring=[]
	try:
		exit=assigndict[tmp[0]]
		#exitstring.append(exit)
		return (tmp[0],exit)
	except:
		return (-1,-1)

@timeMeasure
def setExitRoute(ctlport,portsock,torpassword, exitList, assigndict):
	try:	
		controller = Controller.from_port(address='127.0.0.1', port=9051)
		isauth=controller.authenticate(torpassword) # provide the password here if you set one
	except :
		print "[!!!] Error connecting to tor control port [!!!]"
		sys.exit()

	openCircuits = controller.get_circuits()
	for i in  openCircuits:              
		controller.close_circuit(i.id)
	print "+ Closed a lot of circuits"

	toSet=0
	loop=0
	tryThisExitFP=None
	while (toSet==0 and loop<100 and exitList): #pythonic way for empty lists	
		exitElement=random.choice(exitList)
		#(ip,tryThisExitFP)=sanitizeExitListElement(exitElement,assigndict)
		try:
			print"- Using as exitstring: ",  exitElement[1]
			controller.set_options({
			"ExitNodes":[exitElement[1]],
			"StrictNodes":"1"
			})
			time.sleep(3)
			print "check"
			ipPre=checkCurrentIP(portsock)
			print ipPre, "and", exitElement[0]
			toSet=1
		except Exception as e:
			print "[!!!] no, trying another ", e
			exitList.remove(exitElement)
			toSet=0
			loop=loop+1
	
		

	#topickle={}
	#topickle[ip]=exitElement[
	#print "topickle", topickle
	if (exitElement):
		return exitElement
	else:
		return []
	

@timeMeasure
def configTor(ctlport, torpassword):
	print "-> Configuring tor options: nick,dispredcirc,closingcircutis,etc..",
	try:
		control_socket = stem.socket.ControlPort(port = 9051)
		#print "porta impostata giusta"
	except stem.SocketError, exc:
		print "Unable to connect to port 9051 (%s)" % exc
		sys.exit(1)

	try:
		stem.connection.authenticate(control_socket)
		#print "connessione su socket ok"
	except stem.connection.IncorrectSocketType:
		print "Please check in your torrc that 9051 is the ControlPort."
		print "Maybe you configured it to be the ORPort or SocksPort instead?"
		sys.exit(1)
	except stem.connection.MissingPassword:
		controller_password = getpass.getpass("Controller password: ")
	
	try:
		stem.connection.authenticate_password(control_socket, "")
		#print "connessione ok password"
	except stem.connection.PasswordAuthFailed:
		print "Unable to authenticate, password is incorrect"
		sys.exit(1)
	except stem.connection.AuthenticationFailure, exc:
		print "Unable to authenticate: %s" % exc
		sys.exit(1)
	
	controller = Controller.from_port(address='127.0.0.1', port=9051)
	isauth=controller.authenticate(torpassword) # provide the password here if you set one
	
	# let's delete every other opened circuit
	openCircuits = controller.get_circuits()
	for i in  openCircuits: 
		controller.close_circuit(i.id)
	print "( ", len(openCircuits), " closed )",
	
	controller.set_options({
	"__DisablePredictedCircuits":"1",
	"Nickname":"Superagio",
	"MaxOnionsPending":"0",
	"newcircuitperiod":"999999999",
	"maxcircuitdirtiness":"999999999"
	})
              

@timeMeasure
def findExitRoute(i, varlibtor,assigndict):
	print "-> Finding ExitNode list",
	targetList=''

	for elem in i:
		targetList=targetList+" "+elem[1]

	resultsTmp=findexit.run(targetList, varlibtor)
	
	results=[]
	for result in resultsTmp:
		splitted=result.split(":")
		try:
			#print splitted[0]
			#print assigndict[splitted[0]]
			results.append((splitted[0],assigndict[splitted[0]]))
		except Exception as e:
			print "exception: could not find ip in assigndict", e
			
	
	#filteredResults=[]
	#for x in results:
	#	splitted=x.split(":")
	#	if splitted[1] != "Unnamed":
	#		filteredResults.append(x)
			
	
	return results
