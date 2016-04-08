import os, csv, dpkt, datetime, socket, re

from lib.cuckoo.common.abstracts import Report
from lib.cuckoo.common.exceptions import CuckooReportError

# python-stix
import stix.utils as utils
from stix.core import STIXPackage, STIXHeader 
from stix.indicator import Indicator
from stix.report import Header
from stix.report import Report as stixReport
from stix.common import InformationSource

# TODO http://stixproject.github.io/documentation/idioms/snort-test-mechanism/
# The test_mechanism is part of the indicator

# TODO add UPD, add record type of DNS query, add whole http request

# python-cybox
# http://cyboxproject.github.io/documentation/objects/

# DNS
from cybox.core import *
from cybox.objects.dns_query_object import DNSQuery, DNSQuestion, DNSResourceRecords
from cybox.objects.dns_record_object import DNSRecord
from cybox.objects.domain_name_object import DomainName

# HTTP
from cybox.objects.http_session_object import *
from cybox.objects.uri_object import URI

# Network Connection
from cybox.objects.network_connection_object import NetworkConnection, Layer7Connections
from cybox.objects.socket_address_object import SocketAddress
from cybox.objects.port_object import Port

# IP Address etc
from cybox.objects.address_object import Address


VMIP = "146.231.133.174"

class IOC_STIX(Report):
	def run(self, results):		
		try:
			#print "Start of IOC_STIX reporting module\n"+results
			pcapFile = dpkt.pcap.Reader(file(self.analysis_path+"/cut-byprocessingmodule.pcap"))
			goodIPs = getMicrosoftDomains(self.analysis_path)
			synConn = getSYNInfo(self.analysis_path, goodIPs)
			synackconn = getSYNACKInfo(self.analysis_path, goodIPs)
			ackConn = getACKInfo(self.analysis_path, goodIPs)
			resolvedIPsArray = resolvedIPs(self.analysis_path, goodIPs)
			fullHTTPArray = getFullHTTP(self.analysis_path)
			udpconn = getUDPData(self.analysis_path, goodIPs)
			dnspacket = getDNSData(self.analysis_path)
			icmpPacket = getICMPData(self.analysis_path)
			ftpconn = getFTPConn(self.analysis_path)
			sshconn = getSSHConn(self.analysis_path)
			#foundIPs = findStaticIPs(results["strings"])			
			if synConn!=[] or synackconn!=[] or ackConn!=[] or resolvedIPsArray!=[] or fullHTTPArray!=[] or udpconn!=[] or dnspacket!=[] or icmpPacket!=[] or ftpconn!=[] or sshconn!=[]:# or foundIPs!=[]:
				gatherIOCs(self.analysis_path, synConn, synackconn, ackConn, resolvedIPsArray, results, fullHTTPArray, udpconn, dnspacket, icmpPacket, ftpconn, sshconn) #, foundIPs)
			else:
				print "No IOCs to create"
			
        	except (UnicodeError, TypeError, IOError) as e:
			print "Error", e
            		raise CuckooReportError("Failed to make STIX IOCs :(")
		return True



def findStaticIPs(stringlist):
	arrayofIPs = []
	for i in stringlist:
		if i != []:
			if valid_ip(i):
				arrayofIPs.append(getIP(i))
				print "Found: ", i
	return arrayofIPs


def valid_ip(address):
	regex = re.findall(r'(?:[\d]{1,3})\.(?:[\d]{1,3})\.(?:[\d]{1,3})\.(?:[\d]{1,3})$', address)
	#print "May be wrong, Found:      -------------------- >         ", address, regex	
	if regex != []:
		#print "Found in IP", regex
		return True
	else:
		return False

def getIP(string):
	return re.findall(r'(?:[\d]{1,3})\.(?:[\d]{1,3})\.(?:[\d]{1,3})\.(?:[\d]{1,3})$', string)

def getMicrosoftDomains(folderPath):
	os.system("tshark -r "+folderPath+"/dump.pcap -Y dns.flags.response==1 -T fields -e dns.qry.name -e dns.a -E separator=, > "+folderPath+"/microDomains-SUS-IPs.csv")
	niceIPs = []
	with open(folderPath+"/microDomains-SUS-IPs.csv", 'rb') as csvfile:
		summaryCSV = csv.reader(csvfile, delimiter=',')
		for row in summaryCSV:			
			if row!=[]:
				if row[0].endswith("microsoft.com") or row[0].endswith("windowsupdate.com") or row[0].endswith("trafficmanager.net") or row[0].endswith("msocsp.com") or row[0].endswith("gvt1.com") or row[0].endswith("verisign.com") or row[0].endswith("windows.com"): # to be extra sure no goo traffic gets through
					#print "Row after", row
					for ips in row:
						if valid_ip(ips) and ips not in niceIPs:
							niceIPs.append(ips)
	#print "Good IPs", niceIPs
	return niceIPs    

# SSH
# source IP, source port, destination address, destination port
# https://www.wireshark.org/docs/dfref/s/ssh.html
def getSSHConn(folderPath):
	#print "getSSHConn"
	os.system('tshark -r '+folderPath+'/cut-byprocessingmodule.pcap -w '+folderPath+'/SSHpackets.pcap -F pcap -Y ssh -T fields -e ip.src -e tcp.srcport -e ip.dst -e tcp.dstport -e tcp.flags.syn -e tcp.flags.ack -e ssh.kexdh.host_key -E separator=, > '+folderPath+'/SSHInfo.csv')
	sshpacket = []
	with open(folderPath+"/SSHInfo.csv", 'rb') as csvfile:
		summaryCSVSSH = csv.reader(csvfile, delimiter=',')
		for row in summaryCSVSSH:
			if row != [] and row not in sshpacket:
				sshpacket.append(row)
	return sshpacket

# FTP
# source IP, source port, destination address, destination port
def getFTPConn(folderPath):
	#print "getFTPConn"
	os.system('tshark -r '+folderPath+'/cut-byprocessingmodule.pcap -w '+folderPath+'/FTPpackets.pcap -F pcap -Y ftp -T fields -e ip.src -e tcp.srcport -e ip.dst -e tcp.dstport -e ftp.response.code -e ftp.request.command -e ftp.request.arg -e ftp.response.arg -E separator=, > '+folderPath+'/FTPInfo.csv')
	FTPpacket = []
	with open(folderPath+"/FTPInfo.csv", 'rb') as csvfile:
		summaryCSVFTP = csv.reader(csvfile, delimiter=',')
		for row in summaryCSVFTP:
			if row != [] and row not in FTPpacket:
				FTPpacket.append(row)
	return FTPpacket

# ICMP
# source and destination address, type 
def getICMPData(folderPath):
	#print "getICMPData"
	os.system('tshark -r '+folderPath+'/cut-byprocessingmodule.pcap -w '+folderPath+'/icmppackets.pcap -F pcap -Y icmp -T fields -e icmp.type -e ip.src -e ip.dst -E separator=, > '+folderPath+'/ICMPInfo.csv')
	ICMPpacket = []
	with open(folderPath+"/ICMPInfo.csv", 'rb') as csvfile:
		summaryCSVICMP = csv.reader(csvfile, delimiter=',')
		for row in summaryCSVICMP:
			if row != [] and row not in ICMPpacket:
				ICMPpacket.append(row)
	return ICMPpacket


# source port, destination port, destination ip
# https://www.wireshark.org/docs/dfref/u/udp.html
def getUDPData(folderPath, goodIPs):
	#print "getUDPData"
	os.system('tshark -r '+folderPath+'/cut-byprocessingmodule.pcap -w '+folderPath+'/UDPpackets.pcap -F pcap -Y udp -T fields -e udp.srcport -e udp.dstport -e ip.dst -e ip.src -E separator=, > '+folderPath+'/UDPInfo.csv')
	udppacket = []
	with open(folderPath+"/UDPInfo.csv", 'rb') as csvfile:
		summaryCSVUDP = csv.reader(csvfile, delimiter=',')
		for row in summaryCSVUDP:
			if row != [] and row not in udppacket and (row[2] not in goodIPs) and (row[3] not in goodIPs):
				udppacket.append(row)
	return udppacket

def getDNSData(folderPath):
	#print "getDNSData"
	os.system('tshark -r'+folderPath+'/cut-byprocessingmodule.pcap -w '+folderPath+'/DNSpackets.pcap -F pcap -Y dns.flags.response==0 -T fields -e ip.src -e udp.srcport -e ip.dst -e udp.dstport -e dns.qry.name -e dns.qry.type -e dns.flags.response -E separator=~ > '+folderPath+'/DNSInfo.csv')
	# -e dns.resp.name -e dns.resp.ttl -e dns.resp.type -e dns.a -e dns.flags.response -E separator=~ > '+folderPath+'/DNSInfo.csv')
	dnspacket = []
	with open(folderPath+"/DNSInfo.csv", 'rb') as csvfile:
		summaryCSVDNS = csv.reader(csvfile, delimiter='~')
		for row in summaryCSVDNS:
			print 'row[4].endswith("microsoft.com")', row[4].endswith("microsoft.com"), row[4]
			if row != [] and row not in dnspacket and not row[4].endswith("microsoft.com") and not row[4].endswith("windowsupdate.com"):
				dnspacket.append(row)
	return dnspacket


def getFullHTTP(folderPath):
	#print "getFullHTTP"
	comm = 'tshark -r '+folderPath+'/cut-byprocessingmodule.pcap -w '+folderPath+'/HTTPGETpackets.pcap -F pcap -Y http.request.method=="GET" -T fields -e http.request.method -e http.request.uri -e http.request.version -e tcp.dstport -e http.accept -e http.accept_language -e http.accept_encoding -e http.authorization -e http.cache_control -e http.connection -e http.cookie -e http.content_length -e http.content_type -e http.date -e http.host -e http.proxy_authorization -E separator=~ > '+folderPath+'/HTTPFullGET.csv'	
	os.system(comm)
	comm2 = 'tshark -r '+folderPath+'/cut-byprocessingmodule.pcap -w '+folderPath+'/HTTPPOSTpackets.pcap -F pcap -Y http.request.method=="POST" -T fields -e http.request.method -e http.request.uri -e http.request.version -e tcp.dstport -e http.accept -e http.accept_language -e http.accept_encoding -e http.authorization -e http.cache_control -e http.connection -e http.cookie -e http.content_length -e http.content_type -e http.date -e http.host -e http.proxy_authorization -E separator=~ > '+folderPath+'/HTTPFullPOST.csv'		
	os.system(comm2)
	HTTPfull = []
	with open(folderPath+"/HTTPFullGET.csv", 'rb') as csvfile:
		summaryCSV = csv.reader(csvfile, delimiter='~')
		for row in summaryCSV:
			if row != [] and not row[14].endswith("windowsupdate.com"):
				HTTPfull.append(row)
	with open(folderPath+"/HTTPFullPOST.csv", 'rb') as csvfile:
		summaryCSV = csv.reader(csvfile, delimiter='~')
		for row in summaryCSV:
			if row != []:
				HTTPfull.append(row)
	return HTTPfull


def getSYNInfo(folderPath, goodIPs):
	#print "getSYNInfo"
	os.system("tshark -r "+folderPath+"/cut-byprocessingmodule.pcap -w "+folderPath+"/TCPSYN.pcap -F pcap -Y 'tcp.flags.syn==1 and tcp.flags.ack==0 and tcp.flags.cwr==0 and tcp.flags.ecn==0 and tcp.flags.fin==0 and tcp.flags.ns==0 and tcp.flags.push==0 and tcp.flags.res==0 and tcp.flags.reset==0 and tcp.flags.urg==0' -T fields -e ip.src -e ip.dst -e tcp.srcport -e tcp.dstport -E separator=, > "+folderPath+"/SYNConn.csv")
	dstIPArray = []
	with open(folderPath+"/SYNConn.csv", 'rb') as csvfile:
		summaryCSV = csv.reader(csvfile, delimiter=',')
		for row in summaryCSV:
			print row
			if (tuple(row) not in dstIPArray) and row[0] not in goodIPs and row[1] not in goodIPs:
				dstIPArray.append(tuple(row))
	#print "SYN", dstIPArray
	return dstIPArray

def getSYNACKInfo(folderPath, goodIPs):	
	#print "getSYNACKInfo"
	os.system("tshark -r "+folderPath+"/cut-byprocessingmodule.pcap -w "+folderPath+"/TCPSYNACK.pcap -F pcap -Y 'tcp.flags.syn==1 and tcp.flags.ack==1 and tcp.flags.cwr==0 and tcp.flags.ecn==0 and tcp.flags.fin==0 and tcp.flags.ns==0 and tcp.flags.push==0 and tcp.flags.res==0 and tcp.flags.reset==0 and tcp.flags.urg==0' -T fields -e ip.dst -e ip.src -e tcp.dstport -e tcp.srcport -E separator=, > "+folderPath+"/SYNACKConn.csv")	
	dstIPArray = []
	with open(folderPath+"/SYNACKConn.csv", 'rb') as csvfile:
		summaryCSV = csv.reader(csvfile, delimiter=',')
		for row in summaryCSV:
			if (tuple(row) not in dstIPArray) and row[0] not in goodIPs and row[1] not in goodIPs:
				dstIPArray.append(tuple(row))
	#print "SYN-ACK", dstIPArray
	return dstIPArray

def getACKInfo(folderPath, goodIPs):
	#print "getACKInfo"
	os.system("tshark -r "+folderPath+"/cut-byprocessingmodule.pcap -w "+folderPath+"/TCPACK.pcap -F pcap -Y 'tcp.flags.syn==0 and tcp.flags.ack==1 and tcp.flags.cwr==0 and tcp.flags.ecn==0 and tcp.flags.fin==0 and tcp.flags.ns==0 and tcp.flags.push==0 and tcp.flags.res==0 and tcp.flags.reset==0 and tcp.flags.urg==0' -T fields -e ip.src -e ip.dst -e tcp.srcport -e tcp.dstport -E separator=, > "+folderPath+"/ACKConn.csv")
	dstIPArray = []
	with open(folderPath+"/ACKConn.csv", 'rb') as csvfile:
		summaryCSV = csv.reader(csvfile, delimiter=',')
		for row in summaryCSV:
			if (tuple(row) not in dstIPArray) and row[0] not in goodIPs and row[1] not in goodIPs:
				dstIPArray.append(tuple(row))
	#print "ACK", dstIPArray
	return dstIPArray

def resolvedIPs(folderPath, goodIPs):
	#print "resolvedIPs"
	
	os.system("tshark -r "+folderPath+"/cut-byprocessingmodule.pcap -Y dns.flags.response==1 -T fields -e dns.qry.name -e dns.a -E separator=, > "+folderPath+"/domains-SUS-IPs.csv")
	susResolvedIPArray = []
	with open(folderPath+"/domains-SUS-IPs.csv", 'rb') as csvfile:
		summaryCSV = csv.reader(csvfile, delimiter=',')
		for row in summaryCSV:
			if row != []:
				if not row[0].endswith("microsoft.com") and not row[0].endswith("windowsupdate.com"):
					for i in row:
						#print "Resolved IPs", i
						if valid_ip(i) and i not in goodIPs:				
							#print "IP: -> ", i
							susResolvedIPArray.append(i)
	return removeDuplicates(susResolvedIPArray)

def domainNameobj(domain):
	#print "DomainObj"
	# cybox stuff
	d = DomainName()
	d.value = domain
	# stix stuff
	indicator1 = Indicator()
    	indicator1.title = "Domain name"
    	indicator1.description = ("An indicator containing a suspicious domain name")
	indicator1.set_produced_time(utils.dates.now())
	indicator1.add_object(d)
	return indicator1

#def URIobj(httpR):
#	h = URI()
#	h.value = str(httpR) 
#	indicator = Indicator()
#   	indicator.title = "URI"
#    	indicator.description = ("An indicator containing a suspicious URI")
#	indicator.set_produced_time(utils.dates.now())
#	indicator.add_object(h)
#	return indicator

def HTTPFullObj(http):
	#print "HTTPFullObj"
	httprequestline = HTTPRequestLine()
	httprequestline.http_method = http[0]
	httprequestline.value = http[1]
	httprequestline.version = http[2]
	hostfield = HostField()
	h = URI()
	h.value = str(http[14])
	hostfield.domain_name = h
	port = Port()
	port.port_value = http[3]
	hostfield.port = port
	httprequestheaderfields = HTTPRequestHeaderFields()
	if http[4] != '':										
		httprequestheaderfields.accept = http[4]
	if http[5] != '':									
		httprequestheaderfields.accept_language = http[5]
	if http[6] != '':										
		httprequestheaderfields.accept_encoding = http[6]	
	if http[7] != '':										
		httprequestheaderfields.authorization = http[7]
	if http[8] != '':										
		httprequestheaderfields.cache_control = http[8]
	if http[9] != '':									
		httprequestheaderfields.connection = http[9]	
	if http[10] != '':										
		httprequestheaderfields.cookie = http[10]	
	if http[11] != '':										
		httprequestheaderfields.content_length = http[11] # integer	
	if http[12] != '':										
		httprequestheaderfields.content_type = http[12]	
	if http[13] != '':										
		httprequestheaderfields.date = http[13] # datetime
	if http[14] != '':						
		httprequestheaderfields.host = hostfield
	if http[15] != '':										
		httprequestheaderfields.proxy_authorization = http[15]
	httprequestheader = HTTPRequestHeader()
	httprequestheader.parsed_header = httprequestheaderfields
	#httpmessage = HTTPMessage()
	#httpmessage.length = len(http.body)
	#httpmessage.message_body = http.body
	httpclientrequest = HTTPClientRequest()
	httpclientrequest.http_request_line = httprequestline
	httpclientrequest.http_request_header = httprequestheader
	#httpclientrequest.http_message_body = httpmessage
	
	http_request_response = HTTPRequestResponse()
	http_request_response.http_client_request = httpclientrequest
	
	httpsession = HTTPSession()	
	httpsession.http_request_response = http_request_response	
	#print "Still in http obj, almost done"
	indicator = Indicator()
    	indicator.title = "HTTP request"
    	indicator.description = ("An indicator containing information about a HTTP request")
	indicator.set_produced_time(utils.dates.now())
	indicator.add_object(httpsession)
	return indicator

# source IP, source port, destination address, destination port
def TCPConnectionAttemptFailedObj(tcpinfo):
	#print "TCPConnectionAttemptFailedObj"
	networkconnection = NetworkConnection()
	networkconnection.layer3_protocol = "IPv4"
	networkconnection.layer4_protocol = "TCP"
	if tcpinfo[0] != VMIP: # incoming connection
		ssocketaddress = SocketAddress()
		ssocketaddress.ip_address = tcpinfo[0]
		sport = Port()
		sport.port_value = tcpinfo[2]
		sport.layer4_protocol = "TCP"
		ssocketaddress.port = sport
		networkconnection.source_socket_address = ssocketaddress
	elif tcpinfo[1] != VMIP: # outgoing connection
		dsocketaddress = SocketAddress()
		dsocketaddress.ip_address = tcpinfo[1]
		dport = Port()
		dport.port_value = tcpinfo[3]
		dport.layer4_protocol = "TCP"
		dsocketaddress.port = dport
		networkconnection.destination_socket_address = dsocketaddress
	indicator = Indicator()
    	indicator.title = "TCP Connection Fail"
    	indicator.description = ("An indicator containing information about a failed TCP hand shake")
	indicator.set_produced_time(utils.dates.now())
	indicator.add_object(networkconnection)
	return indicator

# source IP, source port, destination address, destination port
def TCPConnectionEstablishedObj(tcpinfo):
	#print "TCPConnectionEstablishedObj"
	networkconnection = NetworkConnection()
	networkconnection.layer3_protocol = "IPv4"
	networkconnection.layer4_protocol = "TCP"
	if tcpinfo[0] != VMIP: # incoming connection
		ssocketaddress = SocketAddress()
		ssocketaddress.ip_address = tcpinfo[0]
		sport = Port()
		sport.port_value = tcpinfo[2]
		sport.layer4_protocol = "TCP"
		ssocketaddress.port = sport
		networkconnection.source_socket_address = ssocketaddress
	elif tcpinfo[1] != VMIP: # outgoing connection
		dsocketaddress = SocketAddress()
		dsocketaddress.ip_address = tcpinfo[1]
		dport = Port()
		dport.port_value = tcpinfo[3]
		dport.layer4_protocol = "TCP"
		dsocketaddress.port = dport
		networkconnection.destination_socket_address = dsocketaddress
	indicator = Indicator()
    	indicator.title = "TCP Connection Established"
    	indicator.description = ("An indicator containing information about a successful TCP hand shake")
	indicator.set_produced_time(utils.dates.now())
	indicator.add_object(networkconnection)
	return indicator

# source port, destination port, destination ip, source ip
def UDPRequestObj(udpinfo):
	#print "UDPRequestObj"
	#print "In UDP Object"
	u = NetworkConnection()
	u.layer3_protocol = "IPv4"
	u.layer4_protocol = "UDP"
	ssocketaddress = SocketAddress()
	if udpinfo[3] != VMIP:
		ssocketaddress.ip_address = udpinfo[3]
		sport = Port()
		sport.port_value = udpinfo[0]
		sport.layer4_protocol = "UDP"
		ssocketaddress.port = sport
		u.source_socket_address = ssocketaddress		
	dsocketaddress = SocketAddress()
	if udpinfo[2] != VMIP:
		dsocketaddress.ip_address = udpinfo[2]
		dport = Port()
		dport.port_value = udpinfo[1]
		dport.layer4_protocol = "UDP"
		dsocketaddress.port = dport
		u.destination_socket_address = dsocketaddress
	indicator = Indicator()
    	indicator.title = "UDP connection"
    	indicator.description = ("An indicator containing information about a UDP connection")
	indicator.set_produced_time(utils.dates.now())
	indicator.add_object(u)
	return indicator



#-e ip.src -e udp.srcport -e ip.dst -e udp.dstport -e dns.qry.name -e dns.qry.type -e dns.flags.response	
def DNSRequestObj(dnsinfo): 
	#print "DNSRequestObj"
	networkconnection = NetworkConnection()
	networkconnection.layer3_protocol = "IPv4"
	networkconnection.layer4_protocol = "UDP"
	networkconnection.layer7_protocol = "DNS"
	ssocketaddress = SocketAddress()
	sport = Port()
	sport.port_value = dnsinfo[1]
	sport.layer4_protocol = "UDP"
	ssocketaddress.port = sport
	networkconnection.source_socket_address = ssocketaddress
	dsocketaddress = SocketAddress()
	dsocketaddress.ip_address = dnsinfo[2]
	dport = Port()
	dport.port_value = dnsinfo[3]
	dport.layer4_protocol = "UDP"
	dsocketaddress.port = dport
	networkconnection.destination_socket_address = dsocketaddress
	layer7connections = Layer7Connections()
	dqr = DNSQuery()
	indicator = Indicator()  
	dnsques = DNSQuestion()
	dnsques.qname = dnsinfo[4]
	dnsques.qtype = translateType(dnsinfo[5])
	dqr.question = dnsques
	indicator.title = "DNS Request"
	indicator.description = ("An indicator containing information about a DNS Request")	
	layer7connections.dns_query = dqr
	networkconnection.layer7_connections = layer7connections    	
	indicator.set_produced_time(utils.dates.now())
	indicator.add_object(networkconnection)
	return indicator

# type, source address, destination address
def ICMPObj(icmp):
	#print "ICMPObj"
	# block types 0 (ping response), 8 (ping request)
	nc = NetworkConnection()
	indicator = Indicator()
	nc.layer3_protocol = "ICMP"
	if icmp[0] == 0: # echo-reply
		if icmp[1]!=VMIP: 	# incoming reply from a server VM pinged
			ssocketaddress = SocketAddress()
			ssocketaddress.ip_address = icmp[1]
			nc.source_socket_address = ssocketaddress			
			indicator.title = "ICMP echo-reply"
    			indicator.description = ("8")
		else:			# outgoing reply to a server that pinged you
			dsocketaddress = SocketAddress()
			dsocketaddress.ip_address = icmp[2]
			nc.destination_socket_address = dsocketaddress
			indicator.title = "ICMP echo-reply"
    			indicator.description = ("8")
	elif icmp[0] ==  8: # echo-request
		if icmp[1]!=VMIP: 	# incoming ping request from a server
			ssocketaddress = SocketAddress()
			ssocketaddress.ip_address = icmp[1]
			nc.source_socket_address = ssocketaddress
			indicator.title = "ICMP echo-request"
    			indicator.description = ("0")
		else:			# VM is sending a ping request
			dsocketaddress = SocketAddress()
			dsocketaddress.ip_address = icmp[2]
			nc.destination_socket_address = dsocketaddress
		    	indicator.title = "ICMP echo-request"
    			indicator.description = ("0")
	indicator.set_produced_time(utils.dates.now())
	indicator.add_object(nc)
	return indicator

# ip.src, tcp.srcport, ip.dst, tcp.dstport, ftp.response.code, ftp.request.command, ftp.request.arg, ftp.response.arg
# https://en.wikipedia.org/wiki/List_of_FTP_commands
def FTPObj(ftp):
	#print "FTPObj"
	networkconnection = NetworkConnection()
	networkconnection.layer3_protocol = "IPv4"
	networkconnection.layer4_protocol = "TCP"
	networkconnection.layer7_protocol = "FTP"
	indicator = Indicator()
	if ftp[4] == '220':
		if ftp[0] != VMIP: # incoming connection
			ssocketaddress = SocketAddress()
			ssocketaddress.ip_address = ftp[0]
			sport = Port()
			sport.port_value = ftp[1]
			sport.layer4_protocol = "TCP"
			ssocketaddress.port = sport
			networkconnection.source_socket_address = ssocketaddress
		elif ftp[2] != VMIP: # outgoing connection
			dsocketaddress = SocketAddress()
			dsocketaddress.ip_address = ftp[2]
			dport = Port()
			dport.port_value = ftp[3]
			dport.layer4_protocol = "TCP"
			dsocketaddress.port = dport
			networkconnection.destination_socket_address = dsocketaddress
		indicator.title = "FTP"
    		indicator.description = ("Service ready for new user: "+ftp[7])
		indicator.set_produced_time(utils.dates.now())
		indicator.add_object(networkconnection)
		return indicator
	elif ftp[4] == '230':
		if ftp[0] != VMIP: # incoming connection
			ssocketaddress = SocketAddress()
			ssocketaddress.ip_address = ftp[0]
			sport = Port()
			sport.port_value = ftp[1]
			sport.layer4_protocol = "TCP"
			ssocketaddress.port = sport
			networkconnection.source_socket_address = ssocketaddress
		elif ftp[2] != VMIP: # outgoing connection
			dsocketaddress = SocketAddress()
			dsocketaddress.ip_address = ftp[2]
			dport = Port()
			dport.port_value = ftp[3]
			dport.layer4_protocol = "TCP"
			dsocketaddress.port = dport
			networkconnection.destination_socket_address = dsocketaddress
		indicator.title = "FTP"
    		indicator.description = ("User logged in")
		indicator.set_produced_time(utils.dates.now())
		indicator.add_object(networkconnection)
		return indicator
	elif ftp[4] == '250':
		if ftp[0] != VMIP: # incoming connection
			ssocketaddress = SocketAddress()
			ssocketaddress.ip_address = ftp[0]
			sport = Port()
			sport.port_value = ftp[1]
			sport.layer4_protocol = "TCP"
			ssocketaddress.port = sport
			networkconnection.source_socket_address = ssocketaddress
		elif ftp[2] != VMIP: # outgoing connection
			dsocketaddress = SocketAddress()
			dsocketaddress.ip_address = ftp[2]
			dport = Port()
			dport.port_value = ftp[3]
			dport.layer4_protocol = "TCP"
			dsocketaddress.port = dport
			networkconnection.destination_socket_address = dsocketaddress
		indicator.title = "FTP"
    		indicator.description = ("Requested file action okay, completed.")    
		indicator.set_produced_time(utils.dates.now())
		indicator.add_object(networkconnection)
		return indicator
	elif ftp[5] == "USER":
		if ftp[0] != VMIP: # incoming connection
			ssocketaddress = SocketAddress()
			ssocketaddress.ip_address = ftp[0]
			sport = Port()
			sport.port_value = ftp[1]
			sport.layer4_protocol = "TCP"
			ssocketaddress.port = sport
			networkconnection.source_socket_address = ssocketaddress
		elif ftp[2] != VMIP: # outgoing connection
			dsocketaddress = SocketAddress()
			dsocketaddress.ip_address = ftp[2]
			dport = Port()
			dport.port_value = ftp[3]
			dport.layer4_protocol = "TCP"
			dsocketaddress.port = dport
			networkconnection.destination_socket_address = dsocketaddress
		indicator.title = "FTP"
    		indicator.description = ("Requested username: "+ftp[6])    
		indicator.set_produced_time(utils.dates.now())
		indicator.add_object(networkconnection)
		return indicator
	elif ftp[5] == "PASS":
		if ftp[0] != VMIP: # incoming connection
			ssocketaddress = SocketAddress()
			ssocketaddress.ip_address = ftp[0]
			sport = Port()
			sport.port_value = ftp[1]
			sport.layer4_protocol = "TCP"
			ssocketaddress.port = sport
			networkconnection.source_socket_address = ssocketaddress
		elif ftp[2] != VMIP: # outgoing connection
			dsocketaddress = SocketAddress()
			dsocketaddress.ip_address = ftp[2]
			dport = Port()
			dport.port_value = ftp[3]
			dport.layer4_protocol = "TCP"
			dsocketaddress.port = dport
			networkconnection.destination_socket_address = dsocketaddress
		indicator.title = "FTP"
    		indicator.description = ("Requested Password: "+ftp[6])    
		indicator.set_produced_time(utils.dates.now())
		indicator.add_object(networkconnection)
		return indicator
	elif ftp[5] == "STOR":
		if ftp[0] != VMIP: # incoming connection
			ssocketaddress = SocketAddress()
			ssocketaddress.ip_address = ftp[0]
			sport = Port()
			sport.port_value = ftp[1]
			sport.layer4_protocol = "TCP"
			ssocketaddress.port = sport
			networkconnection.source_socket_address = ssocketaddress
		elif ftp[2] != VMIP: # outgoing connection
			dsocketaddress = SocketAddress()
			dsocketaddress.ip_address = ftp[2]
			dport = Port()
			dport.port_value = ftp[3]
			dport.layer4_protocol = "TCP"
			dsocketaddress.port = dport
			networkconnection.destination_socket_address = dsocketaddress
		indicator.title = "FTP"
    		indicator.description = ("Upload file to server: "+ftp[6])    
		indicator.set_produced_time(utils.dates.now())
		indicator.add_object(networkconnection)
		return indicator
	elif ftp[5]=="RETR":
		if ftp[0] != VMIP: # incoming connection
			ssocketaddress = SocketAddress()
			ssocketaddress.ip_address = ftp[0]
			sport = Port()
			sport.port_value = ftp[1]
			sport.layer4_protocol = "TCP"
			ssocketaddress.port = sport
			networkconnection.source_socket_address = ssocketaddress
		elif ftp[2] != VMIP: # outgoing connection
			dsocketaddress = SocketAddress()
			dsocketaddress.ip_address = ftp[2]
			dport = Port()
			dport.port_value = ftp[3]
			dport.layer4_protocol = "TCP"
			dsocketaddress.port = dport
			networkconnection.destination_socket_address = dsocketaddress
		indicator.title = "FTP"
    		indicator.description = ("Retrieve a copy of the file: "+ftp[6])    
		indicator.set_produced_time(utils.dates.now())
		indicator.add_object(networkconnection)
		return indicator

	

# source IP, source port, destination address, destination port
def SSHObj(SSH):
	#print "SSHObj"
	networkconnection = NetworkConnection()
	networkconnection.layer3_protocol = "IPv4"
	networkconnection.layer4_protocol = "TCP"
	networkconnection.layer7_protocol = "SSH"
	if SSH[0] != VMIP and SSH[4]==1 and SSH[5]==0: # incoming connection
		ssocketaddress = SocketAddress()
		ssocketaddress.ip_address = SSH[0]
		sport = Port()
		sport.port_value = SSH[1]
		sport.layer4_protocol = "TCP"
		ssocketaddress.port = sport
		networkconnection.source_socket_address = ssocketaddress
	elif SSH[2] != VMIP and SSH[4]==1 and SSH[5]==0: # outgoing connection
		dsocketaddress = SocketAddress()
		dsocketaddress.ip_address = SSH[2]
		dport = Port()
		dport.port_value = SSH[3]
		dport.layer4_protocol = "TCP"
		dsocketaddress.port = dport
		networkconnection.destination_socket_address = dsocketaddress
	indicator = Indicator()
	if SSH[6] != '':
	    	indicator.title = "SSH Request with pulic key"
	    	indicator.description = ("SSH public key: "+SSH[6])
	else:
		indicator.title = "SSH Request"
	    	indicator.description = ("An indicator containing information about a SSH request")
	indicator.set_produced_time(utils.dates.now())
	indicator.add_object(networkconnection)
	return indicator

def SMTP(smtpinfo):
	pass

def susIP(ip):
	#print "SUSIP"
	#TODO (from dns response) 
	a = Address()
	a.address_value = ip
	a.category = a.CAT_IPV4
	indicator = Indicator()
    	indicator.title = "Suspicious IP address"
    	indicator.description = ("An indicator containing a IPv4 address resolved from a suspicious domain")
	indicator.set_produced_time(utils.dates.now())
	indicator.add_object(a)
	return indicator

def susIPfound(ip):
	#print "SUSIP----found"
	#TODO (from dns response) 
	a = Address()
	a.address_value = ip
	a.category = a.CAT_IPV4
	indicator = Indicator()
    	indicator.title = "Suspicious IP address"
    	indicator.description = ("An indicator containing a suspicious IPv4 address found statically in the sample")
	indicator.set_produced_time(utils.dates.now())
	indicator.add_object(a)
	return indicator

def removeDuplicates(seq):
	#print "removeDuplicates"
	seen = set()
    	seen_add = seen.add
    	return [ x for x in seq if not (x in seen or seen_add(x))]

def translateType(typeNumber):
	#print "translateType"
	typeDict = {'1':'A', '2':'NS', '5':'CNAME', '15':'MX', '6':'SOA', '16':'TXT', '28':'AAAA'}
	return typeDict[typeNumber]
		 
def gatherIOCs(folderPath, synConn, synackConn, ackConn, resolvedIPs, results, fullHTTPArray, udpconn, dnspacket, icmpPacket, ftpconn, sshconn):#, foundIPs):
	#print "Gather IOCs"
	stix_package = STIXPackage()
	stix_report = stixReport() 	# need to add indicator references to this
	stix_header_information_source = InformationSource()
	stix_header_information_source.description = "From Cuckoo sandbox IOC_STIX reporting module"	
	stix_report.header = Header()
	stix_report.header.title = "A bunch of related indicators"
	stix_report.header.short_description = "A short description for the indicators oooooh!"
	stix_report.header.information_source = stix_header_information_source
		


# IP address
	for susip in resolvedIPs:
		stix_package.add(susIP(susip))
		stix_report.add_indicator(Indicator(idref=susIP(susip)._id))
	
# IPs found as static strings in the file	
#	for IP in foundIPs:
#		stix_package.add(susIPfound(IP))
#		stix_report.add_indicator(Indicator(idref=susIPfound(IP)._id))

# TCP Connection attempt and Connection established
	for tcp in synConn:
		if tcp not in ackConn:
			#print "tcp: ", tcp		
			stix_package.add(TCPConnectionAttemptFailedObj(tcp))
			stix_report.add_indicator(Indicator(idref=TCPConnectionAttemptFailedObj(tcp)._id))

	for tcpest in synConn:
		if tcpest in synackConn and tcpest in ackConn:
			#print "tcpest: ", tcpest		
			stix_package.add(TCPConnectionEstablishedObj(tcpest))
			stix_report.add_indicator(Indicator(idref=TCPConnectionEstablishedObj(tcpest)._id))

# Full HTTP Request
	for ht in fullHTTPArray:
		#print "ht array part:  ", ht, type(ht)
		stix_package.add(HTTPFullObj(ht))
		stix_report.add_indicator(Indicator(idref=HTTPFullObj(ht)._id))

# UDP Connection
	#print udpconn, type(udpconn)
	for udp in udpconn:
		if udp[0]!='53' and udp[1]!='53': # ignore DNS UDP packets (they are logged else where)
			#print "udp: ", udp		
			stix_package.add(UDPRequestObj(udp))
			stix_report.add_indicator(Indicator(idref=UDPRequestObj(udp)._id))

# DNS Connection
	for dns in dnspacket:
		#print "dns: ", dns		
		stix_package.add(DNSRequestObj(dns))
		stix_report.add_indicator(Indicator(idref=DNSRequestObj(dns)._id))

# ICMP Connection
	for icmp in icmpPacket:
		#print "ICMP: ", icmp
		if icmp[0] == 0 or icmp[0] == 8:
			stix_package.add(ICMPObj(icmp))
			stix_report.add_indicator(Indicator(idref=ICMPObj(icmp)._id))

# FTP Connection
	for ftp in ftpconn:
		#print "FTP: ", ftp
		if ftp[4]=='220' or ftp[4]=='230' or ftp[4]=='250':			
			stix_package.add(FTPObj(ftp))
			stix_report.add_indicator(Indicator(idref=FTPObj(ftp)._id))
		elif ftp[5]=="USER" or ftp[5]=="PASS" or ftp[5]=="STOR" or ftp[5]=="RETR":
			stix_package.add(FTPObj(ftp))
			stix_report.add_indicator(Indicator(idref=FTPObj(ftp)._id))
			

# SSH Connection
	for ssh in sshconn:
		#print "SSH: ", ssh
		stix_package.add(SSHObj(ssh))
		stix_report.add_indicator(Indicator(idref=SSHObj(ssh)._id))

	stix_package.add_report(stix_report)
	#print results["target"]		
	IOCStix = open(folderPath+"/"+str(results["target"]["file"]["name"])+".xml",'w')
	IOCStix.write(stix_package.to_xml())
	IOCStix.close()	
	#print(stix_package.to_xml())	

