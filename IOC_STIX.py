import os, csv, dpkt, datetime

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
		#print str(results)	
		try:
			print "Start of IOC_STIX new one"
           		#Do things
			pcapFile = dpkt.pcap.Reader(file(self.analysis_path+"/cut-byprocessingmodule.pcap"))
			postDataArray = getPostData(self.analysis_path)
			getDomainsArray = getDomains(self.analysis_path)
			synConn = getSYNInfo(self.analysis_path)
			resolvedIPsArray = resolvedIPs(self.analysis_path)
			fullHTTPArray = getFullHTTP(self.analysis_path)
			udpconn = getUDPData(self.analysis_path)
			dnspacket = getDNSData(self.analysis_path)
			icmpPacket = getICMPData(self.analysis_path)
			ftpconn = getFTPConn(self.analysis_path)
			sshconn = getSSHConn(self.analysis_path)
			if postDataArray != []  or getDomainsArray != [] or synConn != []:
				gatherIOCs(self.analysis_path, postDataArray, getDomainsArray, synConn, resolvedIPsArray, results, fullHTTPArray, udpconn, dnspacket, icmpPacket, ftpconn, sshconn)
			else:
				print "No IOCs to create"
			
        	except (UnicodeError, TypeError, IOError) as e:
			print "Error", e
            		raise CuckooReportError("Failed to make STIX IOCs :(")

# SSH
# source IP, source port, destination address, destination port
# https://www.wireshark.org/docs/dfref/s/ssh.html
def getSSHConn(folderPath):
	os.system('tshark -r '+folderPath+'/cut-byprocessingmodule.pcap -w '+folderPath+'/SSHpackets.pcap -F pcap -Y ssh -T fields -e ip.src -e tcp.srcport -e ip.dst -e tcp.dstport -E separator=, > '+folderPath+'/SSHInfo.csv')
	sshpacket = []
	with open(folderPath+"/SSHInfo.csv", 'rb') as csvfile:
		summaryCSVSSH = csv.reader(csvfile, delimiter=',')
		for row in summaryCSVSSH:
			if row != [] and row not in sshpacket:
				sshpacket.append(row)
	print "sshpacket: ", sshpacket
	return sshpacket

# FTP
# source IP, source port, destination address, destination port
def getFTPConn(folderPath):
	os.system('tshark -r '+folderPath+'/cut-byprocessingmodule.pcap -w '+folderPath+'/FTPpackets.pcap -F pcap -Y ftp.request==1 -T fields -e ip.src -e tcp.srcport -e ip.dst -e tcp.dstport -E separator=, > '+folderPath+'/FTPInfo.csv')
	FTPpacket = []
	with open(folderPath+"/FTPInfo.csv", 'rb') as csvfile:
		summaryCSVFTP = csv.reader(csvfile, delimiter=',')
		for row in summaryCSVFTP:
			if row != [] and row not in FTPpacket:
				FTPpacket.append(row)
	print "FTPpacket: ", FTPpacket
	return FTPpacket

# ICMP
# source and destination address, type 
def getICMPData(folderPath):
	os.system('tshark -r '+folderPath+'/cut-byprocessingmodule.pcap -w '+folderPath+'/icmppackets.pcap -F pcap -Y icmp -T fields -e icmp.type -e ip.src -e ip.dst -E separator=, > '+folderPath+'/ICMPInfo.csv')
	ICMPpacket = []
	with open(folderPath+"/ICMPInfo.csv", 'rb') as csvfile:
		summaryCSVICMP = csv.reader(csvfile, delimiter=',')
		for row in summaryCSVICMP:
			if row != [] and row not in ICMPpacket:
				ICMPpacket.append(row)
	print "ICMPpacket: ", ICMPpacket
	return ICMPpacket


# source port, destination port, destination ip
# https://www.wireshark.org/docs/dfref/u/udp.html
def getUDPData(folderPath):
	os.system('tshark -r '+folderPath+'/cut-byprocessingmodule.pcap -w '+folderPath+'/UDPpackets.pcap -F pcap -Y udp -T fields -e udp.srcport -e udp.dstport -e ip.dst -e ip.src -E separator=, > '+folderPath+'/UDPInfo.csv')
	udppacket = []
	with open(folderPath+"/UDPInfo.csv", 'rb') as csvfile:
		summaryCSVUDP = csv.reader(csvfile, delimiter=',')
		for row in summaryCSVUDP:
			if row != [] and row not in udppacket:
				udppacket.append(row)
	#print "udp packet: ", udppacket
	return udppacket

def getDNSData(folderPath):
	os.system('tshark -r'+folderPath+'/cut-byprocessingmodule.pcap -w '+folderPath+'/DNSpackets.pcap -F pcap -Y dns.flags.response==0 -T fields -e ip.src -e udp.srcport -e ip.dst -e udp.dstport -e dns.qry.name -e dns.qry.type -e dns.flags.response -E separator=~ > '+folderPath+'/DNSInfo.csv')
	# -e dns.resp.name -e dns.resp.ttl -e dns.resp.type -e dns.a -e dns.flags.response -E separator=~ > '+folderPath+'/DNSInfo.csv')
	dnspacket = []
	with open(folderPath+"/DNSInfo.csv", 'rb') as csvfile:
		summaryCSVDNS = csv.reader(csvfile, delimiter='~')
		for row in summaryCSVDNS:
			if row != [] and row not in dnspacket:
				dnspacket.append(row)
	print "dns packet: ", dnspacket
	return dnspacket


def getFullHTTP(folderPath):
	comm = 'tshark -r '+folderPath+'/cut-byprocessingmodule.pcap -w '+folderPath+'/HTTPGETpackets.pcap -F pcap -Y http.request.method=="GET" -T fields -e http.request.method -e http.request.uri -e http.request.version -e http.host -e tcp.dstport -e http.accept -e http.accept_language -e http.accept_encoding -e http.authorization -e http.cache_control -e http.connection -e http.cookie -e http.content_length -e http.content_type -e http.date -e http.host -e http.proxy_authorization -E separator=, > '+folderPath+'/HTTPFullGET.csv'
	#print "Http comm: ", comm
	os.system(comm)
	comm2 = 'tshark -r '+folderPath+'/cut-byprocessingmodule.pcap -w '+folderPath+'/HTTPPOSTpackets.pcap -F pcap -Y http.request.method=="POST" -T fields -e http.request.method -e http.request.uri -e http.request.version -e http.host -e tcp.dstport -e http.accept -e http.accept_language -e http.accept_encoding -e http.authorization -e http.cache_control -e http.connection -e http.cookie -e http.content_length -e http.content_type -e http.date -e http.host -e http.proxy_authorization -E separator=, > '+folderPath+'/HTTPFullPOST.csv'
	#print "Http comm: ", comm2	
	os.system(comm2)
	HTTPfull = []
	with open(folderPath+"/HTTPFullGET.csv", 'rb') as csvfile:
		summaryCSV = csv.reader(csvfile, delimiter=',')
		for row in summaryCSV:
			if row != []:
				HTTPfull.append(row)
	with open(folderPath+"/HTTPFullPOST.csv", 'rb') as csvfile:
		summaryCSV = csv.reader(csvfile, delimiter=',')
		for row in summaryCSV:
			if row != []:
				HTTPfull.append(row)
	return HTTPfull

def getPostData(folderPath):
	#folderNum = folderPath[len(folderPath)-2] 	
	os.system("tshark -r "+folderPath+"/cut-byprocessingmodule.pcap -Y http -T fields -e http.request.uri -E separator=, > "+folderPath+"/HTTPPOST-SUS.csv")
	os.system("tshark -r "+folderPath+"/cut-byprocessingmodule.pcap -Y http -T fields -e http.request.full_uri -E separator=, > "+folderPath+"/HTTPPOST-SUS-FULLURI.csv")
	postDataArray = []
	# ...
	with open(folderPath+"/HTTPPOST-SUS.csv", 'rb') as csvfile:
		summaryCSV = csv.reader(csvfile, delimiter=',')
		for row in summaryCSV:
			if row != []:
				#print "getPostData", row, type(row)
				postDataArray.append(row[0])
	return postDataArray # array of http request URIs

def getDomains(folderPath): # returns array or domain names
	os.system("tshark -r "+folderPath+"/cut-byprocessingmodule.pcap -Y dns -T fields -e dns.qry.name -E separator=, > "+folderPath+"/domains-SUS.csv")
	urlArray = []
	# ...
	with open(folderPath+"/domains-SUS.csv", 'rb') as csvfile:
		summaryCSV = csv.reader(csvfile, delimiter=',')
		for row in summaryCSV:
			if row != [] and row not in urlArray:
				urlArray.append(row[0])
	return urlArray # array of domain names

def getSYNInfo(folderPath): 	# writes to a file the pairs of IPs from each SYN connection and the ports
	#folderNum = folderPath[len(folderPath)-2]
	#print "getSYNInfo",folderPath
	os.system("tshark -r "+folderPath+"/cut-byprocessingmodule.pcap -w "+folderPath+"/TCPSYN.pcap -F pcap -Y 'tcp.flags.syn==1 and tcp.flags.ack==0' -T fields -e ip.src -e ip.dst -e tcp.srcport -e tcp.dstport -E separator=, > "+folderPath+"/SYNConn-SUS.csv")
	#os.system("tshark -r "+folderPath+"/TCPSYN.pcap -T fields -e ip.src -e ip.dst -e tcp.srcport -e tcp.dstport -E separator=, > "+folderPath+"/SYNConn-SUS.csv")
	dstIPArray = []
	# ...
	with open(folderPath+"/SYNConn-SUS.csv", 'rb') as csvfile:
		summaryCSV = csv.reader(csvfile, delimiter=',')
		for row in summaryCSV:
			if (tuple(row) not in dstIPArray):
				dstIPArray.append(tuple(row))
	#print dstIPArray
	return dstIPArray

def resolvedIPs(folderPath):
	#folderNum = folderPath[len(folderPath)-2]
	#print "resolvedIPs", folderPath
	os.system("tshark -r "+folderPath+"/cut-byprocessingmodule.pcap -T fields -e dns.a -E separator=, > "+folderPath+"/domains-SUS-IPs.csv")
	susResolvedIPArray = []
	# ...
	with open(folderPath+"/domains-SUS.csv", 'rb') as csvfile:
		summaryCSV = csv.reader(csvfile, delimiter=',')
		for row in summaryCSV:
			if row != []:
				for i in row:				
					#print type(i), i
					susResolvedIPArray.append(i)
	return removeDuplicates(susResolvedIPArray)

def domainNameobj(domain):
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

def URIobj(httpR):
	h = URI()
	h.value = str(httpR) 
	indicator = Indicator()
    	indicator.title = "URI"
    	indicator.description = ("An indicator containing a suspicious URI")
	indicator.set_produced_time(utils.dates.now())
	indicator.add_object(h)
	return indicator

def HTTPFullObj(http): 
	#print "HTTP full object", http
	# HTTP Request Line
	httprequestline = HTTPRequestLine()
	httprequestline.http_method = http[0]
	httprequestline.value = http[1]
	httprequestline.version = http[2]
	#print "Host field"
	# Host Field
	hostfield = HostField()
	h = URI()
	h.value = str(http[3]) 
	print "Host value: ", http[3]
	hostfield.domain_name = h
	port = Port()
	port.port_value = http[4]
	hostfield.port = port
	#print "http request"
	# HTTP Request Header Fields
	httprequestheaderfields = HTTPRequestHeaderFields()
	if http[5] != '':										
		httprequestheaderfields.accept = http[5]
	if http[6] != '':									
		httprequestheaderfields.accept_language = http[6]
	if http[7] != '':										
		httprequestheaderfields.accept_encoding = http[7]
	if http[8] != '':										
		httprequestheaderfields.authorization = http[8]
	if http[9] != '':										
		httprequestheaderfields.cache_control = http[9]
	if http[10] != '':									
		httprequestheaderfields.connection = http[10]
	if http[11] != '':										
		httprequestheaderfields.cookie = http[11]
	if http[12] != '':										
		httprequestheaderfields.content_length = http[12] # integer
	if http[13] != '':										
		httprequestheaderfields.content_type = http[13]	
	if http[14] != '':										
		httprequestheaderfields.date = http[14] # datetime
	if http[15] != '':						
		httprequestheaderfields.host = hostfield
	if http[16] != '':										
		httprequestheaderfields.proxy_authorization = http[16]				
	#print "httprequestheader"
	httprequestheader = HTTPRequestHeader()
	httprequestheader.parsed_header = httprequestheaderfields

	#httpmessage = HTTPMessage()
	#httpmessage.length = len(http.body)
	#httpmessage.message_body = http.body
	#print "httpclientrequest"
	httpclientrequest = HTTPClientRequest()
	httpclientrequest.http_request_line = httprequestline
	httpclientrequest.http_request_header = httprequestheader
	#httpclientrequest.http_message_body = httpmessage
	
	http_request_response = HTTPRequestResponse()
	http_request_response.http_client_request = httpclientrequest
	
	httpsession = HTTPSession()	
	httpsession.http_request_response = http_request_response	

	indicator = Indicator()
    	indicator.title = "HTTP request"
    	indicator.description = ("An indicator containing information about a HTTP request")
	indicator.set_produced_time(utils.dates.now())
	indicator.add_object(httpsession)
	return indicator


def TCPSYNobj(ips,ports):
	#print "heeererererere TCPSYNobj"
	if len(ports) < 2:
		t = NetworkConnection()
		t.layer3_protocol = "IPv4"
		t.layer4_protocol = "TCP"
		ssocketaddress = SocketAddress()
		sport = Port()
		sport.port_value = ports[0][0] 
		sport.layer4_protocol = "TCP"
		ssocketaddress.port = sport
		t.source_socket_address = ssocketaddress		
		dsocketaddress = SocketAddress()
		dsocketaddress.ip_address = ips
		dport = Port()
		dport.port_value = ports[0][1]
		dport.layer4_protocol = "TCP"
		dsocketaddress.port = dport
		t.destination_socket_address = dsocketaddress
		indicator = Indicator()
	    	indicator.title = "TCP SYN connection"
	    	indicator.description = ("An indicator containing information about a TCP connection")
		indicator.set_produced_time(utils.dates.now())
		indicator.add_object(t)
		return indicator
	else:
		#print "no here"
		for i in ports:
			t = NetworkConnection()
			t.layer3_protocol = "IPv4"
			t.layer4_protocol = "TCP"
			ssocketaddress = SocketAddress()
			sport = Port()
			sport.port_value = i[0] 
			sport.layer4_protocol = "TCP"
			ssocketaddress.port = sport
			t.source_socket_address = ssocketaddress
			dsocketaddress = SocketAddress()
			dsocketaddress.ip_address = ips
			dport = Port()
			dport.port_value = i[1]
			dport.layer4_protocol = "TCP"
			dsocketaddress.port = dport
			t.destination_socket_address = dsocketaddress
			indicator = Indicator()
		    	indicator.title = "TCP SYN connection"
		    	indicator.description = ("An indicator containing information about a TCP connection")
			indicator.set_produced_time(utils.dates.now())
			indicator.add_object(t)
			return indicator

# source port, destination port, destination ip, source ip
def UDPRequestObj(udpinfo):
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
	networkconnection = NetworkConnection()
	networkconnection.layer3_protocol = "IPv4"
	networkconnection.layer4_protocol = "UDP"
	networkconnection.layer7_protocol = "DNS"
	ssocketaddress = SocketAddress()
	#ssocketaddress.ip_address = dnsinfo[0]
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
#	if dnsinfo[9] == 0:
	dnsques = DNSQuestion()
	dnsques.qname = dnsinfo[4]
	dnsques.qtype = translateType(dnsinfo[5])
	dqr.question = dnsques
	indicator.title = "DNS Request"
	indicator.description = ("An indicator containing information about a DNS Request")
#	else: # is a response
#		dqr = DNSQuery()					
#		dnsrecord = DNSRecord()
#		try:
#			dnsrecord.domain_name = dnsinfo[5]
#		except:
#			pass
#		try:
#			dnsrecord.ttl = dnsinfo[6]
#		except:
#			pass
#		try:
#			dnsrecord.record_type = translateType(dnsinfo[7])
#		except:
#			pass
#		dnsrecord.ip_address = dnsinfo[8]
#		dqr.answer_resource_records = DNSResourceRecords(dnsrecord)
#		indicator.title = "DNS Response"
 #   		indicator.description = ("An indicator containing information about a DNS Response")
		#dqr.authority_resource_records = 
		#dqr.additional_records = 	
	layer7connections.dns_query = dqr
	networkconnection.layer7_connections = layer7connections    	
	indicator.set_produced_time(utils.dates.now())
	indicator.add_object(networkconnection)
	return indicator

# type, source address, destination address
def ICMPObj(icmp):
	# block types 0 (ping response), 8 (ping request)
	nc = NetworkConnection()
	nc.layer3_protocol = "ICMP"
	if icmp[0] == 0: # incoming connection
		ssocketaddress = SocketAddress()
		ssocketaddress.ip_address = icmp[1]
		nc.source_socket_address = ssocketaddress
	elif icmp[0] ==  8: # outgoing connection
		dsocketaddress = SocketAddress()
		dsocketaddress.ip_address = icmp[2]
		nc.destination_socket_address = dsocketaddress
	indicator = Indicator()
    	indicator.title = "ICMP connection"
    	indicator.description = ("An indicator containing information about a ICMP connection")
	indicator.set_produced_time(utils.dates.now())
	indicator.add_object(nc)
	return indicator

# source IP, source port, destination address, destination port
def FTPObj(ftp):
	networkconnection = NetworkConnection()
	networkconnection.layer3_protocol = "IPv4"
	networkconnection.layer4_protocol = "TCP"
	networkconnection.layer7_protocol = "FTP"
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
		ssocketaddress.port = dport
		networkconnection.destination_socket_address = dsocketaddress
	indicator = Indicator()
    	indicator.title = "FTP Request"
    	indicator.description = ("An indicator containing information about a FTP request")
	indicator.set_produced_time(utils.dates.now())
	indicator.add_object(networkconnection)
	return indicator

# source IP, source port, destination address, destination port
def SSHObj(SSH):
	networkconnection = NetworkConnection()
	networkconnection.layer3_protocol = "IPv4"
	networkconnection.layer4_protocol = "TCP"
	networkconnection.layer7_protocol = "SSH"
	if SSH[0] != VMIP: # incoming connection
		ssocketaddress = SocketAddress()
		ssocketaddress.ip_address = SSH[0]
		sport = Port()
		sport.port_value = SSH[1]
		sport.layer4_protocol = "TCP"
		ssocketaddress.port = sport
		networkconnection.source_socket_address = ssocketaddress
	elif SSH[2] != VMIP: # outgoing connection
		dsocketaddress = SocketAddress()
		dsocketaddress.ip_address = SSH[2]
		dport = Port()
		dport.port_value = SSH[3]
		dport.layer4_protocol = "TCP"
		ssocketaddress.port = dport
		networkconnection.destination_socket_address = dsocketaddress
	indicator = Indicator()
    	indicator.title = "SSH Request"
    	indicator.description = ("An indicator containing information about a SSH request")
	indicator.set_produced_time(utils.dates.now())
	indicator.add_object(networkconnection)
	return indicator

def SMTP(smtpinfo):
	pass

def susIP(ip):
	#TODO (from dns response) 
	a = Address()
	a.address_value = ip
	a.category = a.CAT_IPV4
	indicator = Indicator()
    	indicator.title = "Suspicious IP address"
    	indicator.description = ("An indicator containing a suspicious IPv4 address")
	indicator.set_produced_time(utils.dates.now())
	indicator.add_object(a)
	return indicator

def removeDuplicates(seq):
	seen = set()
    	seen_add = seen.add
    	return [ x for x in seq if not (x in seen or seen_add(x))]

def translateType(typeNumber):
	typeDict = {'1':'A', '2':'NS', '5':'CNAME', '15':'MX', '6':'SOA', '16':'TXT', '28':'AAAA'}
	return typeDict[typeNumber]

def gatherIOCs(folderPath, postDataArray, getDomains, synConn, resolvedIPs, results, fullHTTPArray, udpconn, dnspacket, icmpPacket, ftpconn, sshconn):
	#print "Gather IPs"
	stix_package = STIXPackage()
	stix_report = stixReport() 	# need to add indicator references to this
	stix_header_information_source = InformationSource()
	stix_header_information_source.description = "From Cuckoo sandbox IOC_STIX reporting module"	
	stix_report.header = Header()
	stix_report.header.title = "A bunch of related indicators"
	stix_report.header.short_description = "A short description for the indicators oooooh!"
	stix_report.header.information_source = stix_header_information_source
		
	uris = []
	tcpSYNips = []
	tcpSYNports = {}

# IP address
	for susip in resolvedIPs:
		stix_package.add(susIP(susip))
		stix_report.add_indicator(Indicator(idref=susIP(susip)._id))
	
#TCP SYN
	for info in synConn:
		tcpSYNips.append(info[1])
		if info[1] not in tcpSYNports.keys():
			tcpSYNports[info[1]] = [(info[2],info[3])]
		else:
			if info[3] not in tcpSYNports[info[1]]:
				tcpSYNports[info[1]].append((info[2],info[3]))
	tcpSYNips = removeDuplicates(tcpSYNips)
	for z in tcpSYNips:		
		stix_package.add(TCPSYNobj(z,tcpSYNports[z]))
		stix_report.add_indicator(Indicator(idref=TCPSYNobj(z,tcpSYNports[z])._id))
	
# URI			
	for i in removeDuplicates(postDataArray):
		stix_package.add(URIobj(i))
		stix_report.add_indicator(Indicator(idref=URIobj(i)._id))
	for dd in removeDuplicates(getDomains):
		stix_package.add(domainNameobj(dd))
		stix_report.add_indicator(Indicator(idref=domainNameobj(dd)._id))

# Full HTTP Request
	for ht in fullHTTPArray:
		#print "ht ", ht
		stix_package.add(HTTPFullObj(ht))
		stix_report.add_indicator(Indicator(idref=HTTPFullObj(ht)._id))

# UDP Connection
	for udp in udpconn:
		#print "udp: ", udp		
		stix_package.add(UDPRequestObj(udp))
		stix_report.add_indicator(Indicator(idref=UDPRequestObj(udp)._id))

# DNS Connection
	for dns in dnspacket:
		print "dns: ", dns		
		stix_package.add(DNSRequestObj(dns))
		stix_report.add_indicator(Indicator(idref=DNSRequestObj(dns)._id))

# ICMP Connection
	for icmp in icmpPacket:
		print "ICMP: ", icmp
		stix_package.add(ICMPObj(icmp))
		stix_report.add_indicator(Indicator(idref=ICMPObj(icmp)._id))

# FTP Connection
	for ftp in ftpconn:
		print "FTP: ", ftp
		stix_package.add(FTPObj(ftp))
		stix_report.add_indicator(Indicator(idref=FTPObj(ftp)._id))

# SSH Connection
	for ssh in sshconn:
		print "SSH: ", ssh
		stix_package.add(SSHObj(ssh))
		stix_report.add_indicator(Indicator(idref=SSHObj(ssh)._id))

	stix_package.add_report(stix_report)		
	IOCStix = open(folderPath+"/"+str(results["virustotal"]["md5"])+".xml",'w')
	IOCStix.write(stix_package.to_xml())
	IOCStix.close()	
	#print(stix_package.to_xml())	

