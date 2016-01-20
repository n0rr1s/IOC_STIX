import os, csv, dpkt

from lib.cuckoo.common.abstracts import Report
from lib.cuckoo.common.exceptions import CuckooReportError

# python-stix
import stix.utils as utils
from stix.core import STIXPackage, STIXHeader
from stix.indicator import Indicator

from cybox.core import *
from cybox.objects.dns_query_object import DNSQuery, DNSQuestion, DNSResourceRecords
from cybox.objects.dns_record_object import DNSRecord
from cybox.objects.domain_name_object import DomainName
import datetime

from cybox.objects.http_session_object import *
from cybox.objects.uri_object import URI

from cybox.objects.network_connection_object import NetworkConnection, Layer7Connections
from cybox.objects.socket_address_object import SocketAddress
from cybox.objects.port_object import Port

from cybox.objects.address_object import Address

# python-stix
import stix.utils as utils
from stix.core import STIXPackage, STIXHeader
from stix.indicator import Indicator

class IOC_STIX(Report):
	def run(self, results):		
		try:
           		#Do things
			pcapFile = dpkt.pcap.Reader(file(self.analysis_path+"/cut-byprocessingmodule.pcap"))
			postDataArray = getPostData(self.analysis_path)
			getDomainsArray = getDomains(self.analysis_path)
			synConn = getSYNInfo(self.analysis_path)
			resolvedIPsArray = resolvedIPs(self.analysis_path)
			if postDataArray != [] and getDomainsArray != [] and synConn != []:
				gatherIOCs(self.analysis_path, postDataArray, getDomainsArray, synConn, resolvedIPsArray)
			else:
				print "No IOCs to create"
			
        	except (UnicodeError, TypeError, IOError) as e:
			print "Error", e
            		raise CuckooReportError("Failed to make STIX IOCs :(")

def getPostData(folderPath):
	folderNum = folderPath[len(folderPath)-2]
	print folderNum	
	os.system("tshark -r "+folderPath+"/cut-byprocessingmodule.pcap -T fields -e http.request.full_uri -E separator=, > "+folderPath+"/HTTPPOST-SUS"+folderNum+".csv")
	postDataArray = []
	# ...
	with open(folderPath+"/HTTPPOST-SUS"+folderNum+".csv", 'rb') as csvfile:
		summaryCSV = csv.reader(csvfile, delimiter=',')
		for row in summaryCSV:
			postDataArray.append(row)
	return postDataArray # array of http dpkt objects

def getDomains(folderPath): # returns array or domain names
	folderNum = folderPath[len(folderPath)-2]
	print "get domains",folderNum
	os.system("tshark -r "+folderPath+"/cut-byprocessingmodule.pcap -T fields -e dns.qry.name -E separator=, > "+folderPath+"/domains-SUS"+folderNum+".csv")
	urlArray = []
	# ...
	with open(folderPath+"/domains-SUS"+folderNum+".csv", 'rb') as csvfile:
		summaryCSV = csv.reader(csvfile, delimiter=',')
		for row in summaryCSV:
			urlArray.append(row)
	return urlArray # array of domain names

def getSYNInfo(folderPath): 	# writes to a file the pairs of IPs from each SYN connection
	folderNum = folderPath[len(folderPath)-2]
	print "getSYNInfo",folderNum
	os.system("tshark -r "+folderPath+"/cut-byprocessingmodule.pcap -w "+folderPath+"/TCPSYN.pcap -F pcap -Y 'tcp.flags.syn==1 and tcp.flags.ack==0'")
	os.system("tshark -r "+folderPath+"/TCPSYN.pcap -T fields -e ip.src -e ip.dst -e tcp.srcport -e tcp.dstport -E separator=, > "+folderPath+"/SYNConn-SUS"+folderNum+".csv")
	dstIPArray = []
	# ...
	with open(folderPath+"/SYNConn-SUS"+folderNum+".csv", 'rb') as csvfile:
		summaryCSV = csv.reader(csvfile, delimiter=',')
		for row in summaryCSV:
			dstIPArray.append(row)
	return list(removeDuplicates(dstIPArray))

def resolvedIPs(folderPath):
	folderNum = folderPath[len(folderPath)-2]
	print "resolvedIPs", folderNum
	os.system("tshark -r "+folderPath+"/cut-byprocessingmodule.pcap -T fields -e dns.a -E separator=, > "+folderPath+"/domains-SUS"+folderNum+".csv")
	susResolvedIPArray = []
	# ...
	with open(folderPath+"/domains-SUS"+folderNum+".csv", 'rb') as csvfile:
		summaryCSV = csv.reader(csvfile, delimiter=',')
		for row in summaryCSV:
			susResolvedIPArray.append(row)
	return susResolvedIPArray

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

def TCPSYNobj(ips,ports):
	if len(ports) < 2:
		t = NetworkConnection()
		t.layer3_protocol = "IPv4"
		t.layer4_protocol = "TCP"
		ssocketaddress = SocketAddress()
		sport = Port()
		sport.port_value = ports[0] 
		sport.layer4_protocol = "TCP"
		ssocketaddress.port = sport
		t.source_socket_address = ssocketaddress		
		dsocketaddress = SocketAddress()
		dsocketaddress.ip_address = ips
		dport = Port()
		dport.port_value = ports[1]
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

def gatherIOCs(folderPath, postDataArray, getDomains, synConn, resolvedIPs):
	stix_package = STIXPackage()
	stix_header = STIXHeader()
    	stix_header.description = "Dridex domains"
   	stix_package.stix_header = stix_header		
	uris = []
	tcpSYNips = []
	tcpSYNports = {}
	for susip in resolvedIPs:
		stix_package.add(susIP(susip))
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
	for x in postDataArray:
		uris.append(x.uri)
	xx = removeDuplicates(uris)		
	for i in xx:
		stix_package.add(URIobj(i))
	for dd in removeDuplicates(getDomains):
		stix_package.add(domainNameobj(dd))
				
	IOCStix = open(folderPath+"/IOCStix.xml",'w')
	IOCStix.write(stix_package.to_xml())
	IOCStix.close()	
	print(stix_package.to_xml())	

