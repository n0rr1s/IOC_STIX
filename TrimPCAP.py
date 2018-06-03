from cuckoo.common.exceptions import CuckooProcessingError
from cuckoo.common.abstracts import Processing
import os
import subprocess32

class PCAPfilter(Processing):

    def run(self):
        self.key = "key"
	# path to pcap
	self.pcap_path
	data = 1
	try:
		print "About to cut PCAP"
		filterString = "meep"
		subprocess32.call([self.analysis_path+"/../../../filterString.sh", self.pcap_path, self.analysis_path+'/cut-byprocessingmodule.pcap'])
		print "Done cutting"
	except:
		raise CuckooProcessingError("Could not process PCAP")
        return filterString
