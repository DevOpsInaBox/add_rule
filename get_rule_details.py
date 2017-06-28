import json
import ssl
import urllib
import urllib.request
import xml.etree.ElementTree as ET
import gzip
import sys

pa_ip = "192.168.1.1"
pa_key = "LUFRPT1keWtzMHlBeHJYZnZGWjdHNUJOMCtaVWNHQ0U9eEd5R3RZZldhZjJMY0h1WlRqSFk2Zz09"
rule_list = sys.argv

def paloalto_rule_getdetails(pa_ip,pa_key,rule_name):
	# Return the rule details that match the rule_name provided
	# Input: Palo Alto gateway IP, Palo Alto Access Key, and rule_name
	# Output: dictionary with the following values:
	# 'dstZone': destination zone
	# 'srcZone': source zone
	# 'srcIP': list of source IP addresses
	# 'dstIP': list of destination IP addresses
	# 'application': application name
	# 'service': service object name
	# 'action': rule action
	ctx = ssl.create_default_context()
	ctx.check_hostname = False
	ctx.verify_mode = ssl.CERT_NONE

	cmd = "/api/?type=config&action=get&"

	url = "https://"+pa_ip+cmd+"Key="+pa_key+"&"+urllib.parse.urlencode({'xpath':"/config/devices/entry[@name=\'localhost.localdomain\']/vsys/entry[@name=\'vsys1\']/rulebase/security/rules/entry[@name=\'"+rule_name+"\']"})

	response = urllib.request.urlopen(url, context=ctx)
	contents= ET.fromstring(response.read())
	results = {} 
	results['srcIP'] = []
	results['dstIP'] = []
	for i in contents[0][0]:
		if i.tag == 'to':
			results['dstZone']=i[0].text
		elif i.tag == 'from':
			results['srcZone']=i[0].text
		elif i.tag == 'source':
			for j in i:
				results['srcIP'].append(j.text)
		elif i.tag == 'destination':
			for j in i:
				results['dstIP'].append(j.text)
		elif i.tag == 'application':
			results['application']=i[0].text
		elif i.tag == 'service':
			results['service']=i[0].text
		elif i.tag == 'action':
			results['action']=i.text
	#results['name']=rule_name
	return results

if len(rule_list) == 1:
    sys.exit()

for i in range(1,len(rule_list)):
     results = paloalto_rule_getdetails(pa_ip,pa_key,rule_list[i])
     print("Details of Rule "+rule_list[i]+":"+str(results))
