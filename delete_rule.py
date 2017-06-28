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

def paloalto_rule_delete(pa_ip,pa_key,rule_name):
	# Delete a rule on the Palo Alto gateway that matches the rule_name provided
	# Input: Palo Alto gateway IP, Palo Alto Access Key, and rule_name
	
	ctx = ssl.create_default_context()
	ctx.check_hostname = False
	ctx.verify_mode = ssl.CERT_NONE

	cmd = "/api/?type=config&action=delete&"

	url = "https://"+pa_ip+cmd+"Key="+pa_key+"&"+urllib.parse.urlencode({'xpath':"/config/devices/entry[@name=\'localhost.localdomain\']/vsys/entry[@name=\'vsys1\']/rulebase/security/rules/entry[@name=\'"+rule_name+"\']"})
	
	response = urllib.request.urlopen(url, context=ctx)
	contents= ET.fromstring(response.read())
	response = urllib.request.urlopen("https://"+pa_ip+"/api/?type=commit&Key="+pa_key+"&cmd=<commit></commit>", context=ctx)
	result = 'success'
	return result

if len(rule_list)==1:
    sys.exit()

for i in range(1,len(rule_list)):
    paloalto_rule_delete(pa_ip,pa_key,rule_list[i])
