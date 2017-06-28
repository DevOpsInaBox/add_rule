import json
import ssl
import urllib
from urllib2 import urlopen
#import urllib.request
import xml.etree.ElementTree as ET
import gzip
import sys

pa_ip = "192.168.1.1"
pa_key = "LUFRPT1keWtzMHlBeHJYZnZGWjdHNUJOMCtaVWNHQ0U9eEd5R3RZZldhZjJMY0h1WlRqSFk2Zz09"
rule_params_list = sys.argv

def paloalto_rule_add(pa_ip,pa_key,rule_params):
	# Add a new rule on Palo Alto gateway
	# Input: Palo Alto gateway IP, Palo Alto Access Key, and rule_params
	# rule_params are the parameters to be configured for the new rule. It is a dictionary with the following values:
	# rule_params['name']: name of the rule
	# rule_params['dstZone']: destination zone
	# rule_params['srcZone']: source zone
	# rule_params['srcIP']: list of source IP addresses
	# rule_params['dstIP']: list of destination IP addresses
	# rule_params['application']: application 
	# rule_params['service']: service
	# rule_params['action']: rule action (allow, deny)
	# rule_params['spg']: name of security group profile to be set 
	# Output: returns 'success' or 'fail' depending on the result

	
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    
    rule_source_ip = ""
    rule_destination_ip = ""
	
    for i in rule_params['srcIP']:
        rule_source_ip = rule_source_ip + "<member>"+i+"</member>"

    for i in rule_params['dstIP']:
        rule_destination_ip = rule_destination_ip + "<member>"+i+"</member>"

    cmd = "/api/?type=config&action=set&"
    parameters = {'xpath':"/config/devices/entry[@name=\'localhost.localdomain\']/vsys/entry[@name=\'vsys1\']/rulebase/security/rules/entry[@name=\'"+rule_params['name']+"\']",'element':"<to><member>"+rule_params['dstZone']+"</member></to><from><member>"+rule_params['srcZone']+"</member></from><source>"+rule_source_ip+"</source><destination>"+rule_destination_ip+"</destination><application><member>"+rule_params['application']+"</member></application><service><member>"+rule_params['service']+"</member></service><action>"+rule_params['action']+"</action>"}


    url = "https://"+pa_ip+cmd+"Key="+pa_key+"&"+urllib.parse.urlencode(parameters)
    print("URL:"+url)
    response = urllib.request.urlopen(url, context=ctx)

    contents= ET.fromstring(response.read())
    response = urllib.request.urlopen("https://"+pa_ip+"/api/?type=commit&Key="+pa_key+"&cmd=<commit></commit>", context=ctx)
    result = 'success'
    return result

if (len(rule_params_list) == 1):
   sys.exit()

rule_params={}
rule_params['name'] = rule_params_list[1]
rule_params['srcZone'] = rule_params_list[2]
rule_params['srcIP'] = [rule_params_list[3]]
rule_params['dstZone'] = rule_params_list[4]
rule_params['dstIP'] = [rule_params_list[5]]
rule_params['application'] = rule_params_list[6]
rule_params['service'] = rule_params_list[7]
rule_params['action'] = rule_params_list[8]

paloalto_rule_add(pa_ip,pa_key,rule_params)
