import boto3
import json
import ssl
import urllib
import urllib.request
import xml.etree.ElementTree as ET
import gzip

pa_ip = "192.168.1.1"
pa_key = "LUFRPT1keWtzMHlBeHJYZnZGWjdHNUJOMCtaVWNHQ0U9eEd5R3RZZldhZjJMY0h1WlRqSFk2Zz09"

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

def paloalto_rule_add(pa_ip,pa_key,pa_rulename):
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
    
    rule_params={}
    rule_params['name'] = pa_rulename
    rule_params['srcZone'] = "any"
    rule_params['dstZone'] = "any"
    rule_params['application'] = "any"
    rule_params['service'] = "any"
    rule_params['srcIP'] = ["192.168.2.139"]
    rule_params['dstIP'] = ["192.168.2.140"]
    rule_params['action'] = "allow"
    rule_params['spg'] = "spg"
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

msg = paloalto_rule_delete(pa_ip,pa_key,"pa_rule")
print(msg)
#paloalto_rule_add(pa_ip,pa_key,"pa_rule")
#results = paloalto_rule_getdetails(pa_ip,pa_key,"pa_rule")
#print(results)