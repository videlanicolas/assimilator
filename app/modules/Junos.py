from flask_restful import Resource
from flask import request,abort,jsonify,Response
from bs4 import BeautifulSoup
from app.modules.firewall import Firewall
from functools import wraps
from lxml import etree
from lxml.builder import E
from bs4.element import Tag
from bs4 import BeautifulSoup as BS
from jnpr.junos import Device
from jnpr.junos.exception import ConnectError
import logging, socket, json, os

#Get logger
logger = logging.getLogger(__name__)

logging.getLogger("ncclient").setLevel(logging.ERROR)

class JUNOS(Firewall):
	def __init__(self,firewall,brand='juniper',primary=True):
		self.firewall = firewall
		self.brand = 'juniper'
		self.primary = primary
		self.ip = self.getFirewall()
		if 'privatekey' in self.getConfig()['juniper'][self.firewall].keys() and 'privatekeypass' in self.getConfig()['juniper'][self.firewall].keys():
			if self.getConfig()['juniper'][self.firewall]['privatekey'] and self.getConfig()['juniper'][self.firewall]['privatekeypass']:
				#RSA SSH connection
				logger.info("Juniper RSA SSH connection.")
				self.dev = Device(host=self.ip, passwd=self.getConfig()['juniper'][self.firewall]['privatekeypass'],\
									ssh_private_key_file=str(self.getConfig()['juniper'][self.firewall]['privatekey']),user=self.getConfig()['juniper'][self.firewall]['user'],\
									port=self.getConfig()['juniper'][self.firewall]['port'],gather_facts=False)
			else:
				#User password connection
				logger.info("Juniper User/Password connection.")
				self.dev = Device(host=self.ip, password=self.getConfig()['juniper'][self.firewall]['pass'],\
									user=self.getConfig()['juniper'][self.firewall]['user'],port=self.getConfig()['juniper'][self.firewall]['port'],gather_facts=False)
		else:
			#User password connection
			logger.info("Juniper User/Password connection.")
			self.dev = Device(host=self.ip, password=self.getConfig()['juniper'][self.firewall]['pass'],\
				user=self.getConfig()['juniper'][self.firewall]['user'],port=self.getConfig()['juniper'][self.firewall]['port'],gather_facts=False)
		self.dev.open(normalize=True)
		self.dev.timeout = 300
class configuration(JUNOS):
	def get(self):
		if not self.dev.connected:
			logger.error("{0}: Firewall timed out or incorrect device credentials.".format(self.firewall))
			return {'error' : 'Could not connect to device.'}, 502
		else:
			logger.info("{0}: Connected successfully.".format(self.firewall))
		ret = self.dev.rpc.get_config()
		self.dev.close()
		return {'config' : str(BeautifulSoup(str(ret),'xml')).replace('<?xml version="1.0" encoding="utf-8"?>\n','')}
class rules(JUNOS):
	def get(self,args):
		if not self.dev.connected:
			logger.error("{0}: Firewall timed out or incorrect device credentials.".format(self.firewall))
			return {'error' : 'Could not connect to device.'}, 504
		else:
			logger.info("{0}: Connected successfully.".format(self.firewall))
		soup = BS(str(self.dev.rpc.get_firewall_policies()).replace('\n',''),'xml')
		self.dev.close()
		entries = list()
		for context in soup.find("security-policies").children:
			if type(context) != Tag:
				continue
			elif context.name == "default-policy":
				continue
			src_zone = context.find("context-information").find("source-zone-name").text
			dst_zone = context.find("context-information").find("destination-zone-name").text
			for rule in context.children:
				if rule.name == "context-information" or type(rule) != Tag:
					continue
				aux = {
					"enabled" : True if rule.find('policy-state').text == 'enabled' else False,
					"id" : int(rule.find('policy-identifier').text),
				      "action": rule.find('policy-information').find('policy-action').find('action-type').text,
				      "destination": list(),
				      "from": src_zone,
				      "logging": False if rule.find('policy-information').find('policy-action').find('log') else rule.find('policy-information').find('policy-action').find('log'),
				      "name": rule.find('policy-information').find('policy-name').text,
				      "application": list(),
				      "source": list(),
					"to": dst_zone
		   		 	}
				for addr in rule.find('source-addresses').children:
					if type(addr) != Tag:
						continue
					aux['source'].append(addr.find('address-name').text)
				for addr in rule.find('destination-addresses').children:
					if type(addr) != Tag:
						continue
					aux['destination'].append(addr.find('address-name').text)
				for addr in rule.find('applications').children:
					if type(addr) != Tag:
						continue
					aux['application'].append(addr.find('application-name').text)
				entries.append(aux)
		entries = self.filter(args,entries)
		return {'len' : len(entries), 'rules' : entries}
class objects(JUNOS):
	def get(self,args=None,object=None):
		if not self.dev.connected:
			logger.error("{0}: Firewall timed out or incorrect device credentials.".format(self.firewall))
			return {'error' : 'Could not connect to device.'}, 504
		else:
			logger.info("{0}: Connected successfully.".format(self.firewall))
		entries = list()
		if object == "address":
			filter = E('security',E('zones'))
			rpc = str(self.dev.rpc.get_config(filter)).replace('\n','')
			self.dev.close()
			soup = BS(str(rpc),'xml')
			for zone in soup.zones.children:
				if type(zone) != Tag or not zone.find('address-book'):
					continue
				dmz = zone.find('name').text
				for object in zone.find('address-book').children:
					if type(object) != Tag or object.name != "address":
						continue
					aux = {
						'dmz' : dmz,
						'type' : 'ip' if object.find('ip-prefix') else 'hostname',
						'name' : object.find('name').text,
						'value' : object.find('ip-prefix').text if object.find('ip-prefix') else object.find('dns-name').text
						}
					entries.append(aux)
		elif object == "service":
			filter = E('applications')
			rpc = str(self.dev.rpc.get_config(filter)).replace('\n','')
			self.dev.close()
			for application in soup.applications.children:
				if type(application) != Tag or application.name != 'application':
					continue
				aux = {
				'name' : application.find('name').text,
				'protocol' : application.protocol.text if application.protocol else '',
				'port' : application.find('destination-port').text if application.find('destination-port') else ''
				}
				entries.append(aux)
			#Load default junos service objects
			with open(os.path.join(os.path.dirname(__file__), 'default-applications.json'),'r') as f:
				for app in json.loads(f.read())['list']:
					if not request.args:
						entries.append(app)
					else:
						for opcion in request.args:
							if opcion in app.keys():
								if type(app[opcion]) == list:
									for i in app[opcion]:
										if request.args[opcion].lower() in i.lower():
											entries.append(app)
								elif request.args[opcion].lower() in app[opcion].lower():
									entries.append(app)
		elif object == "address-group":
			filter = E('security',E('zones'))
			rpc = str(self.dev.rpc.get_config(filter)).replace('\n','')
			self.dev.close()
			for zone in soup.zones.children:
				if type(zone) != Tag or not zone.find('address-book'):
					continue
				dmz = zone.find('name').text
				for object in zone.find('address-book').children:
					if type(object) != Tag or object.name != "address-set":
						continue
					aux = {
					'dmz' : dmz,
					'name' : object.find('name').text,
					'members' : list()
					}
					for addr in object.children:
						if type(addr) != Tag or addr.name == "name":
							continue
						aux['members'].append(addr.find('name').text)
					entries.append(aux)
		elif object == "service-group":
			filter = E('applications')
			rpc = str(self.dev.rpc.get_config(filter)).replace('\n','')
			self.dev.close()
			for application in soup.applications.children:
				if type(application) != Tag or application.name != 'application-set':
					continue
				aux = {
				'name' : application.find('name').text,
				'members' : list()
				}
				for member in application.children:
					if type(member) != Tag or member.name == 'name':
						continue
					aux['members'].append(member.find('name').text)
				entries.append(aux)
		else:
			logger.warning("Resource not found.")
			return {'error' : 'Resource not found.'}, 404
		entries = self.filter(args,entries)
		return {'firewall' : self.firewall, 'len' : len(entries), str(object) : entries}
class route(JUNOS):
	def get(self,ip):
		try:
			socket.inet_aton(str(ip))
		except TypeError:
			#Not a valid IP
			logger.warning("Not a valid IP.")
			logger.debug("ip: {0}".format(str(ip)))
			return {'error' : 'Not a valid IP.'}, 400
		else:
			if not self.dev.connected:
				logger.error("{0}: Firewall timed out or incorrect device credentials.".format(self.firewall))
				return {'error' : 'Could not connect to device.'}, 504
			else:
				logger.info("{0}: Connected successfully.".format(self.firewall))
			if 'ip' in request.args:
				rpc = str(self.dev.rpc.get_route_information(destination=request.args['ip']))
				soup = BS(str(rpc).replace('\n            ','').replace('\n',''),'xml')
				rpc2 = str(self.dev.rpc.get_interface_information(interface_name=soup.find('via').text))
				soup2 = BS(str(rpc2).replace('\n            ','').replace('\n',''),'xml')			
				self.dev.close()
			else:
				WARN('{0}: No ip field in GET argument.'.format(firewall))
				self.dev.close()
				return {'error' : 'Invalid argument.'}, 404
			return {'route' : {
						'destination' : soup.find('rt-destination').text,
						'active' : True if soup.find('current-active') else False,
						'type' : soup.find('protocol-name').text,
						'preference' : int(soup.preference.text),
						'age' : soup.age.text,
						'next-hop' : soup.to.text,
						'interface' : soup.via.text,
						'zone' : soup2.find('logical-interface-zone-name').text.replace('\n','')
						}}
class match(JUNOS):
	def get(self,args):
		logger.debug("Juniper.match.get()")
		if not self.dev.connected:
			logger.error("{0}: Firewall timed out or incorrect device credentials.".format(self.firewall))
			return {'error' : 'Could not connect to device.'}, 504
		else:
			logger.info("{0}: Connected successfully.".format(self.firewall))
		#Source Zone
		rpc = str(self.dev.rpc.get_route_information(destination=args['source']))
		soup = BS(str(rpc).replace('\n            ','').replace('\n',''),'xml')
		rpc = str(self.dev.rpc.get_interface_information(interface_name=soup.find('via').text))
		soup = BS(str(rpc).replace('\n            ','').replace('\n',''),'xml')
		from_zone = soup.find('logical-interface-zone-name').text.replace('\n','')
		#Destination Zone
		rpc = str(self.dev.rpc.get_route_information(destination=args['destination']))
		soup = BS(str(rpc).replace('\n            ','').replace('\n',''),'xml')
		rpc = str(self.dev.rpc.get_interface_information(interface_name=soup.find('via').text))
		soup = BS(str(rpc).replace('\n            ','').replace('\n',''),'xml')
		to_zone = soup.find('logical-interface-zone-name').text.replace('\n','')

		if to_zone == from_zone:
			return {'allowed' : True, 'policy' : 'Intrazone'}
		rpc = str(self.dev.rpc.match_firewall_policies(
			from_zone=from_zone,
			to_zone=to_zone,
			source_ip=args['source'],
			destination_ip=args['destination'],
			source_port=args['source-port'] if 'source-port' in args else "1025",
			destination_port=args['port'],
			protocol=args['protocol'] if 'protocol' in args else "tcp"
			))
		self.dev.close()
		soup = BS(rpc,'xml')
		try:
			aux = {
				"enabled" : True if soup.find('policy-state').text == 'enabled' else False,
				"id" : int(soup.find('policy-identifier').text),
			    "action": soup.find('policy-information').find('policy-action').find('action-type').text,
			    "destination": list(),
			    "from": soup.find('context-information').find('source-zone-name').text,
			    "logging": False if soup.find('policy-information').find('policy-action').find('log') else soup.find('policy-information').find('policy-action').find('log'),
			    "name": soup.find('policy-information').find('policy-name').text,
			    "application": list(),
			    "source": list(),
				"to": soup.find('context-information').find('destination-zone-name').text
	   		 	}
			for addr in soup.find('source-addresses').children:
				if type(addr) != Tag:
					continue
				aux['source'].append(addr.find('address-name').text)
			for addr in soup.find('destination-addresses').children:
				if type(addr) != Tag:
					continue
				aux['destination'].append(addr.find('address-name').text)
			for addr in soup.find('applications').children:
				if type(addr) != Tag:
					continue
				aux['application'].append(addr.find('application-name').text)
		except:
			aux = {
			"enabled" : True if soup.find('policy-state').text == 'enabled' else False,
			"id" : int(soup.find('policy-identifier').text),
			"action": soup.find('policy-information').find('policy-action').find('action-type').text,
			"name": soup.find('policy-information').find('policy-name').text,
			}
		return {'allowed' : True if soup.find('policy-action').find('action-type').text == "permit" else False, 'policy' : aux}
class hitcount(JUNOS):
	def get(self):
		if not self.dev.connected:
			logger.error("{0}: Firewall timed out or incorrect device credentials.".format(self.firewall))
			return {'error' : 'Could not connect to device.'}, 504
		else:
			logger.info("{0}: Connected successfully.".format(self.firewall))
		rpc = str(jns.rpc.get_security_policies_hit_count())
		soup = BS(rpc,'xml')
		entries = list()
		for hitcount in soup.find('policy-hit-count').children:
			if type(hitcount) != Tag or hitcount.name != 'policy-hit-count-entry':
				continue
			aux = {
			'count' : int(hitcount.find('policy-hit-count-count').text),
			'from' : hitcount.find('policy-hit-count-from-zone').text,
			'to' : hitcount.find('policy-hit-count-to-zone').text,
			'policy' : hitcount.find('policy-hit-count-policy-name').text
			}
			entries.append(aux)
		return {'len' : len(entries), 'hitcount' : entries}