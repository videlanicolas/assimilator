from bs4 import BeautifulSoup
from bs4.element import Tag
from lxml import objectify
from functools import wraps
from app.modules.firewall import Firewall
import ConfigParser, re, json, logging
from threading import Thread
from requests import get
from requests.packages.urllib3.exceptions import InsecureRequestWarning
from requests.packages.urllib3 import disable_warnings

#Disable requests insecure log
disable_warnings(InsecureRequestWarning)

#Get logger
logger = logging.getLogger(__name__)

class PAN(Firewall):
	def __init__(self,firewall_config):
		self.firewall_config = firewall_config
		a = self.getMaster()
		self.firewall_config['primary'] = a['active'] if a['ok'] else None
		self.primary = self.firewall_config['primary']
	def apicall(self,verify=False,**kwargs):
		self.__url_base = "https://{0}/api?key={1}".format(self.firewall_config['primary'],self.firewall_config['key'])
		response = get(self.__url_base,params=kwargs,verify=verify)
		logger.debug("{0}: {1} {2}".format(self.firewall_config['primary'],self.__url_base,str(kwargs)))
		return response
	def getMaster(self):
		response = self.apicall(type='op',\
								cmd="<show><high-availability><state></state></high-availability></show>")
		soup = BeautifulSoup(response.text,'xml')
		if response.ok:
			if soup.response['status'] == 'success':
				if soup.response.result.enabled == 'no':
					logger.info("No HA enabled on Firewall, using primary as active IP.")
					return {'ok' : True,\
							'active' : self.firewall_config['primary'], 'passive' : self.firewall_config['secondary']}
				else:
					return {'ok' : True,\
							'active' : self.firewall_config['primary'] if soup.response.result.group.find('local-info').state.text == 'active' else soup.response.result.group.find('peer-info').find('mgmt-ip').text.split('/')[0],\
							'passive' : self.firewall_config['primary'] if soup.response.result.group.find('local-info').state.text == 'passive' else soup.response.result.group.find('peer-info').find('mgmt-ip').text.split('/')[0] }
			else:
				return {'ok' : False, 'info' : 'Could not get active firewall\'s ip.', 'panos-response' : soup.response['status']}
		else:
			aux = self.firewall_config['secondary']
			self.firewall_config['primary'] = self.firewall_config['secondary']
			self.firewall_config['secondary'] = aux
			del aux
			response = self.apicall(type='op',\
								cmd="<show><high-availability><state></state></high-availability></show>")
			soup = BeautifulSoup(response.text,'xml')
			if soup.response['status'] == 'success':
				if soup.response.result.enabled == 'no':
					logger.info("No HA enabled on Firewall, using primary as active IP.")
					return {'ok' : True,\
							'active' : self.firewall_config['primary'], 'passive' : self.firewall_config['secondary']}
				else:
					return {'status' : True,\
							'active' : self.firewall_config['primary'] if soup.response.result.group.find('local-info').state.text == 'active' else soup.response.result.group.find('peer-info').find('mgmt-ip').text.split('/')[0],\
							'passive' : self.firewall_config['primary'] if soup.response.result.group.find('local-info').state.text == 'passive' else soup.response.result.group.find('peer-info').find('mgmt-ip').text.split('/')[0] }
			else:
				return {'ok' : False, 'info' : 'Could not get active firewall\'s ip.', 'panos-response' : soup.response['status']}
	def filter(self,args,_entries):
		#Filter algorithm
		for opt in args:
			filter = list()
			for entry in _entries:
				if opt in entry:
					if type(entry[opt]) == list:
						for e in entry[opt]:
							if args[opt].lower() in e.lower():
								break
						else:
							filter.append(entry)
					elif type(entry[opt]) == bool:
						a = True if args[opt].lower() == 'true' else False if args[opt].lower() == 'false' else None
						if a == None or a != entry[opt]:
							filter.append(entry)
					elif type(entry[opt]) == dict:
						if json.loads(args[opt]) != entry[opt]:
							filter.append(entry)
					else:
						if args[opt].lower() not in entry[opt].lower():
							filter.append(entry)
				else:
					filter.append(entry)
			for f in filter:
				del _entries[_entries.index(f)]
		return _entries

class configuration(PAN):
	def get(self):
		response = self.apicall(type='op', cmd='<show><config><running></running></config></show>')
		if response.status_code != 200:
			logger.error("{0}: ".format(self.firewall) + str(response.text))
			return {'error' : str(response.text)}, 502
		else:
			soup = BeautifulSoup(response.text,'xml')
			if soup.response['status'] == 'error':
				return {'error' : str(soup.msg.text)}, 502
			else:
				return {'config' : response.text}, 200
class rules(PAN):
	def get(self,args):
		response = self.apicall(type='config',\
								action='get',\
								xpath='/config/devices/entry[@name="localhost.localdomain"]/vsys/entry[@name="vsys1"]/rulebase/security/rules')
		if response.status_code != 200:
			logger.error("Palo Alto response: " + str(response.status_code))
			return {'error' : str(response.text)}, 502
		_entries = list()
		for entry in BeautifulSoup(response.text,'xml').rules.children:
			#Some tags are a newline, skip them
			if type(entry) != Tag:
				continue		
			aux = {
			'name' : entry['name'],
			'from' : list(),
			'to' : list(),
			'source' : list(),
			'destination' : list(),
			'action' : entry.find('action').text,
			'application' : list(),
			'category' : list(),
			'description' : entry.find('description').text if entry.find('description') else None,
			'disabled' : False if not entry.find('disabled') else True if entry.find('disabled').text == 'yes' else False,
			'hip-profiles' : list(),
			'icmp-unreachable' : False if not entry.find('icmp-unreachable') else True if entry.find('icmp-unreachable').text == 'yes' else False,
			'log-end' : False if not entry.find('log-end') else True if entry.find('log-end').text == 'yes' else False,
			'log-setting' : entry.find('log-setting').text if entry.find('log-setting') else None,
			'log-start' : False if not entry.find('log-start') else True if entry.find('log-start').text == 'yes' else False,
			'negate-destination' : False if not entry.find('negate-destination') else True if entry.find('negate-destination').text == 'yes' else False,
			'negate-source' : False if not entry.find('negate-source') else True if entry.find('negate-source').text == 'yes' else False,
			'disable-server-response-inspection' : False if not entry.find('disable-server-response-inspection') else True if entry.find('disable-server-response-inspection').text == 'yes' else False,
			'profile-setting' : dict(),
			'qos' : {'marking' : entry.marking.next_element.next_element.name if entry.find('marking') else None, 'type' :  entry.marking.next_element.next_element.text if entry.find('marking') else None},
			'rule-type' : entry.find('rule-type').text if entry.find('rule-type') else 'universal',
			'schedule' : entry.schedule.text if entry.find('schedule') else None,
			'service' : list(),
			'source-user' : list(),
			'tag' : list()
			}
			#Iterate all lists
			for s in ['from','to','source','destination','application','category','hip.profiles','service','source-user','tag']:
				#Check if attribute exists
				if not entry.find(s):
					continue
				for member in entry.find(s).children:
					#Some tags are a newline, skip them
					if type(member) != Tag:
						continue
					aux[s].append(member.text)
			#Special iteration for profile setting
			if not entry.find('profile-setting'):
				aux['profile-setting'] = None
			elif entry.find('profile-setting').group:
				aux['profile-setting'] = {'type' : 'group', 'name' : entry.find('profile-setting').group.member.text if entry.find('profile-setting').group.find('member') else None}
			else:
				aux['profile-setting'] = {
				'type' : 'profile',
				'profiles' : {
						'url-filtering' : entry.find('url-filtering').member.text if entry.find('url-filtering') else None,
						'data-filtering' : entry.find('data-filtering').member.text if entry.find('data-filtering') else None,
						'file-blocking' : entry.find('file-blocking').member.text if entry.find('file-blocking') else None,
						'virus' : entry.find('virus').member.text if entry.find('virus') else None,
						'spyware' : entry.find('spyware').member.text if entry.find('url-filtering') else None,
						'vulnerability' : entry.find('vulnerability').member.text if entry.find('vulnerability') else None,
						'wildfire-analysis' : entry.find('wildfire-analysis').member.text if entry.find('wildfire-analysis') else None
					}
				}
			_entries.append(aux)
		_entries = self.filter(args,_entries)
		return {'len' : len(_entries), 'rules' : _entries}
	def post(self,data):
		response = self.apicall(type='config',\
							action='get',\
							xpath="/config/devices/entry[@name='localhost.localdomain']/vsys/entry[@name='vsys1']/rulebase/security/rules/entry[@name='{0}']".format(data['name']))
		if response.status_code != 200:
			logger.error("Palo Alto response: " + str(response.status_code))
			return {'error' : str(response.text)}, 502
		soup = BeautifulSoup(response.text,'xml')	
		if not soup.result.isSelfClosing:
			logger.warning("Rule already exists.")
			return {'error' : 'Rule already exists.'}, 409
		#Rule does not exists, add it.
		element = BeautifulSoup('','xml')
		for k,v in data.iteritems():
			if k == 'name':
				continue
			if k in ['negate-destination','negate-source','icmp-unreachable','log-start','log-end','disabled']:
				if v:
					element.append(element.new_tag(k))
					element.find(k).append('yes' if v else 'no')
			elif k in ['action','log-setting','rule-type','description','schedule']:
				if v:
					element.append(element.new_tag(k))
					element.find(k).append(v)
			elif k in ['from','to','source','destination','source-user','tag','category','application','service','hip-profiles']:
				element.append(element.new_tag(k))
				if type(v) != list:
					logger.warning('{0} must be a list.'.format(k))
					return {'error' : '{0} must be a list.'.format(k)}, 400
				for d in v:
					element.find(k).append(element.new_tag('member'))
					element.find(k).find_all('member')[-1].append(d)
			elif k == 'disable-server-response-inspection':
				if type(v) != bool:
					logger.warning('{0} must be a boolean.'.format(k))
					return {'error' : '{0} must be a boolean.'.format(k)}, 400
				element.append(element.new_tag('option'))
				element.option.append(element.new_tag('disable-server-response-inspection'))
				element.find('disable-server-response-inspection').append('yes' if v else 'no')
			elif k == 'qos':
				element.append(element.new_tag('qos'))
				if v['marking'] in ['ip-precedence','ip-dscp','folow-c2s-flow']:
					element.qos.append(element.new_tag('marking'))
					element.qos.marking.append(element.new_tag(v['marking']))
					if v['type']:
						element.find(v).append(v['type'])
			elif k == 'profile-setting':
				element.append(element.new_tag('profile-setting'))
				if v['type'] == 'profile':
					element.find('profile-setting').append(element.new_tag('profiles'))
					for _k,_v in v['profiles'].iteritems():
						if _v:
							element.find('profile-setting').append(element.new_tag(_k))
							element.find(_k).append(element.new_tag('member'))
							element.find(_k).member.append(_v)
				elif v['type'] == 'group':
					element.find('profile-setting').append(element.new_tag('group'))
					if v['name']:
						element.find('profile-setting').group.append(element.new_tag('member'))
						element.find('profile-setting').group.member.append(v['name'])
			else:
				logger.warning('{0} not a valid rule parameter.'.format(k))
				return {'error' : '{0} not a valid rule parameter.'.format(k)}, 400
		element = str(element).replace('<?xml version="1.0" encoding="utf-8"?>\n','')
		response = self.apicall(type='config',\
								action='set',\
								xpath="/config/devices/entry[@name='localhost.localdomain']/vsys/entry[@name='vsys1']/rulebase/security/rules/entry[@name='{0}']".format(data['name']),\
								element=element)
		if response.status_code != 200:
			logger.error("Palo Alto response: " + str(response.status_code))
			return {'error' : str(response.text)}, 502
		soup = BeautifulSoup(response.text,'xml')
		if soup.response['status'] != 'success':
			logger.warning("Rule badly formatted: " + str(response.status_code))
			return {'error' : 'Rule badly formatted.'}, 400
		else:
			return data, 201
	def patch(self,name,data):
		response = self.apicall(type='config',\
							action='get',\
							xpath="/config/devices/entry[@name='localhost.localdomain']/vsys/entry[@name='vsys1']/rulebase/security/rules/entry[@name='{0}']".format(name))
		if response.status_code != 200:
			logger.error("Palo Alto response: " + str(response.status_code))
			return {'error' : str(response.text)}, 502
		soup = BeautifulSoup(response.text,'xml')	
		if soup.result.isSelfClosing:
			logger.warning("Rule does not exists.")
			return {'error' : 'Rule does not exists.'}, 400
		else:
			entry = soup.find('entry')
		#Rule exists, patch it
		element = BeautifulSoup('','xml')
		for k,v in data.iteritems():
			if k == 'name':
				continue
			if k in ['negate-destination','negate-source','icmp-unreachable','log-start','log-end','disabled']:
				if v:
					element.append(element.new_tag(k))
					element.find(k).append('yes' if v else 'no')
			elif k in ['action','log-setting','rule-type','description','schedule']:
				if v:
					element.append(element.new_tag(k))
					element.find(k).append(v)
			elif k in ['from','to','source','destination','source-user','tag','category','application','service','hip-profiles']:
				element.append(element.new_tag(k))
				if type(v) != list:
					logger.warning('{0} must be a list.'.format(k))
					return {'error' : '{0} must be a list.'.format(k)}, 400
				for d in v:
					element.find(k).append(element.new_tag('member'))
					element.find(k).find_all('member')[-1].append(d)
			elif k == 'disable-server-response-inspection':
				if type(v) != bool:
					logger.warning('{0} must be a boolean.'.format(k))
					return {'error' : '{0} must be a boolean.'.format(k)}, 400
				element.append(element.new_tag('option'))
				element.option.append(element.new_tag('disable-server-response-inspection'))
				element.find('disable-server-response-inspection').append('yes' if v else 'no')
			elif k == 'qos':
				element.append(element.new_tag('qos'))
				if v['marking'] in ['ip-precedence','ip-dscp','folow-c2s-flow']:
					element.qos.append(element.new_tag('marking'))
					element.qos.marking.append(element.new_tag(v['marking']))
					if v['type']:
						element.find(v).append(v['type'])
			elif k == 'profile-setting':
				element.append(element.new_tag('profile-setting'))
				if v['type'] == 'profile':
					element.find('profile-setting').append(element.new_tag('profiles'))
					for _k,_v in v['profiles'].iteritems():
						if _v:
							element.find('profile-setting').append(element.new_tag(_k))
							element.find(_k).append(element.new_tag('member'))
							element.find(_k).member.append(_v)
				elif v['type'] == 'group':
					element.find('profile-setting').append(element.new_tag('group'))
					if v['name']:
						element.find('profile-setting').group.append(element.new_tag('member'))
						element.find('profile-setting').group.member.append(v['name'])
			else:
				logger.warning('{0} not a valid rule parameter.'.format(k))
				return {'error' : '{0} not a valid rule parameter.'.format(k)}, 400
		element = str(element).replace('<?xml version="1.0" encoding="utf-8"?>\n','')
		response = self.apicall(type='config',\
								action='set',\
								xpath="/config/devices/entry[@name='localhost.localdomain']/vsys/entry[@name='vsys1']/rulebase/security/rules/entry[@name='{0}']".format(name),\
								element=element)
		if response.status_code != 200:
			logger.error("Palo Alto response: " + str(response.status_code))
			return {'error' : str(response.text)}, 502
		soup = BeautifulSoup(response.text,'xml')
		if soup.response['status'] != 'success':
			logger.warning("Rule badly formatted: " + str(response.status_code))
			return {'error' : 'Rule badly formatted.'}, 400
		else:
			aux = {
			'name' : entry['name'],
			'from' : list(),
			'to' : list(),
			'source' : list(),
			'destination' : list(),
			'action' : entry.find('action').text,
			'application' : list(),
			'category' : list(),
			'description' : entry.find('description').text if entry.find('description') else None,
			'disabled' : False if not entry.find('disabled') else True if entry.find('disabled').text == 'yes' else False,
			'hip-profiles' : list(),
			'icmp-unreachable' : False if not entry.find('icmp-unreachable') else True if entry.find('icmp-unreachable').text == 'yes' else False,
			'log-end' : False if not entry.find('log-end') else True if entry.find('log-end').text == 'yes' else False,
			'log-setting' : entry.find('log-setting').text if entry.find('log-setting') else None,
			'log-start' : False if not entry.find('log-start') else True if entry.find('log-start').text == 'yes' else False,
			'negate-destination' : False if not entry.find('negate-destination') else True if entry.find('negate-destination').text == 'yes' else False,
			'negate-source' : False if not entry.find('negate-source') else True if entry.find('negate-source').text == 'yes' else False,
			'disable-server-response-inspection' : False if not entry.find('disable-server-response-inspection') else True if entry.find('disable-server-response-inspection').text == 'yes' else False,
			'profile-setting' : dict(),
			'qos' : {'marking' : entry.marking.next_element.next_element.name if entry.find('marking') else None, 'type' :  entry.marking.next_element.next_element.text if entry.find('marking') else None},
			'rule-type' : entry.find('rule-type').text if entry.find('rule-type') else 'universal',
			'schedule' : entry.schedule.text if entry.find('schedule') else None,
			'service' : list(),
			'source-user' : list(),
			'tag' : list()
			}
			#Iterate all lists
			for s in ['from','to','source','destination','application','category','hip.profiles','service','source-user','tag']:
				#Check if attribute exists
				if not entry.find(s):
					continue
				for member in entry.find(s).children:
					#Some tags are a newline, skip them
					if type(member) != Tag:
						continue
					aux[s].append(member.text)
			#Special iteration for profile setting
			if not entry.find('profile-setting'):
				aux['profile-setting'] = None
			elif entry.find('profile-setting').group:
				aux['profile-setting'] = {'type' : 'group', 'name' : entry.find('profile-setting').group.member.text if entry.find('profile-setting').group.find('member') else None}
			else:
				aux['profile-setting'] = {
				'type' : 'profile',
				'profiles' : {
						'url-filtering' : entry.find('url-filtering').member.text if entry.find('url-filtering') else None,
						'data-filtering' : entry.find('data-filtering').member.text if entry.find('data-filtering') else None,
						'file-blocking' : entry.find('file-blocking').member.text if entry.find('file-blocking') else None,
						'virus' : entry.find('virus').member.text if entry.find('virus') else None,
						'spyware' : entry.find('spyware').member.text if entry.find('url-filtering') else None,
						'vulnerability' : entry.find('vulnerability').member.text if entry.find('vulnerability') else None,
						'wildfire-analysis' : entry.find('wildfire-analysis').member.text if entry.find('wildfire-analysis') else None
					}
				}
			for k,v in data.iteritems():
				if type(aux[k]) == list:
					aux[k].append(v)
				else:
					aux[k] = v
			return aux, 200
	def put(self,name,data):
		response = self.apicall(type='config',\
							action='get',\
							xpath="/config/devices/entry[@name='localhost.localdomain']/vsys/entry[@name='vsys1']/rulebase/security/rules/entry[@name='{0}']".format(name))
		if response.status_code != 200:
			logger.error("Palo Alto response: " + str(response.status_code))
			return {'error' : str(response.text)}, 502
		soup = BeautifulSoup(response.text,'xml')	
		if soup.result.isSelfClosing:
			logger.warning("Rule does not exists.")
			return {'error' : 'Rule does not exists.'}, 400
		else:
			element = soup.find('entry')
		#Rule exists, patch it
		for k,v in data.iteritems():
			if k == 'name':
				continue
			if k in ['negate-destination','negate-source','icmp-unreachable','log-start','log-end','disabled']:
				if v:
					if not element.find(k):
						element.append(soup.new_tag(k))
					else:
						element.find(k).clear()
					element.find(k).append('yes' if v else 'no')
			elif k in ['action','log-setting','rule-type','description','schedule']:
				if v:
					if not element.find(k):
						element.append(soup.new_tag(k))
					else:
						element.find(k).clear()
					element.find(k).append(v)
			elif k in ['from','to','source','destination','source-user','tag','category','application','service','hip-profiles']:
				if not element.find(k):
					element.append(soup.new_tag(k))
				else:
					element.find(k).clear()
				if type(v) != list:
					logger.warning('{0} must be a list.'.format(k))
					return {'error' : '{0} must be a list.'.format(k)}, 400
				for d in v:
					element.find(k).append(soup.new_tag('member'))
					element.find(k).find_all('member')[-1].append(d)
			elif k == 'disable-server-response-inspection':
				if type(v) != bool:
					logger.warning('{0} must be a boolean.'.format(k))
					return {'error' : '{0} must be a boolean.'.format(k)}, 400
				if not element.find('option'):
					element.append(soup.new_tag('option'))
				else:
					element.find('option').clear()
				element.option.append(element.new_tag('disable-server-response-inspection'))
				element.find('disable-server-response-inspection').append('yes' if v else 'no')
			elif k == 'qos':
				if not element.find(k):
					element.append(soup.new_tag(k))
				else:
					element.find(k).clear()
				if v['marking'] in ['ip-precedence','ip-dscp','folow-c2s-flow']:
					element.qos.append(soup.new_tag('marking'))
					element.qos.marking.append(soup.new_tag(v['marking']))
					if v['type']:
						element.find(v).append(v['type'])
			elif k == 'profile-setting':
				if not element.find(k):
					element.append(soup.new_tag(k))
				else:
					element.find(k).clear()
				if v['type'] == 'profile':
					element.find('profile-setting').append(soup.new_tag('profiles'))
					for _k,_v in v['profiles'].iteritems():
						if _v:
							element.find('profile-setting').append(soup.new_tag(_k))
							element.find(_k).append(soup.new_tag('member'))
							element.find(_k).member.append(_v)
				elif v['type'] == 'group':
					element.find('profile-setting').append(soup.new_tag('group'))
					if v['name']:
						element.find('profile-setting').group.append(soup.new_tag('member'))
						element.find('profile-setting').group.member.append(v['name'])
			else:
				logger.warning('{0} not a valid rule parameter.'.format(k))
				return {'error' : '{0} not a valid rule parameter.'.format(k)}, 400
		logger.debug("Element: {0}".format(str(element).replace('<?xml version="1.0" encoding="utf-8"?>\n','')))
		response = self.apicall(type='config',\
								action='edit',\
								xpath="/config/devices/entry[@name='localhost.localdomain']/vsys/entry[@name='vsys1']/rulebase/security/rules/entry[@name='{0}']".format(name),\
								element=str(element).replace('<?xml version="1.0" encoding="utf-8"?>\n',''))
		if response.status_code != 200:
			logger.error("Palo Alto response: " + str(response.status_code))
			return {'error' : str(response.text)}, 502
		soup = BeautifulSoup(response.text,'xml')
		if soup.response['status'] != 'success':
			logger.warning("Rule badly formatted: " + str(response.status_code))
			return {'error' : 'Rule badly formatted.'}, 400
		else:
			aux = {
			'name' : element['name'],
			'from' : list(),
			'to' : list(),
			'source' : list(),
			'destination' : list(),
			'action' : element.find('action').text,
			'application' : list(),
			'category' : list(),
			'description' : element.find('description').text if element.find('description') else None,
			'disabled' : False if not element.find('disabled') else True if element.find('disabled').text == 'yes' else False,
			'hip-profiles' : list(),
			'icmp-unreachable' : False if not element.find('icmp-unreachable') else True if element.find('icmp-unreachable').text == 'yes' else False,
			'log-end' : False if not element.find('log-end') else True if element.find('log-end').text == 'yes' else False,
			'log-setting' : element.find('log-setting').text if element.find('log-setting') else None,
			'log-start' : False if not element.find('log-start') else True if element.find('log-start').text == 'yes' else False,
			'negate-destination' : False if not element.find('negate-destination') else True if element.find('negate-destination').text == 'yes' else False,
			'negate-source' : False if not element.find('negate-source') else True if element.find('negate-source').text == 'yes' else False,
			'disable-server-response-inspection' : False if not element.find('disable-server-response-inspection') else True if element.find('disable-server-response-inspection').text == 'yes' else False,
			'profile-setting' : dict(),
			'qos' : {'marking' : element.marking.next_element.next_element.name if element.find('marking') else None, 'type' :  element.marking.next_element.next_element.text if element.find('marking') else None},
			'rule-type' : element.find('rule-type').text if element.find('rule-type') else 'universal',
			'schedule' : element.schedule.text if element.find('schedule') else None,
			'service' : list(),
			'source-user' : list(),
			'tag' : list()
			}
			#Iterate all lists
			for s in ['from','to','source','destination','application','category','hip.profiles','service','source-user','tag']:
				#Check if attribute exists
				if not element.find(s):
					continue
				for member in element.find(s).children:
					#Some tags are a newline, skip them
					if type(member) != Tag:
						continue
					aux[s].append(member.text)
			#Special iteration for profile setting
			if not element.find('profile-setting'):
				aux['profile-setting'] = None
			elif element.find('profile-setting').group:
				aux['profile-setting'] = {'type' : 'group', 'name' : element.find('profile-setting').group.member.text if element.find('profile-setting').group.find('member') else None}
			else:
				aux['profile-setting'] = {
				'type' : 'profile',
				'profiles' : {
						'url-filtering' : element.find('url-filtering').member.text if element.find('url-filtering') else None,
						'data-filtering' : element.find('data-filtering').member.text if element.find('data-filtering') else None,
						'file-blocking' : element.find('file-blocking').member.text if element.find('file-blocking') else None,
						'virus' : element.find('virus').member.text if element.find('virus') else None,
						'spyware' : element.find('spyware').member.text if element.find('url-filtering') else None,
						'vulnerability' : element.find('vulnerability').member.text if element.find('vulnerability') else None,
						'wildfire-analysis' : element.find('wildfire-analysis').member.text if element.find('wildfire-analysis') else None
					}
				}
			return aux, 200
	def delete(self,name):
		response = self.apicall(type='config',\
							action='get',\
							xpath="/config/devices/entry[@name='localhost.localdomain']/vsys/entry[@name='vsys1']/rulebase/security/rules/entry[@name='{0}']".format(name))
		if response.status_code != 200:
			logger.error("Palo Alto response: " + str(response.status_code))
			return {'error' : str(response.text)}, 502
		entry = BeautifulSoup(response.text,'xml')	
		if entry.result.isSelfClosing:
			logger.warning("Rule does not exists.")
			return {'error' : 'Rule does not exists.'}, 404
		else:
			entry = entry.find('entry')
		#Rule exists, delete it
		response = self.apicall(type='config',\
								action='delete',\
								xpath='/config/devices/entry[@name="localhost.localdomain"]/vsys/entry[@name="vsys1"]/rulebase/security/rules/entry[@name="{0}"]'.format(name))
		if response.status_code != 200:
			logger.error("Palo Alto response: " + str(response.status_code))
			return {'error' : str(response.text)}, 502
		else:
			logger.info("Rule {0} deleted.".format(name))
			aux = {
			'name' : entry['name'],
			'from' : list(),
			'to' : list(),
			'source' : list(),
			'destination' : list(),
			'action' : entry.find('action').text,
			'application' : list(),
			'category' : list(),
			'description' : entry.find('description').text if entry.find('description') else None,
			'disabled' : False if not entry.find('disabled') else True if entry.find('disabled').text == 'yes' else False,
			'hip-profiles' : list(),
			'icmp-unreachable' : False if not entry.find('icmp-unreachable') else True if entry.find('icmp-unreachable').text == 'yes' else False,
			'log-end' : False if not entry.find('log-end') else True if entry.find('log-end').text == 'yes' else False,
			'log-setting' : entry.find('log-setting').text if entry.find('log-setting') else None,
			'log-start' : False if not entry.find('log-start') else True if entry.find('log-start').text == 'yes' else False,
			'negate-destination' : False if not entry.find('negate-destination') else True if entry.find('negate-destination').text == 'yes' else False,
			'negate-source' : False if not entry.find('negate-source') else True if entry.find('negate-source').text == 'yes' else False,
			'disable-server-response-inspection' : False if not entry.find('disable-server-response-inspection') else True if entry.find('disable-server-response-inspection').text == 'yes' else False,
			'profile-setting' : dict(),
			'qos' : {'marking' : entry.marking.next_element.next_element.name if entry.find('marking') else None, 'type' :  entry.marking.next_element.next_element.text if entry.find('marking') else None},
			'rule-type' : entry.find('rule-type').text if entry.find('rule-type') else 'universal',
			'schedule' : entry.schedule.text if entry.find('schedule') else None,
			'service' : list(),
			'source-user' : list(),
			'tag' : list()
			}
			#Iterate all lists
			for s in ['from','to','source','destination','application','category','hip.profiles','service','source-user','tag']:
				#Check if attribute exists
				if not entry.find(s):
					continue
				for member in entry.find(s).children:
					#Some tags are a newline, skip them
					if type(member) != Tag:
						continue
					aux[s].append(member.text)
			#Special iteration for profile setting
			if not entry.find('profile-setting'):
				aux['profile-setting'] = None
			elif entry.find('profile-setting').group:
				aux['profile-setting'] = {'type' : 'group', 'name' : entry.find('profile-setting').group.member.text if entry.find('profile-setting').group.find('member') else None}
			else:
				aux['profile-setting'] = {
				'type' : 'profile',
				'profiles' : {
						'url-filtering' : entry.find('url-filtering').member.text if entry.find('url-filtering') else None,
						'data-filtering' : entry.find('data-filtering').member.text if entry.find('data-filtering') else None,
						'file-blocking' : entry.find('file-blocking').member.text if entry.find('file-blocking') else None,
						'virus' : entry.find('virus').member.text if entry.find('virus') else None,
						'spyware' : entry.find('spyware').member.text if entry.find('url-filtering') else None,
						'vulnerability' : entry.find('vulnerability').member.text if entry.find('vulnerability') else None,
						'wildfire-analysis' : entry.find('wildfire-analysis').member.text if entry.find('wildfire-analysis') else None
					}
				}
			return aux, 200
class rules_move(PAN):
	def post(self,where,rule1,rule2=None):
		if where in ['top','bottom']:
			response = self.apicall(type='config',\
						action='move',\
						xpath="/config/devices/entry[@name='localhost.localdomain']/vsys/entry[@name='vsys1']/rulebase/security/rules/entry[@name='{0}']".format(rule1),\
						where=where)
			if response.status_code != 200:
				logger.error("Palo Alto response: " + str(response.status_code))
				return {'error' : str(response.text)}, 502
			elif BeautifulSoup(response.text,'xml').response['status'] != 'success':
				logger.error("Palo Alto response: " + str(response.status_code))
				return {'error' : str(response.text)}, 502
			else:
				return {'where' : where, 'rule1' : rule1}
		elif where in ['before', 'after'] and rule2:
			response = self.apicall(type='config',\
						action='move',\
						xpath="/config/devices/entry[@name='localhost.localdomain']/vsys/entry[@name='vsys1']/rulebase/security/rules/entry[@name='{0}']".format(rule1),\
						where=where,\
						dst=rule2)
			if response.status_code != 200:
				logger.error("Palo Alto response: " + str(response.status_code))
				return {'error' : str(response.text)}, 502
			elif BeautifulSoup(response.text,'xml').response['status'] != 'success':
				logger.error("Palo Alto response: " + str(response.status_code))
				return {'error' : str(response.text)}, 502
			else:
				return {'where' : where, 'rule1' : rule1, 'rule2' : rule2}
		else:
			logger.warning("'where' not in 'after', 'before', 'top', 'bottom' or 'rule2' not present.")
			return {'error' : "'where' not in 'after', 'before', 'top', 'bottom' or 'rule2' not present."}, 400
class rules_rename(PAN):
	def post(self,oldname,newname):
		response = self.apicall(type='config',\
					action='rename',\
					xpath="/config/devices/entry[@name='localhost.localdomain']/vsys/entry[@name='vsys1']/rulebase/security/rules/entry[@name='{0}']".format(oldname),\
					newname=newname)
		if response.status_code != 200:
			logger.error("Palo Alto response: " + str(response.status_code))
			return {'error' : str(response.text)}, 502
		elif BeautifulSoup(response.text,'xml').response['status'] != 'success':
			logger.error("Palo Alto response: " + str(response.status_code))
			return {'error' : str(response.text)}, 502
		else:
			logger.info("Rule {0} renamed to {1}.".format(oldname,newname))
			response = self.apicall(type='config',\
								action='get',\
								xpath='/config/devices/entry[@name="localhost.localdomain"]/vsys/entry[@name="vsys1"]/rulebase/security/rules/entry[@name="{0}"]'.format(newname))
			if response.status_code != 200:
				logger.error("Palo Alto response: " + str(response.status_code))
				return {'error' : str(response.text)}, 502
			elif BeautifulSoup(response.text,'xml').response['status'] != 'success':
				logger.error("Palo Alto response: " + str(response.status_code))
				return {'error' : str(response.text)}, 502
			else:
				entry = BeautifulSoup(response.text,'xml').entry
			aux = {
			'name' : entry['name'],
			'from' : list(),
			'to' : list(),
			'source' : list(),
			'destination' : list(),
			'action' : entry.find('action').text,
			'application' : list(),
			'category' : list(),
			'description' : entry.find('description').text if entry.find('description') else None,
			'disabled' : False if not entry.find('disabled') else True if entry.find('disabled').text == 'yes' else False,
			'hip-profiles' : list(),
			'icmp-unreachable' : False if not entry.find('icmp-unreachable') else True if entry.find('icmp-unreachable').text == 'yes' else False,
			'log-end' : False if not entry.find('log-end') else True if entry.find('log-end').text == 'yes' else False,
			'log-setting' : entry.find('log-setting').text if entry.find('log-setting') else None,
			'log-start' : False if not entry.find('log-start') else True if entry.find('log-start').text == 'yes' else False,
			'negate-destination' : False if not entry.find('negate-destination') else True if entry.find('negate-destination').text == 'yes' else False,
			'negate-source' : False if not entry.find('negate-source') else True if entry.find('negate-source').text == 'yes' else False,
			'disable-server-response-inspection' : False if not entry.find('disable-server-response-inspection') else True if entry.find('disable-server-response-inspection').text == 'yes' else False,
			'profile-setting' : dict(),
			'qos' : {'marking' : entry.marking.next_element.next_element.name if entry.find('marking') else None, 'type' :  entry.marking.next_element.next_element.text if entry.find('marking') else None},
			'rule-type' : entry.find('rule-type').text if entry.find('rule-type') else 'universal',
			'schedule' : entry.schedule.text if entry.find('schedule') else None,
			'service' : list(),
			'source-user' : list(),
			'tag' : list()
			}
			#Iterate all lists
			for s in ['from','to','source','destination','application','category','hip.profiles','service','source-user','tag']:
				#Check if attribute exists
				if not entry.find(s):
					continue
				for member in entry.find(s).children:
					#Some tags are a newline, skip them
					if type(member) != Tag:
						continue
					aux[s].append(member.text)
			#Special iteration for profile setting
			if not entry.find('profile-setting'):
				aux['profile-setting'] = None
			elif entry.find('profile-setting').group:
				aux['profile-setting'] = {'type' : 'group', 'name' : entry.find('profile-setting').group.member.text if entry.find('profile-setting').group.find('member') else None}
			else:
				aux['profile-setting'] = {
				'type' : 'profile',
				'profiles' : {
						'url-filtering' : entry.find('url-filtering').member.text if entry.find('url-filtering') else None,
						'data-filtering' : entry.find('data-filtering').member.text if entry.find('data-filtering') else None,
						'file-blocking' : entry.find('file-blocking').member.text if entry.find('file-blocking') else None,
						'virus' : entry.find('virus').member.text if entry.find('virus') else None,
						'spyware' : entry.find('spyware').member.text if entry.find('url-filtering') else None,
						'vulnerability' : entry.find('vulnerability').member.text if entry.find('vulnerability') else None,
						'wildfire-analysis' : entry.find('wildfire-analysis').member.text if entry.find('wildfire-analysis') else None
					}
				}
			return aux
class rules_match(PAN):
	def get(self,args):
		if 'from' not in args or 'to' not in args or 'source' not in args or 'destination' not in args or 'protocol' not in args or 'port' not in args:
			logger.warning('Migging parameters.')
			return {'error' : 'Missing parameters.'}, 400
		soup = BeautifulSoup('<test><security-policy-match></security-policy-match></test>','xml')
		#from
		soup.find('security-policy-match').append(soup.new_tag('from'))
		soup.find('from').append(args['from'])
		#to
		soup.find('security-policy-match').append(soup.new_tag('to'))
		soup.find('to').append(args['to'])
		#source
		soup.find('security-policy-match').append(soup.new_tag('source'))
		soup.find('source').append(args['source'])
		#destination
		soup.find('security-policy-match').append(soup.new_tag('destination'))
		soup.find('destination').append(args['destination'])
		#protocol
		soup.find('security-policy-match').append(soup.new_tag('protocol'))
		soup.find('protocol').append('6' if args['protocol'].lower() == 'tcp' else '17')
		#port
		soup.find('security-policy-match').append(soup.new_tag('destination-port'))
		soup.find('destination-port').append(args['port'])
		if 'application' in args: 
			#application
			soup.find('security-policy-match').append(soup.new_tag('application'))
			soup.find('application').append(args['application'])
		if 'source-user' in args: 
			#source-user
			soup.find('security-policy-match').append(soup.new_tag('source-user'))
			soup.find('source-user').append(args['source-user'])
		if 'category' in args: 
			#category
			soup.find('security-policy-match').append(soup.new_tag('category'))
			soup.find('category').append(args['category'])
		response = self.apicall(type='op',\
								cmd=str(soup).replace('<?xml version="1.0" encoding="utf-8"?>\n',''))
		if response.status_code != 200:
			logger.error("Palo Alto response: " + str(response.status_code))
			return {'error' : str(response.text)}, 502
		soup = BeautifulSoup(response.text,'xml').entry
		aux = None
		if soup:
			response = self.apicall(type='config',\
					action='get',\
					xpath='/config/devices/entry[@name="localhost.localdomain"]/vsys/entry[@name="vsys1"]/rulebase/security/rules/entry[@name="{0}"]'.format(soup.text))
			if response.status_code != 200:
				logger.error("Palo Alto response: " + str(response.status_code))
				return {'error' : str(response.text)}, 502
			else:
				entry = BeautifulSoup(response.text,'xml').entry
				aux = {
				'name' : entry['name'],
				'from' : list(),
				'to' : list(),
				'source' : list(),
				'destination' : list(),
				'action' : entry.find('action').text,
				'application' : list(),
				'category' : list(),
				'description' : entry.find('description').text if entry.find('description') else None,
				'disabled' : False if not entry.find('disabled') else True if entry.find('disabled').text == 'yes' else False,
				'hip-profiles' : list(),
				'icmp-unreachable' : False if not entry.find('icmp-unreachable') else True if entry.find('icmp-unreachable').text == 'yes' else False,
				'log-end' : False if not entry.find('log-end') else True if entry.find('log-end').text == 'yes' else False,
				'log-setting' : entry.find('log-setting').text if entry.find('log-setting') else None,
				'log-start' : False if not entry.find('log-start') else True if entry.find('log-start').text == 'yes' else False,
				'negate-destination' : False if not entry.find('negate-destination') else True if entry.find('negate-destination').text == 'yes' else False,
				'negate-source' : False if not entry.find('negate-source') else True if entry.find('negate-source').text == 'yes' else False,
				'disable-server-response-inspection' : False if not entry.find('disable-server-response-inspection') else True if entry.find('disable-server-response-inspection').text == 'yes' else False,
				'profile-setting' : dict(),
				'qos' : {'marking' : entry.marking.next_element.next_element.name if entry.find('marking') else None, 'type' :  entry.marking.next_element.next_element.text if entry.find('marking') else None},
				'rule-type' : entry.find('rule-type').text if entry.find('rule-type') else 'universal',
				'schedule' : entry.schedule.text if entry.find('schedule') else None,
				'service' : list(),
				'source-user' : list(),
				'tag' : list()
				}
				#Iterate all lists
				for s in ['from','to','source','destination','application','category','hip.profiles','service','source-user','tag']:
					#Check if attribute exists
					if not entry.find(s):
						continue
					for member in entry.find(s).children:
						#Some tags are a newline, skip them
						if type(member) != Tag:
							continue
						aux[s].append(member.text)
				#Special iteration for profile setting
				if not entry.find('profile-setting'):
					aux['profile-setting'] = None
				elif entry.find('profile-setting').group:
					aux['profile-setting'] = {'type' : 'group', 'name' : entry.find('profile-setting').group.member.text if entry.find('profile-setting').group.find('member') else None}
				else:
					aux['profile-setting'] = {
					'type' : 'profile',
					'profiles' : {
							'url-filtering' : entry.find('url-filtering').member.text if entry.find('url-filtering') else None,
							'data-filtering' : entry.find('data-filtering').member.text if entry.find('data-filtering') else None,
							'file-blocking' : entry.find('file-blocking').member.text if entry.find('file-blocking') else None,
							'virus' : entry.find('virus').member.text if entry.find('virus') else None,
							'spyware' : entry.find('spyware').member.text if entry.find('url-filtering') else None,
							'vulnerability' : entry.find('vulnerability').member.text if entry.find('vulnerability') else None,
							'wildfire-analysis' : entry.find('wildfire-analysis').member.text if entry.find('wildfire-analysis') else None
						}
					}
		return {'allowed' : False if not soup else False if aux['action'] != 'allow' else False, 'policy' : aux}
class objects(PAN):
	def get(self,args,object):
		response = self.apicall(type='config',\
								action='get',\
								xpath="/config/devices/entry[@name='localhost.localdomain']/vsys/entry[@name='vsys1']/{0}".format(object))
		if response.status_code != 200:
			logger.error("Palo Alto response: " + str(response.status_code))
			return {'error' : str(response.text)}, 502
		_entries = list()
		for entry in BeautifulSoup(response.text,'xml').find(object).children:
			if type(entry) != Tag:
				continue
			if object == 'address':
				aux = {
					'name' : entry['name'],
					'type' : 'ip-netmask' if entry.find('ip-netmask') else 'fqdn' if entry.find('fqdn') else 'ip-range' if entry.find('ip-range') else None,
					'value' : entry.find('ip-netmask').text if entry.find('ip-netmask') else entry.find('fqdn').text if entry.find('fqdn') else entry.find('ip-range').text if entry.find('ip-range') else None,
					'description' : entry.find('description').text if entry.find('description') else None,
					'tag' : list() if entry.find('tag') else None
					}
				if type(aux['tag']) == list:
					for tag in entry.find('tag').children:
						if type(tag) != Tag:
							continue
						aux['tag'].append(tag.text)
				_entries.append(aux)
			elif object == 'service':
				aux = {
					'name' : entry['name'],
					'destination-port' : entry.find('port').text if entry.find('port') else None,
					'source-port' : entry.find('source-port').text if entry.find('source-port') else None,
					'description' : entry.find('description').text if entry.find('description') else None,
					'protocol' : 'tcp' if entry.find('tcp') else 'udp' if entry.find('udp') else None,
					'tag' : list() if entry.find('tag') else None
					}
				if type(aux['tag']) == list:
					for tag in entry.find('tag').children:
						if type(tag) != Tag:
							continue
						aux['tag'].append(tag.text)
				_entries.append(aux)
			elif object == 'service-group':
				aux = {
					'name' : entry['name'],
					'tag' : list() if entry.find('tag') else None,
					'value' : list()
					}
				for member in entry.find('members').children:
					if type(member) != Tag:
						continue
					aux['value'].append(member.text)
				if type(aux['tag']) == list:
					for tag in entry.find('tag').children:
						if type(tag) != Tag:
							continue
						aux['tag'].append(tag.text)
				_entries.append(aux)
			elif object == 'address-group':
				aux = {
					'name' : entry['name'],
					'description' : entry.find('description').text if entry.find('description') else None,
					'type' : 'static' if entry.find('static') else 'dynamic' if entry.find('dynamic') else None,
					'tag' : list() if entry.find('tag') else None,
					}
				if aux['type'] == 'static':
					aux['static'] = list()
					for member in entry.find('static').children:
						if type(member) != Tag:
							continue
						aux['static'].append(member.text)
				elif aux['type'] == 'dynamic':
					aux['filter'] = entry.find('filter').text if entry.find('filter') else None
				if type(aux['tag']) == list:
					for tag in entry.find('tag').children:
						if type(tag) != Tag:
							continue
						aux['tag'].append(tag.text)
				_entries.append(aux)
		_entries = self.filter(args,_entries)
		return {'len' : len(_entries), 'objects' : _entries}
	def post(self,data,object):
		response = self.apicall(type='config',\
								action='get',\
								xpath="/config/devices/entry[@name='localhost.localdomain']/vsys/entry[@name='vsys1']/{0}/entry[@name='{1}']".format(object,data['name']))
		if response.status_code != 200:
			logger.error("Palo Alto response: " + str(response.status_code))
			return {'error' : str(response.text)}, 502
		soup = BeautifulSoup(response.text,'xml')	
		if not soup.result.isSelfClosing:
			logger.warning("{0} already exists.".format(object))
			return {'error' : "{0} already exists.".format(object)}, 409
		#Object does not exists, create it
		element = BeautifulSoup('','xml')
		if object == 'address':
			element.append(element.new_tag(data['type']))
			element.find(data['type']).append(data['value'])
			if 'tag' in data:
				if data['tag']:
					element.append(element.new_tag(data['tag']))
					for t in data['tag']:
						element.tag.append(element.new_tag('member'))
						element.tag.find_all('member')[-1].append(t)
			if 'description' in data:
				if data['description']:
					element.append(element.new_tag('description'))
					element.description.append(data['description'])
		elif object == 'service':
			if 'description' in data:
				if data['description']:
					element.append(element.new_tag('description'))
					element.description.append(data['description'])
			if 'tag' in data:
				if data['tag']:
					element.append(element.new_tag('tag'))
					for t in data['tag']:
						element.tag.append(element.new_tag('member'))
						element.tag.find_all('member')[-1].append(t)
			element.append(element.new_tag('protocol'))
			element.protocol.append(element.new_tag(data['protocol']))
			element.find(data['protocol']).append(element.new_tag('port'))
			if 'destination-port' in data:
				if data['destination-port']:
					element.port.append(data['destination-port'])
			if 'source-port' in data:
				if data['source-port']:
					element.find(data['protocol']).append(element.new_tag('source-port'))
					element.find(data['source-port']).append(data['source-port'])
		elif object == 'address-group':
			if 'description' in data:
				if data['description']:
					element.append(element.new_tag('description'))
					element.description.append(data['description'])
			if 'tag' in data:
				if data['tag']:
					element.append(element.new_tag('tag'))
					for t in data['tag']:
						element.tag.append(element.new_tag('member'))
						element.tag.find_all('member')[-1].append(t)
			if data['type'] == 'static':
				element.append(element.new_tag('static'))
				for d in data['static']:
					element.static.append(element.new_tag('member'))
					element.static.find_all('member')[-1].append(d)
			elif data['type'] == 'dynamic':
				element.append(element.new_tag(data['dynamic']))
				element.dynamic.append(element.new_tag(data['filter']))
				element.dynamic.filter.append(data['filter'])
		elif object == 'service-group':
			if 'tag' in data:
				if data['tag']:
					element.append(element.new_tag('tag'))
					for t in data['tag']:
						element.tag.append(element.new_tag('member'))
						element.tag.find_all('member')[-1].append(t)
			if 'value' in data:
				element.append(element.new_tag('members'))
				for d in data['value']:
					element.members.append(element.new_tag('member'))
					element.members.find_all('member')[-1].append(d)
		else:
			logger.warning("Object not found.")
			return {'error' : 'Object not found.'}, 404
		logger.debug(str(element).replace('<?xml version="1.0" encoding="utf-8"?>\n',''))
		response = self.apicall(type='config',\
					action='set',\
					xpath="/config/devices/entry[@name='localhost.localdomain']/vsys/entry[@name='vsys1']/{0}/entry[@name='{1}']".format(object,data['name']),\
					element=str(element).replace('<?xml version="1.0" encoding="utf-8"?>\n',''))
		if response.status_code != 200:
			logger.error("Palo Alto response: " + str(response.status_code))
			return {'error' : str(response.text)}, 502
		elif BeautifulSoup(response.text,'xml').response['status'] != 'success':
			logger.error("Palo Alto response: " + str(response.status_code))
			return {'error' : str(response.text)}, 502
		else:
			return data, 201
	def patch(self,data,object):
		response = self.apicall(type='config',\
					action='get',\
					xpath="/config/devices/entry[@name='localhost.localdomain']/vsys/entry[@name='vsys1']/{0}/entry[@name='{1}']".format(object,data['name']))
		if response.status_code != 200:
			logger.error("Palo Alto response: " + str(response.status_code))
			return {'error' : str(response.text)}, 502
		soup = BeautifulSoup(response.text,'xml')	
		if soup.result.isSelfClosing:
			logger.warning("Object does not exists.")
			return {'error' : 'Object does not exists.'}, 400
		element = BeautifulSoup('','xml')
		if object == 'address':
			element.append(element.new_tag(data['type']))
			element.find(data['type']).append(data['value'])
			if 'tag' in data:
				if data['tag']:
					element.append(element.new_tag(data['tag']))
					for t in data['tag']:
						element.tag.append(element.new_tag('member'))
						element.tag.find_all('member')[-1].append(t)
			if 'description' in data:
				if data['description']:
					element.append(element.new_tag('description'))
					element.description.append(data['description'])
		elif object == 'service':
			if 'description' in data:
				if data['description']:
					element.append(element.new_tag('description'))
					element.description.append(data['description'])
			if 'tag' in data:
				if data['tag']:
					element.append(element.new_tag('tag'))
					for t in data['tag']:
						element.tag.append(element.new_tag('member'))
						element.tag.find_all('member')[-1].append(t)
			element.append(element.new_tag('protocol'))
			element.protocol.append(element.new_tag(data['protocol']))
			element.find(data['protocol']).append(element.new_tag('port'))
			if 'destination-port' in data:
				if data['destination-port']:
					element.port.append(data['destination-port'])
			if 'source-port' in data:
				if data['source-port']:
					element.find(data['protocol']).append(element.new_tag('source-port'))
					element.find(data['source-port']).append(data['source-port'])
		elif object == 'address-group':
			if 'description' in data:
				if data['description']:
					element.append(element.new_tag('description'))
					element.description.append(data['description'])
			if 'tag' in data:
				if data['tag']:
					element.append(element.new_tag('tag'))
					for t in data['tag']:
						element.tag.append(element.new_tag('member'))
						element.tag.find_all('member')[-1].append(t)
			if 'static' in data:
				element.append(element.new_tag('static'))					
				for d in data['static']:
					element.static.append(element.new_tag('member'))
					element.static.find_all('member')[-1].append(d)
			elif 'filter' in data:	
				element.append(element.new_tag('dynamic'))
				element.dynamic.append(element.new_tag('filter'))
				element.dynamic.filter.append(data['filter'])
		elif object == 'service-group':
			if 'tag' in data:
				if data['tag']:
					element.append(element.new_tag('tag'))
					for t in data['tag']:
						element.tag.append(element.new_tag('member'))
						element.tag.find_all('member')[-1].append(t)
			if 'value' in data:
				element.append(element.new_tag('members'))
				for d in data['value']:
					element.members.append(element.new_tag('member'))
					element.members.find_all('member')[-1].append(d)
		else:
			logger.warning("Object not found.")
			return {'error' : 'Object not found.'}, 404
		logger.debug(str(element).replace('<?xml version="1.0" encoding="utf-8"?>\n',''))
		response = self.apicall(type='config',\
					action='set',\
					xpath="/config/devices/entry[@name='localhost.localdomain']/vsys/entry[@name='vsys1']/{0}/entry[@name='{1}']".format(object,data['name']),\
					element=str(element).replace('<?xml version="1.0" encoding="utf-8"?>\n',''))
		if response.status_code != 200:
			logger.error("Palo Alto response: " + str(response.status_code))
			return {'error' : str(response.text)}, 502
		elif BeautifulSoup(response.text,'xml').response['status'] != 'success':
			logger.error("Palo Alto response: " + str(response.status_code))
			return {'error' : str(response.text)}, 502
		else:
			aux = dict()
			entry = soup.entry
			if object == 'address':
				aux = {
					'name' : entry['name'],
					'type' : 'ip-netmask' if entry.find('ip-netmask') else 'fqdn' if entry.find('fqdn') else 'ip-range' if entry.find('ip-range') else None,
					'value' : entry.find('ip-netmask').text if entry.find('ip-netmask') else entry.find('fqdn').text if entry.find('fqdn') else entry.find('ip-range').text if entry.find('ip-range') else None,
					'description' : entry.find('description').text if entry.find('description') else None,
					'tag' : list() if entry.find('tag') else None
					}
				if type(aux['tag']) == list:
					for tag in entry.find('tag').children:
						if type(tag) != Tag:
							continue
						aux['tag'].append(tag.text)
			elif object == 'service':
				aux = {
					'name' : entry['name'],
					'destination-port' : entry.find('port').text if entry.find('port') else None,
					'source-port' : entry.find('source-port').text if entry.find('source-port') else None,
					'description' : entry.find('description').text if entry.find('description') else None,
					'protocol' : 'tcp' if entry.find('tcp') else 'udp' if entry.find('udp') else None,
					'tag' : list() if entry.find('tag') else None
					}
				if type(aux['tag']) == list:
					for tag in entry.find('tag').children:
						if type(tag) != Tag:
							continue
						aux['tag'].append(tag.text)
			elif object == 'service-group':
				aux = {
					'name' : entry['name'],
					'tag' : list() if entry.find('tag') else None,
					'value' : list()
					}
				for member in entry.find('members').children:
					if type(member) != Tag:
						continue
					aux['value'].append(member.text)
				if type(aux['tag']) == list:
					for tag in entry.find('tag').children:
						if type(tag) != Tag:
							continue
						aux['tag'].append(tag.text)
			elif object == 'address-group':
				aux = {
					'name' : entry['name'],
					'description' : entry.find('description').text if entry.find('description') else None,
					'type' : 'static' if entry.find('static') else 'dynamic' if entry.find('dynamic') else None,
					'tag' : list() if entry.find('tag') else None,
					}
				if aux['type'] == 'static':
					aux['static'] = list()
					for member in entry.find('static').children:
						if type(member) != Tag:
							continue
						aux['static'].append(member.text)
				elif aux['type'] == 'dynamic':
					aux['filter'] = entry.find('filter').text if entry.find('filter') else None
				if type(aux['tag']) == list:
					for tag in entry.find('tag').children:
						if type(tag) != Tag:
							continue
						aux['tag'].append(tag.text)
			for k,v in data.iteritems():
				if type(aux[k]) == list:
					if type(v) == list:
						for _v in v:
							if _v not in aux[k]:
								aux[k].append(_v)
					else:	
						aux[k].append(v)
				else:
					aux[k] = v
			return aux, 200
	def put(self,data,object):
		response = self.apicall(type='config',\
					action='get',\
					xpath="/config/devices/entry[@name='localhost.localdomain']/vsys/entry[@name='vsys1']/{0}/entry[@name='{1}']".format(object,data['name']))
		if response.status_code != 200:
			logger.error("Palo Alto response: " + str(response.status_code))
			return {'error' : str(response.text)}, 502
		soup = BeautifulSoup(response.text,'xml')	
		if soup.result.isSelfClosing:
			logger.warning("Object does not exists.")
			return {'error' : 'Object does not exists.'}, 400
		element = BeautifulSoup('','xml')
		if object == 'address':
			if 'value' in data:
				element.append(element.new_tag(data['type'] if 'type' in data else soup.entry.next_element.next_element.name))
				element.find(data['type'] if 'type' in data else soup.entry.next_element.name).append(data['value'])
			if 'tag' in data:
				if data['tag']:
					element.append(element.new_tag(data['tag']))
					for t in data['tag']:
						element.tag.append(element.new_tag('member'))
						element.tag.find_all('member')[-1].append(t)
			if 'description' in data:
				if data['description']:
					element.append(element.new_tag('description'))
					element.description.append(data['description'])
		elif object == 'service':
			if 'description' in data:
				if data['description']:
					element.append(element.new_tag('description'))
					element.description.append(data['description'])
			if 'tag' in data:
				if data['tag']:
					element.append(element.new_tag('tag'))
					for t in data['tag']:
						element.tag.append(element.new_tag('member'))
						element.tag.find_all('member')[-1].append(t)
			if 'destination-port' in data:
				if data['destination-port']:
					element.append(element.new_tag('protocol'))
					element.protocol.append(element.new_tag(data['protocol'] if 'protocol' in data else soup.entry.protocol.next_element.next_element.name))
					element.find(data['protocol'] if 'protocol' in data else soup.entry.protocol.next_element.next_element.name).append(element.new_tag('port'))
					element.port.append(data['destination-port'])
			if 'source-port' in data:
				if data['source-port']:
					element.append(element.new_tag('protocol'))
					element.protocol.append(element.new_tag(data['protocol'] if 'protocol' in data else soup.entry.protocol.next_element.next_element.name))
					element.find(data['protocol'] if 'protocol' in data else soup.entry.protocol.next_element.next_element.name).append(element.new_tag('source-port'))
					element.find(data['source-port']).append(data['source-port'])
		elif object == 'address-group':
			element.append(element.new_tag('entry'))
			element.entry['name'] = data['name']
			if 'description' in data:
				if data['description']:
					element.entry.append(element.new_tag('description'))
					element.description.append(data['description'])
			if 'tag' in data:
				if data['tag']:
					element.entry.append(element.new_tag('tag'))
					for t in data['tag']:
						element.tag.append(element.new_tag('member'))
						element.tag.find_all('member')[-1].append(t)
			if 'static' in data:
				element.entry.append(element.new_tag('static'))
				for d in data['static']:
					element.static.append(element.new_tag('member'))
					element.static.find_all('member')[-1].append(d)
			elif 'filter' in data:	
				element.entry.append(element.new_tag('dynamic'))
				element.dynamic.append(element.new_tag('filter'))
				element.dynamic.filter.append(data['filter'])
		elif object == 'service-group':
			element.append(element.new_tag('entry'))
			element.entry['name'] = data['name']
			if 'tag' in data:
				if data['tag']:
					element.entry.append(element.new_tag('tag'))
					for t in data['tag']:
						element.tag.append(element.new_tag('member'))
						element.tag.find_all('member')[-1].append(t)
			if 'value' in data:
				element.entry.append(element.new_tag('members'))
				for d in data['value']:
					element.members.append(element.new_tag('member'))
					element.members.find_all('member')[-1].append(d)
		else:
			logger.warning("Object not found.")
			return {'error' : 'Object not found.'}, 404
		logger.debug(str(element).replace('<?xml version="1.0" encoding="utf-8"?>\n',''))
		response = self.apicall(type='config',\
					action='edit' if object in ['address-group','service-group'] else 'set',\
					xpath="/config/devices/entry[@name='localhost.localdomain']/vsys/entry[@name='vsys1']/{0}/entry[@name='{1}']".format(object,data['name']),\
					element=str(element).replace('<?xml version="1.0" encoding="utf-8"?>\n',''))
		if response.status_code != 200:
			logger.error("Palo Alto response: " + str(response.status_code))
			return {'error' : str(response.text)}, 502
		elif BeautifulSoup(response.text,'xml').response['status'] != 'success':
			logger.error("Palo Alto response: " + str(response.text))
			return {'error' : str(response.text)}, 502
		else:
			aux = dict()
			entry = soup.entry
			if object == 'address':
				aux = {
					'name' : entry['name'],
					'type' : 'ip-netmask' if entry.find('ip-netmask') else 'fqdn' if entry.find('fqdn') else 'ip-range' if entry.find('ip-range') else None,
					'value' : entry.find('ip-netmask').text if entry.find('ip-netmask') else entry.find('fqdn').text if entry.find('fqdn') else entry.find('ip-range').text if entry.find('ip-range') else None,
					'description' : entry.find('description').text if entry.find('description') else None,
					'tag' : list() if entry.find('tag') else None
					}
				if type(aux['tag']) == list:
					for tag in entry.find('tag').children:
						if type(tag) != Tag:
							continue
						aux['tag'].append(tag.text)
			elif object == 'service':
				aux = {
					'name' : entry['name'],
					'destination-port' : entry.find('port').text if entry.find('port') else None,
					'source-port' : entry.find('source-port').text if entry.find('source-port') else None,
					'description' : entry.find('description').text if entry.find('description') else None,
					'protocol' : 'tcp' if entry.find('tcp') else 'udp' if entry.find('udp') else None,
					'tag' : list() if entry.find('tag') else None
					}
				if type(aux['tag']) == list:
					for tag in entry.find('tag').children:
						if type(tag) != Tag:
							continue
						aux['tag'].append(tag.text)
			elif object == 'service-group':
				aux = {
					'name' : entry['name'],
					'tag' : list() if entry.find('tag') else None,
					'value' : list()
					}
				for member in entry.find('members').children:
					if type(member) != Tag:
						continue
					aux['value'].append(member.text)
				if type(aux['tag']) == list:
					for tag in entry.find('tag').children:
						if type(tag) != Tag:
							continue
						aux['tag'].append(tag.text)
			elif object == 'address-group':
				aux = {
					'name' : entry['name'],
					'description' : entry.find('description').text if entry.find('description') else None,
					'type' : 'static' if entry.find('static') else 'dynamic' if entry.find('dynamic') else None,
					'tag' : list() if entry.find('tag') else None,
					}
				if aux['type'] == 'static':
					aux['static'] = list()
					for member in entry.find('static').children:
						if type(member) != Tag:
							continue
						aux['static'].append(member.text)
				elif aux['type'] == 'dynamic':
					aux['filter'] = entry.find('filter').text if entry.find('filter') else None
				if type(aux['tag']) == list:
					for tag in entry.find('tag').children:
						if type(tag) != Tag:
							continue
						aux['tag'].append(tag.text)
			for k,v in data.iteritems():
				if type(aux[k]) == list:
					if type(v) == list:
						aux[k] = list()
						for _v in v:
							aux[k].append(_v)
				else:
					aux[k] = v
			return aux, 200
	def delete(self,name,object):
		response = self.apicall(type='config',\
								action='get',\
								xpath="/config/devices/entry[@name='localhost.localdomain']/vsys/entry[@name='vsys1']/{0}/entry[@name='{1}']".format(object,name))
		if response.status_code != 200:
			logger.error("Palo Alto response: " + str(response.status_code))
			return {'error' : str(response.text)}, 502
		entry = BeautifulSoup(response.text,'xml')	
		if entry.result.isSelfClosing:
			logger.warning("Rule does not exists.")
			return {'error' : 'Rule does not exists.'}, 404
		else:
			entry = entry.find('entry')
		#Object exists, delete it
		response = self.apicall(type='config',\
								action='delete',\
								xpath="/config/devices/entry[@name='localhost.localdomain']/vsys/entry[@name='vsys1']/{0}/entry[@name='{1}']".format(object,name))
		if response.status_code != 200:
			logger.error("Palo Alto response: " + str(response.status_code))
			return {'error' : str(response.text)}, 502
		elif BeautifulSoup(response.text,'xml').response['status'] != 'success':
			logger.error("Palo Alto response: " + str(response.status_code))
			return {'error' : str(response.text)}, 502
		else:
			if object == 'address':
				aux = {
					'name' : entry['name'],
					'type' : 'ip-netmask' if entry.find('ip-netmask') else 'fqdn' if entry.find('fqdn') else 'ip-range' if entry.find('ip-range') else None,
					'value' : entry.find('ip-netmask').text if entry.find('ip-netmask') else entry.find('fqdn').text if entry.find('fqdn') else entry.find('ip-range').text if entry.find('ip-range') else None,
					'description' : entry.find('description').text if entry.find('description') else None,
					'tag' : list() if entry.find('tag') else None
					}
				if type(aux['tag']) == list:
					for tag in entry.find('tag').children:
						if type(tag) != Tag:
							continue
						aux['tag'].append(tag.text)
			elif object == 'service':
				aux = {
					'name' : entry['name'],
					'destination-port' : entry.find('port').text if entry.find('port') else None,
					'source-port' : entry.find('source-port').text if entry.find('source-port') else None,
					'description' : entry.find('description').text if entry.find('description') else None,
					'protocol' : 'tcp' if entry.find('tcp') else 'udp' if entry.find('udp') else None,
					'tag' : list() if entry.find('tag') else None
					}
				if type(aux['tag']) == list:
					for tag in entry.find('tag').children:
						if type(tag) != Tag:
							continue
						aux['tag'].append(tag.text)
			elif object == 'address-group':
				aux = {
					'name' : entry['name'],
					'description' : entry.find('description').text if entry.find('description') else None,
					'type' : 'static' if entry.find('static') else 'dynamic' if entry.find('dynamic') else None,
					'tag' : list() if entry.find('tag') else None,
					}
				if aux['type'] == 'static':
					aux['static'] = list()
					for member in entry.find('static').children:
						if type(member) != Tag:
							continue
						aux['static'].append(member.text)
				elif aux['type'] == 'dynamic':
					aux['filter'] = entry.find('filter').text if entry.find('filter') else None
				if type(aux['tag']) == list:
					for tag in entry.find('tag').children:
						if type(tag) != Tag:
							continue
						aux['tag'].append(tag.text)
			elif object == 'service-group':
				aux = {
					'name' : entry['name'],
					'tag' : list() if entry.find('tag') else None,
					'value' : list()
					}
				for member in entry.find('members').children:
					if type(member) != Tag:
						continue
					aux['value'].append(member.text)
				if type(aux['tag']) == list:
					for tag in entry.find('tag').children:
						if type(tag) != Tag:
							continue
						aux['tag'].append(tag.text)
			else:
				logger.error("Unknown error.")
				return {'error' : 'Unknown error.'}, 500
			return aux, 200
class objects_rename(PAN):
	def post(self,object,oldname,newname):
		response = self.apicall(type='config',\
					action='rename',\
					xpath="/config/devices/entry[@name='localhost.localdomain']/vsys/entry[@name='vsys1']/{0}/entry[@name='{1}']".format(object,oldname),\
					newname=newname)
		if response.status_code != 200:
			logger.error("Palo Alto response: " + str(response.status_code))
			return {'error' : str(response.text)}, 502
		elif BeautifulSoup(response.text,'xml').response['status'] != 'success':
			logger.error("Palo Alto response: " + str(response.status_code))
			return {'error' : str(response.text)}, 502
		else:
			logger.info("Object {0} {1} renamed to {2}.".format(object,oldname,newname))
			response = self.apicall(type='config',\
								action='get',\
								xpath="/config/devices/entry[@name='localhost.localdomain']/vsys/entry[@name='vsys1']/{0}/entry[@name='{1}']".format(object,newname))
			if response.status_code != 200:
				logger.error("Palo Alto response: " + str(response.status_code))
				return {'error' : str(response.text)}, 502
			elif BeautifulSoup(response.text,'xml').response['status'] != 'success':
				logger.error("Palo Alto response: " + str(response.status_code))
				return {'error' : str(response.text)}, 502
			else:
				entry = BeautifulSoup(response.text,'xml')
			if object == 'address':
				aux = {
					'name' : entry['name'],
					'type' : 'ip-netmask' if entry.find('ip-netmask') else 'fqdn' if entry.find('fqdn') else 'ip-range' if entry.find('ip-range') else None,
					'value' : entry.find('ip-netmask').text if entry.find('ip-netmask') else entry.find('fqdn').text if entry.find('fqdn') else entry.find('ip-range').text if entry.find('ip-range') else None,
					'description' : entry.find('description').text if entry.find('description') else None,
					'tag' : list() if entry.find('tag') else None
					}
				if type(aux['tag']) == list:
					for tag in entry.find('tag').children:
						if type(tag) != Tag:
							continue
						aux['tag'].append(tag.text)
			elif object == 'service':
				aux = {
					'name' : entry['name'],
					'destination-port' : entry.find('port').text if entry.find('port') else None,
					'source-port' : entry.find('source-port').text if entry.find('source-port') else None,
					'description' : entry.find('description').text if entry.find('description') else None,
					'protocol' : 'tcp' if entry.find('tcp') else 'udp' if entry.find('udp') else None,
					'tag' : list() if entry.find('tag') else None
					}
				if type(aux['tag']) == list:
					for tag in entry.find('tag').children:
						if type(tag) != Tag:
							continue
						aux['tag'].append(tag.text)
			elif object == 'address-group':
				aux = {
					'name' : entry['name'],
					'description' : entry.find('description').text if entry.find('description') else None,
					'type' : 'static' if entry.find('static') else 'dynamic' if entry.find('dynamic') else None,
					'tag' : list() if entry.find('tag') else None,
					}
				if aux['type'] == 'static':
					aux['static'] = list()
					for member in entry.find('static').children:
						if type(member) != Tag:
							continue
						aux['static'].append(member.text)
				elif aux['type'] == 'dynamic':
					aux['filter'] = entry.find('filter').text if entry.find('filter') else None
				if type(aux['tag']) == list:
					for tag in entry.find('tag').children:
						if type(tag) != Tag:
							continue
						aux['tag'].append(tag.text)
			elif object == 'service-group':
				aux = {
					'name' : entry['name'],
					'tag' : list() if entry.find('tag') else None,
					'value' : list()
					}
				for member in entry.find('members').children:
					if type(member) != Tag:
						continue
					aux['value'].append(member.text)
				if type(aux['tag']) == list:
					for tag in entry.find('tag').children:
						if type(tag) != Tag:
							continue
						aux['tag'].append(tag.text)
			else:
				logger.error("Unknown error.")
				return {'error' : 'Unknown error.'}, 500
			return aux, 200
class interfaces(PAN):
	def get(self,args):
		response = self.apicall(type='op',\
							cmd="<show><interface>all</interface></show>")
		if response.status_code != 200:
			logger.error("Palo Alto response: " + str(response.status_code))
			return {'error' : str(response.text)}, 502
		logger.debug(str(response.text))
		entries = list()
		for entry in BeautifulSoup(response.text,'xml').find_all('entry'):
			entries.append({
				'name' : entry.find('name').text,
				'zone' : entry.zone.text if entry.zone else None,
				'virtual-router' : None if not entry.fwd else  entry.fwd.text.strip('vr:') if entry.fwd.text != 'N/A' else None,
				'tag' : entry.tag.text if entry.tag else None,
				'ip' : None if not entry.ip else  entry.ip.text if entry.ip.text != 'N/A' else None,
				'id' : entry.id.text				
			})
		return {'interfaces' : self.filter(args,entries)}
class route(PAN):
	def get(self,args):
		response = self.apicall(type='op',\
								cmd='<show><routing><route></route></routing></show>')
		if response.status_code != 200:
			logger.error("Palo Alto response: " + str(response.status_code))
			return {'error' : str(response.text)}, 502
		entries = list()
		for entry in BeautifulSoup(response.text,'xml').find_all('entry'):
			entries.append({
				'virtual-router' : entry.find('virtual-router').text,
				'destination' : entry.destination.text,
				'nexthop' : entry.nexthop.text,
				'metric' : int(entry.metric.text) if entry.metric.text else None,
				'interface' : entry.interface.text,
				'age' : entry.age.text if entry.age.text else None,
				'flags' : {
						'active' : True if 'A' in entry.flags.text else False,
						'loose' : True if '?' in entry.flags.text else False,
						'connect' : True if 'C' in entry.flags.text else False,
						'host' : True if 'H' in entry.flags.text else False,
						'static' : True if 'S' in entry.flags.text else False,
						'internal' : True if '~' in entry.flags.text else False,
						'rip' : True if 'R' in entry.flags.text else False,
						'ospf' : True if 'O' in entry.flags.text else False,
						'bgp' : True if 'B' in entry.flags.text else False,
						'ospf-intra-area' : True if 'Oi' in entry.flags.text else False,
						'ospf-inter-area' : True if 'Oo' in entry.flags.text else False,
						'ospf-external-1' : True if 'O1' in entry.flags.text else False,
						'ospf-external-2' : True if 'O1' in entry.flags.text else False,
						'ecmp' : True if 'E' in entry.flags.text else False
					}
				})
		return {'routes' : self.filter(args,entries)}
class lock(PAN):
	def get(self,option=None,admin=None):
		if option in ['commit-locks', 'config-locks']:
			if option == 'commit-locks':
				response = self.apicall(type='op',\
										cmd='<show><commit-locks></commit-locks></show>')
				if response.status_code != 200:
					logger.error("Palo Alto response: " + str(response.status_code))
					return {'error' : str(response.text)}, 502
				elif BeautifulSoup(response.text,'xml').response['status'] != 'success':
					logger.error("Palo Alto response: " + str(response.status_code))
					return {'error' : str(response.text)}, 400
				entries = list()
				for entry in BeautifulSoup(response.text,'xml').find_all('entry'):
					if admin:
						if admin == entry['name']:
							entries.append({
								'name' : entry['name'],
								'created' : entry.created.text,
								'last-activity' : entry.find('last-activity').text,
								'loggedin' : True if entry.loggedin.text == 'yes' else False,
								'comment' : entry.comment.text if entry.comment.text != '(null)' else None
								})
							break
					else:
						entries.append({
							'name' : entry['name'],
							'created' : entry.created.text,
							'last-activity' : entry.find('last-activity').text,
							'loggedin' : True if entry.loggedin.text == 'yes' else False,
							'comment' : entry.comment.text if entry.comment.text != '(null)' else None
							})
				return {'commit-locks' : entries}
			else:
				response = self.apicall(type='op',\
										cmd='<show><config-locks></config-locks></show>')
				if response.status_code != 200:
					logger.error("Palo Alto response: " + str(response.status_code))
					return {'error' : str(response.text)}, 502
				elif BeautifulSoup(response.text,'xml').response['status'] != 'success':
					logger.error("Palo Alto response: " + str(response.status_code))
					return {'error' : str(response.text)}, 400
				entries = list()
				for entry in BeautifulSoup(response.text,'xml').find_all('entry'):
					if admin:
						if admin == entry['name']:
							entries.append({
								'name' : entry['name'],
								'created' : entry.created.text,
								'last-activity' : entry.find('last-activity').text,
								'loggedin' : True if entry.loggedin.text == 'yes' else False,
								'comment' : entry.comment.text if entry.comment.text != '(null)' else None
								})
							break
					else:
						entries.append({
							'name' : entry['name'],
							'created' : entry.created.text,
							'last-activity' : entry.find('last-activity').text,
							'loggedin' : True if entry.loggedin.text == 'yes' else False,
							'comment' : entry.comment.text if entry.comment.text != '(null)' else None
							})
				return {'config-locks' : entries}
		else:
			response = self.apicall(type='op',\
									cmd='<show><commit-locks></commit-locks></show>')
			if response.status_code != 200:
				logger.error("Palo Alto response: " + str(response.status_code))
				return {'error' : str(response.text)}, 502
			elif BeautifulSoup(response.text,'xml').response['status'] != 'success':
					logger.error("Palo Alto response: " + str(response.status_code))
					return {'error' : str(response.text)}, 400
			entries = list()
			for entry in BeautifulSoup(response.text,'xml').find_all('entry'):
				entries.append({
					'name' : entry['name'],
					'created' : entry.created.text,
					'last-activity' : entry.find('last-activity').text,
					'loggedin' : True if entry.loggedin.text == 'yes' else False,
					'comment' : entry.comment.text if entry.comment.text != '(null)' else None
					})
			response = self.apicall(type='op',\
									cmd='<show><config-locks></config-locks></show>')
			if response.status_code != 200:
				logger.error("Palo Alto response: " + str(response.status_code))
				return {'error' : str(response.text)}, 502
			elif BeautifulSoup(response.text,'xml').response['status'] != 'success':
					logger.error("Palo Alto response: " + str(response.status_code))
					return {'error' : str(response.text)}, 400
			_entries = list()
			for entry in BeautifulSoup(response.text,'xml').find_all('entry'):
				_entries.append({
					'name' : entry['name'],
					'created' : entry.created.text,
					'last-activity' : entry.find('last-activity').text,
					'loggedin' : True if entry.loggedin.text == 'yes' else False,
					'comment' : entry.comment.text if entry.comment.text != '(null)' else None
					})
			return {'commit-locks' : entries, 'config-locks' : _entries, 'locked' : True if entries or _entries else False}
	def post(self,comment=None,option=None,admin=None):
		if option in ['commit-locks', 'config-locks']:
			if option == 'commit-locks':
				response = self.apicall(type='op',\
							cmd='<request><commit-lock><add>{0}</add></commit-lock></request>'.format("<comment>{0}</comment>".format(comment) if comment else ''))
				if response.status_code != 200:
					logger.error("Palo Alto response: " + str(response.status_code))
					return {'error' : str(response.text)}, 502
				elif BeautifulSoup(response.text,'xml').response['status'] != 'success':
					logger.error("Palo Alto response: " + str(response.status_code))
					return {'error' : str(response.text)}, 400
			else:
				response = self.apicall(type='op',\
							cmd='<request><config-lock><add>{0}</add></config-lock></request>'.format("<comment>{0}</comment>".format(comment) if comment else ''))
				if response.status_code != 200:
					logger.error("Palo Alto response: " + str(response.status_code))
					return {'error' : str(response.text)}, 502
				elif BeautifulSoup(response.text,'xml').response['status'] != 'success':
					logger.error("Palo Alto response: " + str(response.status_code))
					return {'error' : str(response.text)}, 400
		else:
			response = self.apicall(type='op',\
									cmd='<request><commit-lock><add>{0}</add></commit-lock></request>'.format("<comment>{0}</comment>".format(comment) if comment else ''))
			if response.status_code != 200:
				logger.error("Palo Alto response: " + str(response.status_code))
				return {'error' : str(response.text)}, 502
			elif BeautifulSoup(response.text,'xml').response['status'] != 'success':
					logger.error("Palo Alto response: " + str(response.status_code))
					return {'error' : str(response.text)}, 400
			else:
				logger.debug(str(response.text))
			response = self.apicall(type='op',\
							cmd='<request><config-lock><add>{0}</add></config-lock></request>'.format("<comment>{0}</comment>".format(comment) if comment else ''))
			if response.status_code != 200:
				logger.error("Palo Alto response: " + str(response.status_code))
				return {'error' : str(response.text)}, 502
			elif BeautifulSoup(response.text,'xml').response['status'] != 'success':
					logger.error("Palo Alto response: " + str(response.status_code))
					return {'error' : str(response.text)}, 400
			else:
				logger.debug(str(response.text))
		return self.get(option)
	def delete(self,option=None,admin=None):
		if option == 'commit-locks':
			if admin:
				response = self.apicall(type='op',\
										cmd='<request><commit-lock><remove><admin>{0}</admin></remove></commit-lock></request>'.format(admin))
				if response.status_code != 200:
					logger.error("Palo Alto response: " + str(response.status_code))
					return {'error' : str(response.text)}, 502
				elif BeautifulSoup(response.text,'xml').response['status'] != 'success' and 'Commit lock is not currently held by' not in BeautifulSoup(response.text,'xml').line.text:
					logger.error("Palo Alto response: " + str(response.status_code))
					return {'error' : str(response.text)}, 502
			else:
				response = self.apicall(type='op',\
										cmd='<request><commit-lock><remove></remove></commit-lock></request>')
				if response.status_code != 200:
					logger.error("Palo Alto response: " + str(response.status_code))
					return {'error' : str(response.text)}, 502
				elif BeautifulSoup(response.text,'xml').response['status'] != 'success':
					logger.error("Palo Alto response: " + str(response.status_code))
					return {'error' : str(response.text)}, 502
		elif option == 'config-locks':
			response = self.apicall(type='op',\
									cmd='<request><config-lock><remove /></config-lock></request>')
			if response.status_code != 200:
				logger.error("Palo Alto response: " + str(response.status_code))
				return {'error' : str(response.text)}, 502
			elif BeautifulSoup(response.text,'xml').response['status'] != 'success' and 'Config lock is not currently locked' not in BeautifulSoup(response.text,'xml').line.text:
				logger.error("Palo Alto response: " + str(response.status_code))
				return {'error' : str(response.text)}, 502
		else:
			response = self.apicall(type='op',\
						cmd='<request><commit-lock><remove></remove></commit-lock></request>')
			if response.status_code != 200:
				logger.error("Palo Alto response: " + str(response.status_code))
				return {'error' : str(response.text)}, 502
			elif BeautifulSoup(response.text,'xml').response['status'] != 'success' and 'Commit lock is not currently held by' not in BeautifulSoup(response.text,'xml').line.text:
				logger.error("Palo Alto response: " + str(response.status_code))
				return {'error' : str(response.text)}, 502
			else:
				logger.debug(str(response.text))
			response = self.apicall(type='op',\
						cmd='<request><config-lock><remove></remove></config-lock></request>')
			if response.status_code != 200:
				logger.error("Palo Alto response: " + str(response.status_code))
				return {'error' : str(response.text)}, 502
			elif BeautifulSoup(response.text,'xml').response['status'] != 'success' and 'Config lock is not currently locked' not in BeautifulSoup(response.text,'xml').line.text:
				logger.error("Palo Alto response: " + str(response.status_code))
				return {'error' : str(response.text)}, 502
			else:
				logger.debug(str(response.text))
		return self.get(option)
class commit(PAN):
	def get(self):
		response = self.apicall(type='op',\
								cmd="<show><jobs><processed></processed></jobs></show>")
		if response.status_code != 200:
			logger.error("Palo Alto response: " + str(response.status_code))
			return {'error' : str(response.text)}, 502
		elif BeautifulSoup(response.text,'xml').response['status'] != 'success':
			logger.error("Palo Alto response: " + str(response.status_code))
			return {'error' : str(response.text)}, 502
		else:
			soup = BeautifulSoup(response.text,'xml')
		fw_obj = list()
		for job in soup.response.result.find_all('job'):
			if job.type.text == 'Commit':
				aux = dict()
				for prop in job.find_all():
					aux[prop.name] = prop.text
				fw_obj.append(aux)
		return {'commit-jobs' : fw_obj}, 200
	def post(self):
		response = self.apicall(type='commit',\
								cmd="<commit><description /></commit>")
		if response.status_code != 200:
			logger.error("Palo Alto response: " + str(response.status_code))
			return {'error' : str(response.text)}, 502
		elif BeautifulSoup(response.text,'xml').response['status'] != 'success':
			logger.error("Palo Alto response: " + str(response.status_code))
			return {'commit' : False, 'error' : str(response.text)}, 502
		else:
			soup = BeautifulSoup(response.text,'xml')
		return {'commit' : True, 'id' : soup.job.text}, 201
class logging(PAN):
	def get(self):
		response = self.apicall(type='config',\
								action='get',\
								xpath="/config/devices/entry[@name='localhost.localdomain']/vsys/entry[@name='vsys1']/log-settings/profiles")
		if response.status_code != 200:
			logger.error("Palo Alto response: " + str(response.status_code))
			return {'error' : str(response.text)}, 502
		elif BeautifulSoup(response.text,'xml').response['status'] != 'success':
			logger.error("Palo Alto response: " + str(response.status_code))
			return {'commit' : False, 'error' : str(response.text)}, 502
		else:
			soup = BeautifulSoup(response.text,'xml')
		logging = list()
		for a in soup.response.result.profiles.find_all('entry'):
			logging.append(a['name'])
		return {'log-settings' : logging }