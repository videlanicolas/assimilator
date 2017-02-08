from flask_restful import Resource
from flask import request
from functools import wraps
import ConfigParser, re, json, logging
from app.modules.firewall import Firewall
import app.modules.PaloAlto as PaloAlto
import app.modules.Junos as Juniper

logger = logging.getLogger(__name__)

def require_appkey(view_function):
	@wraps(view_function)
	# the new, post-decoration function. Note *args and **kwargs here.
	def decorated_function(*args, **kwargs):
		logger.warning("{0} {1} {2} {3}".format(request.remote_addr, request.method, request.path, str(request.args)))
		logger.debug("data: {0}".format(request.form))
		config = ConfigParser.RawConfigParser()
		config.read('/etc/assimilator/assimilator.conf')
		with open(config.get('General','apikeyfile')) as f:
			apikeys = json.loads(f.read())
		if request.headers.get('key'):
			for k,v in apikeys.iteritems():
				if request.headers.get('key') == v['key']:
					for reg in v['token']:
						if re.search(reg['path'],request.url) and request.method in reg['method']:
							return view_function(*args, **kwargs)
					else:
						logger.warning("{0}: Path or method not allowed.".format(str(request.remote_addr)))
						return {'error' : 'Unauthorized.'}, 401
			else:
				logger.warning("{0}: Key invalid.".format(request.remote_addr))
				return {'error' : 'Unauthorized.'}, 401
		else:
			logger.warning("{0}: Request with no key.".format(request.remote_addr))
			return {'error' : 'No API key present.'}, 401
	return decorated_function

class config(Resource):
	@require_appkey
	def get(self,firewall):
		logger.debug('handler.config.get()')
		#Check if Firewall exists.
		fw = Firewall(firewall=firewall).getConfig()
		if not fw:
			logger.error('Firewall not found.')
			return {'error' : 'Firewall not found.'}, 404
		#Switch by Firewall Brand
		if fw['brand'] == "paloalto":
			c = PaloAlto.configuration(firewall_config=fw)
			if not c.primary:
				logger.error("Could not get {0} active ip.".format(firewall))
				return {'error' : 'Could not get firewall active IP.'}, 502
			else:
				logger.info("{0} active ip {1}".format(firewall, c.primary))
				return c.get()
		elif fw['brand'] == "juniper":
			c = Juniper.configuration(firewall)
			if not c.primary:
				logger.error("Could not get {0} active ip.".format(firewall))
				return {'error' : 'Could not get firewall active IP.'}, 502
			else:
				logger.info("{0} active ip {1}".format(firewall, c.primary))
				return c.get()
		elif fw['brand'] == "cisco":
			return Cisco.configuration(firewall)
		elif fw['brand'] == "aws":
			return Cisco.configuration(firewall)
		elif fw['brand'] == "checkpoint":
			return Checkpoint.configuration(firewall)
		elif fw['brand'] == "fortinet":
			return Fortinet.configuration(firewall)
		elif fw['brand'] == "pfsense":
			return PfSense.configuration(firewall)
		else:
			#That Firewall Brand does not exists.
			logger.error("{0}: Firewall brand not found.".format(request.remote_addr))
			return {'error' : 'URL not found.'}, 404
class rules(Resource):
	@require_appkey
	def get(self,firewall):
		logger.debug('handler.rules.get()')
		fw = Firewall(firewall=firewall).getConfig()
		if not fw:
			logger.error('Firewall not found.')
			return {'error' : 'Firewall not found.'}, 404
		if fw['brand'] == "paloalto":
			c = PaloAlto.rules(firewall_config=fw)
			if not c.primary:
				logger.error("Could not get {0} active ip.".format(firewall))
				return {'error' : 'Could not get firewall active IP.'}, 502
			else:
				logger.info("{0} active ip {1}".format(firewall, c.primary))
				return c.get(request.args)
		elif fw['brand'] == "juniper":
			c = Juniper.rules(firewall)
			if not c.primary:
				logger.error("Could not get {0} active ip.".format(firewall))
				return {'error' : 'Could not get firewall active IP.'}, 502
			else:
				logger.info("{0} active ip {1}".format(firewall, c.primary))
				return c.get(request.args)
		elif fw['brand'] == "cisco":
			return Cisco.configuration(firewall)
		elif fw['brand'] == "aws":
			return Cisco.configuration(firewall)
		elif fw['brand'] == "checkpoint":
			return Checkpoint.configuration(firewall)
		elif fw['brand'] == "fortinet":
			return Fortinet.configuration(firewall)
		elif fw['brand'] == "pfsense":
			return PfSense.configuration(firewall)
		else:
			#That Firewall Brand does not exists.
			logger.error("{0}: Firewall brand not found.".format(request.remote_addr))
			return {'error' : 'URL not found.'}, 404
	@require_appkey
	def post(self,firewall):
		logger.debug('handler.config.post()')
		fw = Firewall(firewall=firewall).getConfig()
		if not fw:
			logger.error('Firewall not found.')
			return {'error' : 'Firewall not found.'}, 404
		if fw['brand'] == "paloalto":
			c = PaloAlto.rules(firewall_config=fw)
			if not c.primary:
				logger.error("Could not get {0} active ip.".format(firewall))
				return {'error' : 'Could not get firewall active IP.'}, 502
			else:
				logger.info("{0} active ip {1}".format(firewall, c.primary))
				if not request.json:
					return {'error' : 'Content type needs to be application/json.'}, 400
				else:
					return c.post(request.json)
		elif fw['brand'] == "juniper":
			return Cisco.configuration(firewall)
		elif fw['brand'] == "cisco":
			return Cisco.configuration(firewall)
		elif fw['brand'] == "aws":
			return Cisco.configuration(firewall)
		elif fw['brand'] == "checkpoint":
			return Checkpoint.configuration(firewall)
		elif fw['brand'] == "fortinet":
			return Fortinet.configuration(firewall)
		elif fw['brand'] == "pfsense":
			return PfSense.configuration(firewall)
		else:
			#That Firewall Brand does not exists.
			logger.error("{0}: Firewall brand not found.".format(request.remote_addr))
			return {'error' : 'URL not found.'}, 404
	@require_appkey
	def patch(self,firewall):
		logger.debug('handler.config.patch()')
		fw = Firewall(firewall=firewall).getConfig()
		if not fw:
			logger.error('Firewall not found.')
			return {'error' : 'Firewall not found.'}, 404
		if fw['brand'] == "paloalto":
			c = PaloAlto.rules(firewall_config=fw)
			if not c.primary:
				logger.error("Could not get {0} active ip.".format(firewall))
				return {'error' : 'Could not get firewall active IP.'}, 502
			else:
				logger.info("{0} active ip {1}".format(firewall, c.primary))
				if not request.json:
					return {'error' : 'Content type needs to be application/json.'}, 400
				elif 'name' not in request.args:
					return {'error' : 'No rule name supplied.'}, 400
				else:
					return c.patch(request.args['name'], request.json)
		elif fw['brand'] == "juniper":
			return Cisco.configuration(firewall)
		elif fw['brand'] == "cisco":
			return Cisco.configuration(firewall)
		elif fw['brand'] == "aws":
			return Cisco.configuration(firewall)
		elif fw['brand'] == "checkpoint":
			return Checkpoint.configuration(firewall)
		elif fw['brand'] == "fortinet":
			return Fortinet.configuration(firewall)
		elif fw['brand'] == "pfsense":
			return PfSense.configuration(firewall)
		else:
			#That Firewall Brand does not exists.
			logger.error("{0}: Firewall brand not found.".format(request.remote_addr))
			return {'error' : 'URL not found.'}, 404
	@require_appkey
	def put(self,firewall):
		logger.debug('handler.config.put()')
		fw = Firewall(firewall=firewall).getConfig()
		if not fw:
			logger.error('Firewall not found.')
			return {'error' : 'Firewall not found.'}, 404
		if fw['brand'] == "paloalto":
			c = PaloAlto.rules(firewall_config=fw)
			if not c.primary:
				logger.error("Could not get {0} active ip.".format(firewall))
				return {'error' : 'Could not get firewall active IP.'}, 502
			else:
				logger.info("{0} active ip {1}".format(firewall, c.primary))
				if not request.json:
					return {'error' : 'Content type needs to be application/json.'}, 400
				elif 'name' not in request.args:
					return {'error' : 'No rule name supplied.'}, 400
				else:
					return c.put(request.args['name'], request.json)
		elif fw['brand'] == "juniper":
			return Cisco.configuration(firewall)
		elif fw['brand'] == "cisco":
			return Cisco.configuration(firewall)
		elif fw['brand'] == "aws":
			return Cisco.configuration(firewall)
		elif fw['brand'] == "checkpoint":
			return Checkpoint.configuration(firewall)
		elif fw['brand'] == "fortinet":
			return Fortinet.configuration(firewall)
		elif fw['brand'] == "pfsense":
			return PfSense.configuration(firewall)
		else:
			#That Firewall Brand does not exists.
			logger.error("{0}: Firewall brand not found.".format(request.remote_addr))
			return {'error' : 'URL not found.'}, 404
	@require_appkey
	def delete(self,firewall):
		logger.debug('handler.config.delete()')
		fw = Firewall(firewall=firewall).getConfig()
		if not fw:
			logger.error('Firewall not found.')
			return {'error' : 'Firewall not found.'}, 404
		if fw['brand'] == "paloalto":
			c = PaloAlto.rules(firewall_config=fw)
			if not c.primary:
				logger.error("Could not get {0} active ip.".format(firewall))
				return {'error' : 'Could not get firewall active IP.'}, 502
			else:
				logger.info("{0} active ip {1}".format(firewall, c.primary))
				if 'name' not in request.args:
					logger.warning("No rule name given.")
					return {'error' : 'No rule name given.'}, 400
				else:
					return c.delete(request.args['name'])
		elif fw['brand'] == "juniper":
			return Cisco.configuration(firewall)
		elif fw['brand'] == "cisco":
			return Cisco.configuration(firewall)
		elif fw['brand'] == "aws":
			return Cisco.configuration(firewall)
		elif fw['brand'] == "checkpoint":
			return Checkpoint.configuration(firewall)
		elif fw['brand'] == "fortinet":
			return Fortinet.configuration(firewall)
		elif fw['brand'] == "pfsense":
			return PfSense.configuration(firewall)
		else:
			#That Firewall Brand does not exists.
			logger.error("{0}: Firewall brand not found.".format(request.remote_addr))
			return {'error' : 'URL not found.'}, 404
class rules_move(Resource):
	@require_appkey
	def post(self,firewall):
		logger.debug('handler.rules_move.post()')
		fw = Firewall(firewall=firewall).getConfig()
		if not fw:
			logger.error('Firewall not found.')
			return {'error' : 'Firewall not found.'}, 404
		if fw['brand'] == "paloalto":
			c = PaloAlto.rules_move(firewall_config=fw)
			if not c.primary:
				logger.error("Could not get {0} active ip.".format(firewall))
				return {'error' : 'Could not get firewall active IP.'}, 502
			else:
				logger.info("{0} active ip {1}".format(firewall, c.primary))
				if 'where' in request.json.keys() and 'rule1' in request.json.keys() and 'rule2' in request.json.keys():
					return c.post(request.json['where'],request.json['rule1'],request.json['rule2'])
				elif 'where' in request.json.keys() and 'rule1' in request.json.keys():
					return c.post(request.json['where'],request.json['rule1'])
				else:
					logger.warning("No 'where' or 'rule1' in request.")
					return {'error' : "No 'where' or 'rule1' in request."}, 400
		elif fw['brand'] == "juniper":
			c = Juniper.configuration(firewall)
			return c.get()
		elif fw['brand'] == "cisco":
			return Cisco.configuration(firewall)
		elif fw['brand'] == "checkpoint":
			return Checkpoint.configuration(firewall)
		elif fw['brand'] == "fortinet":
			return Fortinet.configuration(firewall)
		elif fw['brand'] == "pfsense":
			return PfSense.configuration(firewall)
		else:
			logger.error("{0}: Firewall brand not found.".format(request.remote_addr))
			return {'error' : 'URL not found.'}, 404
class rules_rename(Resource):
	@require_appkey
	def post(self,firewall):
		logger.debug('handler.rules_rename.post()')
		fw = Firewall(firewall=firewall).getConfig()
		if not fw:
			logger.error('Firewall not found.')
			return {'error' : 'Firewall not found.'}, 404
		if fw['brand'] == "paloalto":
			c = PaloAlto.rules_rename(firewall_config=fw)
			if not c.primary:
				logger.error("Could not get {0} active ip.".format(firewall))
				return {'error' : 'Could not get firewall active IP.'}, 502
			else:
				logger.info("{0} active ip {1}".format(firewall, c.primary))
				if 'oldname' not in request.json or 'newname' not in request.json:
					logger.warning("'oldname' or 'newname' not in request.")
					return {'error' : "'oldname' or 'newname' not in request."}, 400
				else:
					return c.post(request.json['oldname'],request.json['newname'])
		elif fw['brand'] == "juniper":
			c = Juniper.configuration(firewall)
			return c.get()
		elif fw['brand'] == "cisco":
			return Cisco.configuration(firewall)
		elif fw['brand'] == "checkpoint":
			return Checkpoint.configuration(firewall)
		elif fw['brand'] == "fortinet":
			return Fortinet.configuration(firewall)
		elif fw['brand'] == "pfsense":
			return PfSense.configuration(firewall)
		else:
			logger.error("{0}: Firewall brand not found.".format(request.remote_addr))
			return {'error' : 'URL not found.'}, 404
class rules_match(Resource):
	@require_appkey
	def get(self,firewall):
		logger.debug('handler.config.get()')
		fw = Firewall(firewall=firewall).getConfig()
		if not fw:
			logger.error('Firewall not found.')
			return {'error' : 'Firewall not found.'}, 404
		if fw['brand'] == "paloalto":
			c = PaloAlto.rules_match(firewall_config=fw)
			if not c.primary:
				logger.error("Could not get {0} active ip.".format(firewall))
				return {'error' : 'Could not get firewall active IP.'}, 502
			else:
				logger.info("{0} active ip {1}".format(firewall, c.primary))
				return c.get(request.args)
		elif fw['brand'] == "juniper":
			c = Juniper.match(firewall)
			if not c.primary:
				logger.error("Could not get {0} active ip.".format(firewall))
				return {'error' : 'Could not get firewall active IP.'}, 502
			else:
				logger.info("{0} active ip {1}".format(firewall, c.primary))
				return c.get(request.args)
		elif fw['brand'] == "cisco":
			return Cisco.configuration(firewall)
		elif fw['brand'] == "checkpoint":
			return Checkpoint.configuration(firewall)
		elif fw['brand'] == "fortinet":
			return Fortinet.configuration(firewall)
		elif fw['brand'] == "pfsense":
			return PfSense.configuration(firewall)
		else:
			logger.error("{0}: Firewall brand not found.".format(request.remote_addr))
			return {'error' : 'URL not found.'}, 404
class objects(Resource):
	@require_appkey
	def get(self,firewall,object):
		logger.debug('handler.config.get()')
		fw = Firewall(firewall=firewall).getConfig()
		if not fw:
			logger.error('Firewall not found.')
			return {'error' : 'Firewall not found.'}, 404
		if fw['brand'] == "paloalto":
			c = PaloAlto.objects(firewall_config=fw)
			if not c.primary:
				logger.error("Could not get {0} active ip.".format(firewall))
				return {'error' : 'Could not get firewall active IP.'}, 502
			else:
				logger.info("{0} active ip {1}".format(firewall, c.primary))
				return c.get(request.args,object)
		elif fw['brand'] == "juniper":
			c = Juniper.objects(firewall)
			if not c.primary:
				logger.error("Could not get {0} active ip.".format(firewall))
				return {'error' : 'Could not get firewall active IP.'}, 502
			else:
				logger.info("{0} active ip {1}".format(firewall, c.primary))
				return c.get(request.args,object)
		elif fw['brand'] == "cisco":
			return Cisco.configuration(firewall)
		elif fw['brand'] == "checkpoint":
			return Checkpoint.configuration(firewall)
		elif fw['brand'] == "fortinet":
			return Fortinet.configuration(firewall)
		elif fw['brand'] == "pfsense":
			return PfSense.configuration(firewall)
		else:
			logger.error("{0}: Firewall brand not found.".format(request.remote_addr))
			return {'error' : 'URL not found.'}, 404
	@require_appkey
	def post(self,firewall,object):
		logger.debug('handler.objects.post()')
		fw = Firewall(firewall=firewall).getConfig()
		if not fw:
			logger.error('Firewall not found.')
			return {'error' : 'Firewall not found.'}, 404
		if fw['brand'] == "paloalto":
			c = PaloAlto.objects(firewall_config=fw)
			if not c.primary:
				logger.error("Could not get {0} active ip.".format(firewall))
				return {'error' : 'Could not get firewall active IP.'}, 502
			else:
				logger.info("{0} active ip {1}".format(firewall, c.primary))
				if not request.json:
					return {'error' : 'Content type needs to be application/json.'}, 400
				else:
					return c.post(request.json,object)
		elif fw['brand'] == "juniper":
			c = Juniper.configuration(firewall)
			return c.get()
		elif fw['brand'] == "cisco":
			return Cisco.configuration(firewall)
		elif fw['brand'] == "checkpoint":
			return Checkpoint.configuration(firewall)
		elif fw['brand'] == "fortinet":
			return Fortinet.configuration(firewall)
		elif fw['brand'] == "pfsense":
			return PfSense.configuration(firewall)
		else:
			logger.error("{0}: Firewall brand not found.".format(request.remote_addr))
			return {'error' : 'URL not found.'}, 404
	@require_appkey
	def patch(self,firewall,object):
		logger.debug('handler.objects.patch()')
		fw = Firewall(firewall=firewall).getConfig()
		if not fw:
			logger.error('Firewall not found.')
			return {'error' : 'Firewall not found.'}, 404
		if fw['brand'] == "paloalto":
			c = PaloAlto.objects(firewall_config=fw)
			if not c.primary:
				logger.error("Could not get {0} active ip.".format(firewall))
				return {'error' : 'Could not get firewall active IP.'}, 502
			else:
				logger.info("{0} active ip {1}".format(firewall, c.primary))
				if not request.json:
					return {'error' : 'Content type needs to be application/json.'}, 400
				else:
					return c.patch(request.json,object)
		elif fw['brand'] == "juniper":
			c = Juniper.configuration(firewall)
			return c.get()
		elif fw['brand'] == "cisco":
			return Cisco.configuration(firewall)
		elif fw['brand'] == "checkpoint":
			return Checkpoint.configuration(firewall)
		elif fw['brand'] == "fortinet":
			return Fortinet.configuration(firewall)
		elif fw['brand'] == "pfsense":
			return PfSense.configuration(firewall)
		else:
			logger.error("{0}: Firewall brand not found.".format(request.remote_addr))
			return {'error' : 'URL not found.'}, 404
	@require_appkey
	def put(self,firewall,object):
		logger.debug('handler.objects.put()')
		fw = Firewall(firewall=firewall).getConfig()
		if not fw:
			logger.error('Firewall not found.')
			return {'error' : 'Firewall not found.'}, 404
		if fw['brand'] == "paloalto":
			c = PaloAlto.objects(firewall_config=fw)
			if not c.primary:
				logger.error("Could not get {0} active ip.".format(firewall))
				return {'error' : 'Could not get firewall active IP.'}, 502
			else:
				logger.info("{0} active ip {1}".format(firewall, c.primary))
				if not request.json:
					return {'error' : 'Content type needs to be application/json.'}, 400
				else:
					return c.put(request.json,object)
		elif fw['brand'] == "juniper":
			c = Juniper.configuration(firewall)
			return c.get()
		elif fw['brand'] == "cisco":
			return Cisco.configuration(firewall)
		elif fw['brand'] == "checkpoint":
			return Checkpoint.configuration(firewall)
		elif fw['brand'] == "fortinet":
			return Fortinet.configuration(firewall)
		elif fw['brand'] == "pfsense":
			return PfSense.configuration(firewall)
		else:
			logger.error("{0}: Firewall brand not found.".format(request.remote_addr))
			return {'error' : 'URL not found.'}, 404
	@require_appkey
	def delete(self,firewall,object):
		logger.debug('handler.objects.delete()')
		fw = Firewall(firewall=firewall).getConfig()
		if not fw:
			logger.error('Firewall not found.')
			return {'error' : 'Firewall not found.'}, 404
		if fw['brand'] == "paloalto":
			c = PaloAlto.objects(firewall_config=fw)
			if not c.primary:
				logger.error("Could not get {0} active ip.".format(firewall))
				return {'error' : 'Could not get firewall active IP.'}, 502
			else:
				logger.info("{0} active ip {1}".format(firewall, c.primary))
				if 'name' not in request.args:
					logger.warning("No rule name given.")
					return {'error' : 'No rule name given.'}, 400
				else:
					return c.delete(request.args['name'],object)
		elif fw['brand'] == "juniper":
			c = Juniper.configuration(firewall)
			return c.get()
		elif fw['brand'] == "cisco":
			return Cisco.configuration(firewall)
		elif fw['brand'] == "checkpoint":
			return Checkpoint.configuration(firewall)
		elif fw['brand'] == "fortinet":
			return Fortinet.configuration(firewall)
		elif fw['brand'] == "pfsense":
			return PfSense.configuration(firewall)
		else:
			logger.error("{0}: Firewall brand not found.".format(request.remote_addr))
			return {'error' : 'URL not found.'}, 404
class objects_rename(Resource):
	@require_appkey
	def post(self,firewall,object):
		logger.debug('handler.rules_rename.get()')
		fw = Firewall(firewall=firewall).getConfig()
		if not fw:
			logger.error('Firewall not found.')
			return {'error' : 'Firewall not found.'}, 404
		if fw['brand'] == "paloalto":
			c = PaloAlto.objects_rename(firewall_config=fw)
			if not c.primary:
				logger.error("Could not get {0} active ip.".format(firewall))
				return {'error' : 'Could not get firewall active IP.'}, 502
			else:
				logger.info("{0} active ip {1}".format(firewall, c.primary))
				if 'oldname' not in request.json or 'newname' not in request.json:
					logger.warning("'oldname' or 'newname' not in request.")
					return {'error' : "'oldname' or 'newname' not in request."}, 400
				elif option not in ['address', 'service', 'address-group', 'service-group']:
					logger.warning("{0} not found".format(option))
					return {'error' : "URL not found."}, 404
				else:
					return c.get(object,request.json['oldname'],request.json['newname'])
		elif fw['brand'] == "juniper":
			c = Juniper.configuration(firewall)
			return c.get()
		elif fw['brand'] == "cisco":
			return Cisco.configuration(firewall)
		elif fw['brand'] == "checkpoint":
			return Checkpoint.configuration(firewall)
		elif fw['brand'] == "fortinet":
			return Fortinet.configuration(firewall)
		elif fw['brand'] == "pfsense":
			return PfSense.configuration(firewall)
		else:
			logger.error("{0}: Firewall brand not found.".format(request.remote_addr))
			return {'error' : 'URL not found.'}, 404
class interfaces(Resource):
	@require_appkey
	def get(self,firewall):
		logger.debug('handler.config.get()')
		fw = Firewall(firewall=firewall).getConfig()
		if not fw:
			logger.error('Firewall not found.')
			return {'error' : 'Firewall not found.'}, 404
		if fw['brand'] == "paloalto":
			c = PaloAlto.interfaces(firewall_config=fw)
			if not c.primary:
				logger.error("Could not get {0} active ip.".format(firewall))
				return {'error' : 'Could not get firewall active IP.'}, 504
			else:
				logger.info("{0} active ip {1}".format(firewall, c.primary))
				return c.get(request.args)
		elif fw['brand'] == "juniper":
			c = Juniper.configuration(firewall)
			return c.get()
		elif fw['brand'] == "cisco":
			return Cisco.configuration(firewall)
		elif fw['brand'] == "checkpoint":
			return Checkpoint.configuration(firewall)
		elif fw['brand'] == "fortinet":
			return Fortinet.configuration(firewall)
		elif fw['brand'] == "pfsense":
			return PfSense.configuration(firewall)
		else:
			logger.error("{0}: Firewall brand not found.".format(request.remote_addr))
			return {'error' : 'URL not found.'}, 404
class route(Resource):
	@require_appkey
	def get(self,firewall):
		logger.debug('handler.route.get()')
		fw = Firewall(firewall=firewall).getConfig()
		if not fw:
			logger.error('Firewall not found.')
			return {'error' : 'Firewall not found.'}, 404
		if fw['brand'] == "paloalto":
			c = PaloAlto.route(firewall_config=fw)
			if not c.primary:
				logger.error("Could not get {0} active ip.".format(firewall))
				return {'error' : 'Could not get firewall active IP.'}, 504
			else:
				logger.info("{0} active ip {1}".format(firewall, c.primary))
				return c.get(request.args)
		elif fw['brand'] == "juniper":
			c = Juniper.route(firewall)
			if not c.primary:
				logger.error("Could not get {0} active ip.".format(firewall))
				return {'error' : 'Could not get firewall active IP.'}, 504
			else:
				logger.info("{0} active ip {1}".format(firewall, c.primary))
				return c.get(request.args['ip'])
		elif fw['brand'] == "cisco":
			return Cisco.configuration(firewall)
		elif fw['brand'] == "aws":
			return Cisco.configuration(firewall)
		elif fw['brand'] == "checkpoint":
			return Checkpoint.configuration(firewall)
		elif fw['brand'] == "fortinet":
			return Fortinet.configuration(firewall)
		elif fw['brand'] == "pfsense":
			return PfSense.configuration(firewall)
		else:
			#That Firewall Brand does not exists.
			logger.error("{0}: Firewall brand not found.".format(request.remote_addr))
			return {'error' : 'URL not found.'}, 404
##################################JUNIPER##################################
class hitcount(Resource):
	@require_appkey
	def get(self,brand,firewall):
		logger.debug('handler.route.get()')
		fw = Firewall(firewall=firewall).getConfig()
		if not fw:
			logger.error('Firewall not found.')
			return {'error' : 'Firewall not found.'}, 404
		c = Juniper.hitcount(firewall)
		if not c.primary:
			logger.error("Could not get {0} active ip.".format(firewall))
			return {'error' : 'Could not get firewall active IP.'}, 504
		else:
			logger.info("{0} active ip {1}".format(firewall, c.primary))
			return c.get()
##################################PALO ALTO##################################
class lock(Resource):
	@require_appkey
	def get(self,firewall):
		logger.debug('handler.lock.get()')
		fw = Firewall(firewall=firewall).getConfig()
		if not fw:
			logger.error('Firewall not found.')
			return {'error' : 'Firewall not found.'}, 404
		c = PaloAlto.lock(firewall_config=fw)
		if not c.primary:
			logger.error("Could not get {0} active ip.".format(firewall))
			return {'error' : 'Could not get firewall active IP.'}, 502
		else:
			logger.info("{0} active ip {1}".format(firewall, c.primary))
			return c.get()
	@require_appkey
	def post(self,firewall):
		logger.debug('handler.lock.post()')
		fw = Firewall(firewall=firewall).getConfig()
		if not fw:
			logger.error('Firewall not found.')
			return {'error' : 'Firewall not found.'}, 404
		c = PaloAlto.lock(firewall_config=fw)
		if not c.primary:
			logger.error("Could not get {0} active ip.".format(firewall))
			return {'error' : 'Could not get firewall active IP.'}, 502
		else:
			logger.info("{0} active ip {1}".format(firewall, c.primary))
			return c.post(None)
	@require_appkey
	def delete(self,firewall):
		logger.debug('handler.lock.delete()')
		fw = Firewall(firewall=firewall).getConfig()
		if not fw:
			logger.error('Firewall not found.')
			return {'error' : 'Firewall not found.'}, 404
		c = PaloAlto.lock(firewall_config=fw)
		if not c.primary:
			logger.error("Could not get {0} active ip.".format(firewall))
			return {'error' : 'Could not get firewall active IP.'}, 502
		else:
			logger.info("{0} active ip {1}".format(firewall, c.primary))
			return c.delete()
class lock_option(Resource):
	@require_appkey
	def get(self,firewall,option):
		logger.debug('handler.lock_option.get()')
		fw = Firewall(firewall=firewall).getConfig()
		if not fw:
			logger.error('Firewall not found.')
			return {'error' : 'Firewall not found.'}, 404
		c = PaloAlto.lock(firewall_config=fw)
		if not c.primary:
			logger.error("Could not get {0} active ip.".format(firewall))
			return {'error' : 'Could not get firewall active IP.'}, 502
		else:
			logger.info("{0} active ip {1}".format(firewall, c.primary))
			return c.get(option)
	@require_appkey
	def post(self,firewall,option):
		logger.debug('handler.lock_option.post()')
		fw = Firewall(firewall=firewall).getConfig()
		if not fw:
			logger.error('Firewall not found.')
			return {'error' : 'Firewall not found.'}, 404
		c = PaloAlto.lock(firewall_config=fw)
		if not c.primary:
			logger.error("Could not get {0} active ip.".format(firewall))
			return {'error' : 'Could not get firewall active IP.'}, 502
		else:
			logger.info("{0} active ip {1}".format(firewall, c.primary))
			return c.post(None,option)
	@require_appkey
	def delete(self,firewall,option):
		logger.debug('handler.lock_option.delete()')
		fw = Firewall(firewall=firewall).getConfig()
		if not fw:
			logger.error('Firewall not found.')
			return {'error' : 'Firewall not found.'}, 404
		c = PaloAlto.lock(firewall_config=fw)
		if not c.primary:
			logger.error("Could not get {0} active ip.".format(firewall))
			return {'error' : 'Could not get firewall active IP.'}, 502
		else:
			logger.info("{0} active ip {1}".format(firewall, c.primary))
			return c.delete(option)
class lock_admin(Resource):
	@require_appkey
	def get(self,firewall,option,admin):
		logger.debug('handler.lock_admin.get()')
		fw = Firewall(firewall=firewall).getConfig()
		if not fw:
			logger.error('Firewall not found.')
			return {'error' : 'Firewall not found.'}, 404
		c = PaloAlto.lock(firewall_config=fw)
		if not c.primary:
			logger.error("Could not get {0} active ip.".format(firewall))
			return {'error' : 'Could not get firewall active IP.'}, 502
		else:
			logger.info("{0} active ip {1}".format(firewall, c.primary))
			return c.get(option,admin)
	@require_appkey
	def post(self,firewall,option,admin):
		logger.debug('handler.lock_admin.post()')
		fw = Firewall(firewall=firewall).getConfig()
		if not fw:
			logger.error('Firewall not found.')
			return {'error' : 'Firewall not found.'}, 404
		c = PaloAlto.lock(firewall_config=fw)
		if not c.primary:
			logger.error("Could not get {0} active ip.".format(firewall))
			return {'error' : 'Could not get firewall active IP.'}, 502
		else:
			logger.info("{0} active ip {1}".format(firewall, c.primary))
			return c.post(None,option,admin)
	@require_appkey
	def delete(self,firewall,option,admin):
		logger.debug('handler.lock_admin.delete()')
		fw = Firewall(firewall=firewall).getConfig()
		if not fw:
			logger.error('Firewall not found.')
			return {'error' : 'Firewall not found.'}, 404
		c = PaloAlto.lock(firewall_config=fw)
		if not c.primary:
			logger.error("Could not get {0} active ip.".format(firewall))
			return {'error' : 'Could not get firewall active IP.'}, 502
		else:
			logger.info("{0} active ip {1}".format(firewall, c.primary))
			return c.delete(option,admin)
class commit(Resource):
	@require_appkey
	def get(self,firewall):
		logger.debug('handler.commit.get()')
		fw = Firewall(firewall=firewall).getConfig()
		if not fw:
			logger.error('Firewall not found.')
			return {'error' : 'Firewall not found.'}, 404
		c = PaloAlto.commit(firewall_config=fw)
		if not c.primary:
			logger.error("Could not get {0} active ip.".format(firewall))
			return {'error' : 'Could not get firewall active IP.'}, 502
		else:
			logger.info("{0} active ip {1}".format(firewall, c.primary))
			return c.get()
	@require_appkey
	def post(self,firewall):
		logger.debug('handler.commit.post()')
		fw = Firewall(firewall=firewall).getConfig()
		if not fw:
			logger.error('Firewall not found.')
			return {'error' : 'Firewall not found.'}, 404
		c = PaloAlto.commit(firewall_config=fw)
		if not c.primary:
			logger.error("Could not get {0} active ip.".format(firewall))
			return {'error' : 'Could not get firewall active IP.'}, 502
		else:
			logger.info("{0} active ip {1}".format(firewall, c.primary))
			return c.post()
class logging(Resource):
	@require_appkey
	def get(self,firewall):
		logger.debug('handler.logging.get()')
		fw = Firewall(firewall=firewall).getConfig()
		if not fw:
			logger.error('Firewall not found.')
			return {'error' : 'Firewall not found.'}, 404
		c = PaloAlto.logging(firewall_config=fw)
		if not c.primary:
			logger.error("Could not get {0} active ip.".format(firewall))
			return {'error' : 'Could not get firewall active IP.'}, 502
		else:
			logger.info("{0} active ip {1}".format(firewall, c.primary))
			return c.get()