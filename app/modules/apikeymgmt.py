from flask_restful import Resource
from flask import request
from functools import wraps
from app.modules.handler import require_appkey
import logging, ConfigParser, json, random, string

#Get logger
logger = logging.getLogger(__name__)

def check_auth(username, password):
	config = ConfigParser.RawConfigParser()
	config.read('/etc/assimilator/assimilator.conf')
	if config.get('Key Management','type') == 'static':
		return config.get('Key Management','user') == username and config.get('Key Management','password') == password
	else:
		logger.error("No valid auth type in configuration file.")
		raise

def requires_auth(f):
	@wraps(f)
	def decorated(*args, **kwargs):
		logger.info("{0} {1} {2} {3}".format(request.remote_addr, request.method, request.url, str(request.args)))
		logger.debug("data: {0}".format(str(request.form)))
		auth = request.authorization
		logger.debug('Check_auth: ' + str(auth))
		if not auth or not check_auth(auth.username, auth.password):
			logger.warning("Unauthorized.")
			return {'error' : 'Unauthorized.'}, 401
		return f(*args, **kwargs)
	return decorated

class mgmt_all(Resource):
	@requires_auth
	def get(self):
		config = ConfigParser.RawConfigParser()
		config.read('/etc/assimilator/assimilator.conf')
		try:
			with open(config.get('General','apikeyfile')) as f:
				apikeys = json.loads(f.read())
		except ValueError:
			return {}, 204
		except Exception as e:
			logger.error("Cannot JSON parse API key file.")
		return apikeys

class mgmt(Resource):
	@requires_auth
	def get(self,id):
		config = ConfigParser.RawConfigParser()
		config.read('/etc/assimilator/assimilator.conf')
		try:
			with open(config.get('General','apikeyfile')) as f:
				apikeys = json.loads(f.read())
		except Exception as e:
			logger.error("Cannot JSON parse API key file.")
			return {}, 204
		try:
			return apikeys[str(id)]
		except Exception as e:
			logger.warning("ID not found.")
			return {'error' : 'ID not found.'}, 404
	@requires_auth
	def post(self,id):
		config = ConfigParser.RawConfigParser()
		config.read('/etc/assimilator/assimilator.conf')
		try:
			with open(config.get('General','apikeyfile')) as f:
				apikeys = json.loads(f.read())
		except Exception as e:
			logger.error("Cannot JSON parse API key file.")
			return {}, 204
		try:
			apikeys[str(id)]['token'].append({'path' : request.json['path'], 'method' : request.json['method']})
			with open(config.get('General','apikeyfile'),'w') as f:
				json.dump(apikeys,f)
			return {'path' : request.json['path'], 'method' : request.json['method']}
		except Exception as e:
			logger.warning("Bad token format.")
			return {'error' : 'Bad token format.'}, 400
	@requires_auth
	def delete(self,id):
		config = ConfigParser.RawConfigParser()
		config.read('/etc/assimilator/assimilator.conf')
		try:
			with open(config.get('General','apikeyfile')) as f:
				apikeys = json.loads(f.read())
		except Exception as e:
			logger.error("Cannot JSON parse API key file.")
			return {}, 204
		try:
			if str(id) not in apikeys:
				logger.warning("ID not found.")
				return {'error' : 'ID not found.'}, 404
			else:
				del apikeys[str(id)]
				with open(config.get('General','apikeyfile'),'w') as f:
					json.dump(apikeys,f)
				return request.json, 200
		except Exception as e:
			logger.warning("Exception found: {0}".format(str(e)))
			return {'error' : 'Unknown error.'}, 500
class generate(Resource):
	@requires_auth
	def get(self):
		return {'error' : 'Use POST to generate apikey.'}, 404
	@requires_auth
	def post(self):
		config = ConfigParser.RawConfigParser()
		config.read('/etc/assimilator/assimilator.conf')
		try:
			apikeys = dict()
			with open(config.get('General','apikeyfile')) as f:
				apikeys = json.loads(f.read())
		except ValueError:
			logger.warning("No JSON data on apikeyfile.")
		except Exception as e:
			logger.error("Cannot JSON parse API key file.")
			return {'error' : 'Error parsing apikeyfile.'}, 500
		try:
			if apikeys:
				aux = list()
				for k,v in apikeys.iteritems():
					aux.append(int(k))				
				id = str(sorted(aux)[-1] + 1)
			else:
				id = "1"
			key = {id : {"token" : list(), "comment" : request.json['comment'] if 'comment' in request.json else None ,"key" : ''.join(random.SystemRandom().choice(string.ascii_uppercase + string.ascii_lowercase + string.digits) for _ in range(100))}}
			apikeys[id] = key[id]
			with open(config.get('General','apikeyfile'),'w') as f:
				json.dump(apikeys,f)
			return key, 201
		except Exception as e:
			logger.warning("Exception found: {0}".format(str(e)))
			return {'error' : 'Invalid token format.'}, 400