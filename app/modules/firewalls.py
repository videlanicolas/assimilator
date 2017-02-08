from flask_restful import Resource
from flask import request
from functools import wraps
from app.modules.handler import require_appkey
import logging, ConfigParser, json

#Get logger
logger = logging.getLogger(__name__)

def check_auth(username, password):
	config = ConfigParser.RawConfigParser()
	config.read('/etc/assimilator/assimilator.conf')
	if config.get('Firewall Management','type') == 'static':
		return config.get('Firewall Management','user') == username and config.get('Firewall Management','password') == password
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

class firewalls_all(Resource):
	@requires_auth
	def get(self):
		config = ConfigParser.RawConfigParser()
		config.read('/etc/assimilator/assimilator.conf')
		try:
			with open(config.get('General','firewalls')) as f:
				firewalls = json.loads(f.read())
		except ValueError:
			logger.warning("No data returned.")
			return {}, 204
		except Exception as e:
			logger.error("Cannot JSON parse Firewalls file.")
			return {'error' : 'Cannot JSON parse Firewalls file.'}, 500
		return firewalls
	@requires_auth
	def post(self):
		config = ConfigParser.RawConfigParser()
		config.read('/etc/assimilator/assimilator.conf')
		try:
			with open(config.get('General','firewalls')) as f:
				data = f.read()
				firewalls = json.loads(data)
		except ValueError:
			if data:
				logger.error("Cannot JSON parse Firewalls file.")
				return {'error' : 'Cannot JSON parse Firewalls file.'}, 500
			else:
				logger.info("No data on firewall file.")
		except Exception as e:
			logger.error("Exception while parsing Firewalls file.")
			return {'error' : 'Exception while parsing Firewalls file.'}, 500
		finally:
			firewalls = request.json
			try:
				with open(config.get('General','firewalls'),'w') as f:
					json.dump(firewalls,f)
				return request.json
			except Exception as e:
				logger.error("Exception while parsing Firewalls file.")
				return {'error' : 'Exception while parsing Firewalls file.'}, 500

	@requires_auth
	def delete(self):
		config = ConfigParser.RawConfigParser()
		config.read('/etc/assimilator/assimilator.conf')
		try:
			with open(config.get('General','firewalls')) as f:
				data = f.read()
				firewalls = json.loads(data)
		except ValueError:
			if not data:
				logger.error("Firewall file already empty.")
				return {'error' : 'Firewall file already empty.'}, 204
			else:
				logger.error("Cannot JSON parse Firewalls file.")
				return {'error' : 'Cannot JSON parse Firewalls file.'}, 500
		except Exception as e:
			logger.error("Exception while parsing Firewalls file.")
			return {'error' : 'Exception while parsing Firewalls file.'}, 500
		else:
			logger.info("Firewall file with existing configuration.")
			try:
				with open(config.get('General','firewalls'),'w'):
					pass
				return firewalls, 200
			except Exception as e:
				logger.error("Error while deleting Firewall file: {0}".format(str(e)))
				return {'error' : 'Error while deleting Firewall file.'}, 500

class firewalls(Resource):
	@requires_auth
	def get(self,site):
		config = ConfigParser.RawConfigParser()
		config.read('/etc/assimilator/assimilator.conf')
		try:
			with open(config.get('General','firewalls')) as f:
				firewall = json.loads(f.read())
		except Exception as e:
			logger.error("Cannot JSON parse API key file.")
			return {}, 204
		try:
			return firewall[site]
		except Exception as e:
			logger.warning("Firewall brand or site not found.")
			return {'error' : 'Firewall brand or site not found.'}, 404
	@requires_auth
	def post(self,site):
		config = ConfigParser.RawConfigParser()
		config.read('/etc/assimilator/assimilator.conf')
		try:
			with open(config.get('General','firewalls')) as f:
				data = f.read()
				firewalls = json.loads(data)
		except ValueError:
			if data:
				logger.error("Cannot JSON parse Firewalls file.")
				return {'error' : 'Cannot JSON parse Firewalls file.'}, 500
			else:
				logger.warning("No data on firewall file.")
				firewalls = dict()
		except Exception as e:
			logger.error("Exception while parsing Firewalls file.")
			return {'error' : 'Exception while parsing Firewalls file.'}, 500
		finally:
			firewalls[site] = request.json
			try:
				with open(config.get('General','firewalls'),'w') as f:
					json.dump(firewalls,f)
				return request.json
			except Exception as e:
				logger.error("Exception while parsing Firewalls file.")
				return {'error' : 'Exception while parsing Firewalls file.'}, 500
	@requires_auth
	def delete(self,site):
		config = ConfigParser.RawConfigParser()
		config.read('/etc/assimilator/assimilator.conf')
		try:
			with open(config.get('General','firewalls')) as f:
				data = f.read()
				firewalls = json.loads(data)
		except ValueError:
			if data:
				logger.error("Cannot JSON parse Firewalls file.")
				return {'error' : 'Cannot JSON parse Firewalls file.'}, 500
			else:
				logger.warning("No data on firewall file.")
				return {'error' : 'No data on firewall file.'}, 204
		except Exception as e:
			logger.error("Exception while parsing Firewalls file.")
			return {'error' : 'Exception while parsing Firewalls file.'}, 500
		else:
			ret = firewalls[site]
			del firewalls[site]
			try:
				with open(config.get('General','firewalls'),'w') as f:
					json.dump(firewalls,f)
				return ret
			except Exception as e:
				logger.error("Exception while parsing Firewalls file.")
				return {'error' : 'Exception while parsing Firewalls file.'}, 500