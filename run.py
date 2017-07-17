#!flask/bin/python
from werkzeug.exceptions import HTTPException
from flask import Flask,jsonify,render_template, request
from flask_restful import Resource, Api
from traceback import format_exc
import app.modules.handler as handler
import app.modules.apikeymgmt as keymgmt
import app.modules.firewalls as firewalls
import app.modules.status as status
import ConfigParser, os
import logging
import bs4

#Read configuration file
config = ConfigParser.RawConfigParser()
try:
	config.read('/etc/assimilator/assimilator.conf')
	LOG_FILE = config.get('General','logfile')
	LOG_LEVEL = config.get('General','loglevel')
	assert LOG_LEVEL in ['DEBUG', 'INFO', 'WARN', 'ERROR', 'CRIT', 'FATAL']
	if LOG_LEVEL == 'DEBUG':
		LOG_LEVEL = logging.DEBUG
	elif LOG_LEVEL == 'INFO':
		LOG_LEVEL = logging.INFO
	elif LOG_LEVEL == 'WARN':
		LOG_LEVEL = logging.WARNING
	elif LOG_LEVEL == 'ERROR':
		LOG_LEVEL = logging.ERROR
	elif LOG_LEVEL == 'CRIT':
		LOG_LEVEL = logging.CRITICAL
	elif LOG_LEVEL == 'FATAL':
		LOG_LEVEL = logging.FATAL
	datefmt = config.get('General','format')
except Exception as e:
	print "Error parsing configuration file: {0}".format(str(e))
	quit()

logging.getLogger("requests").setLevel(logging.ERROR)
logging.getLogger("bs4").setLevel(logging.ERROR)

#Logging configuration
logging.basicConfig(filename=LOG_FILE,level=LOG_LEVEL,format='%(asctime)s - %(levelname)s - %(message)s', datefmt=datefmt)

app = Flask(__name__)
api = Api(app)

#Error handling
@app.errorhandler(Exception)
def handle_error(e):
	logging.critical(str(format_exc()) + '\n' + str(e))
	code = 500
	if isinstance(e, HTTPException):
		code = e.code
	return jsonify(error='Unknown Error'), code

#API Keys management
api.add_resource(keymgmt.mgmt, '/keymgmt/<int:id>')
api.add_resource(keymgmt.mgmt_all, '/keymgmt')
api.add_resource(keymgmt.generate, '/keymgmt/generate')
#Firewall Management
api.add_resource(firewalls.firewalls, '/firewalls/<string:site>')
api.add_resource(firewalls.firewalls_all, '/firewalls')

#API REST Resources
#STATUS
api.add_resource(status.status, '/api/status')

#CONFIG
api.add_resource(handler.config, '/api/<string:firewall>/config')

#RULES
api.add_resource(handler.rules, '/api/<string:firewall>/rules')
api.add_resource(handler.rules_move, '/api/<string:firewall>/rules/move')
api.add_resource(handler.rules_rename, '/api/<string:firewall>/rules/rename')
api.add_resource(handler.rules_match, '/api/<string:firewall>/rules/match')

#INTERFACES
api.add_resource(handler.interfaces, '/api/<string:firewall>/interfaces')

#OBJECTS
api.add_resource(handler.objects, '/api/<string:firewall>/objects/<string:object>')
api.add_resource(handler.objects_rename, '/api/<string:firewall>/objects/<string:object>/rename')

#ROUTE
api.add_resource(handler.route, '/api/<string:firewall>/route')
#api.add_resource(handler.route_match, '/api/<string:brand>/<string:firewall>/route/match')

####Device Specific####
##Palo Alto##
#LOCK
api.add_resource(handler.lock, '/api/<string:firewall>/locks')
api.add_resource(handler.lock_option, '/api/<string:firewall>/locks/<string:option>')
api.add_resource(handler.lock_admin, '/api/<string:firewall>/locks/<string:option>/<string:admin>')

#COMMIT
api.add_resource(handler.commit, '/api/<string:firewall>/commit')

#LOGGING
api.add_resource(handler.logging, '/api/<string:firewall>/logging')

##Palo Alto##
#Hitcount
api.add_resource(handler.hitcount, '/api/<string:firewall>/rules/hitcount')

if __name__ == '__main__':
	app.run(host='0.0.0.0',debug=False)
