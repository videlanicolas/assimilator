import logging, json, ConfigParser

#Get logger
logger = logging.getLogger(__name__)

class Firewall():
	def __init__(self,firewall):
		self.firewall = firewall
	def getConfig(self):
		config = ConfigParser.RawConfigParser()
		config.read("/etc/assimilator/assimilator.conf")
		return json.loads(open(config.get('General','firewalls')).read())[self.firewall]
	def getMaster(self):
		return self.firewall_config['primary']
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