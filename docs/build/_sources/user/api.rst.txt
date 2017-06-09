.. _api:

API
===

The juice of Assimilator relies on the /api. From here one can access all Firewall configuration, check rules, routes and network objects. Also the user can test an access to see if the Firewall grants the access. Assimilator has default resource URL for all firewalls (like rules, objects and routes) and private resource URL destined for each Firewall brand. This is to grasp the full functionality of Firewalls.

Config
------

**/api/<firewall>/config**

Gets the full configuration of the Firewall, in it's native format. In many cases this is XML.

*Example*

::
	
	GET /api/argentina/config
	key: BDP0NyHZMDfz98kcmD3GuBIQGW9EZTgWGPf56dWnkD3LGM3dZPaZICrKVnTnQWh5YdGLh5SJ9ktg7ReR4le94zyxdigdLTHHf8s
	Content-Type: application/json

::

	200 OK

.. block-code: json
   {
   		"config" : " ... "
   }


Rules
-----

**/api/<firewall>/rules**

Get all rules in the selected Firewall. This can be filtered with URL arguments.

*Example (PaloAlto)*
::
	
	GET /api/argentina/rules
	key: BDP0NyHZMDfz98kcmD3GuBIQGW9EZTgWGPf56dWnkD3LGM3dZPaZICrKVnTnQWh5YdGLh5SJ9ktg7ReR4le94zyxdigdLTHHf8s
	Content-Type: application/json

::

	200 OK

.. block-code: json
   {
   		"rules" : [
   		{
	      "log-end": false,
	      "qos": {
	        "marking": null,
	        "type": null
	      },
	      "negate-source": false,
	      "disabled": true,
	      "rule-type": "universal",
	      "tag": [],
	      "log-start": false,
	      "hip-profiles": [],
	      "negate-destination": false,
	      "description": null,
	      "category": [
	        "any"
	      ],
	      "from": [
	        "trust"
	      ],
	      "service": [
	        "any"
	      ],
	      "source": [
	        "any"
	      ],
	      "destination": [
	        "8.8.8.8",
	        "8.8.4.4"
	      ],
	      "application": [
	        "dns"
	      ],
	      "profile-setting": null,
	      "log-setting": null,
	      "to": [
	        "untrust"
	      ],
	      "schedule": null,
	      "source-user": [
	        "any"
	      ],
	      "icmp-unreachable": false,
	      "name": "DNS Google Access",
	      "disable-server-response-inspection": false,
	      "action": "allow"
	    },
	    ...
   		]
   }

*Example with arguments (PaloAlto)*
::
	
	GET /api/argentina/rules?from=dmz&to=untrust
	key: BDP0NyHZMDfz98kcmD3GuBIQGW9EZTgWGPf56dWnkD3LGM3dZPaZICrKVnTnQWh5YdGLh5SJ9ktg7ReR4le94zyxdigdLTHHf8s
	Content-Type: application/json

::

	200 OK

.. block-code: json
   {
   		"rules" : [
   		{
	      "log-end": true,
	      "qos": {
	        "marking": null,
	        "type": null
	      },
	      "negate-source": false,
	      "disabled": true,
	      "rule-type": "universal",
	      "tag": [],
	      "log-start": false,
	      "hip-profiles": [],
	      "negate-destination": false,
	      "description": null,
	      "category": [
	        "any"
	      ],
	      "from": [
	        "dmz"
	      ],
	      "service": [
	        "any"
	      ],
	      "source": [
	        "any"
	      ],
	      "destination": [
	        "10.10.50.2",
	      ],
	      "application": [
	        "web-browsing",
	        "ssl"
	      ],
	      "profile-setting": null,
	      "log-setting": null,
	      "to": [
	        "untrust"
	      ],
	      "schedule": null,
	      "source-user": [
	        "any"
	      ],
	      "icmp-unreachable": false,
	      "name": "Internet access",
	      "disable-server-response-inspection": false,
	      "action": "allow"
	    },
	    ...
   		]
   }


To add a rule one simply changes the method to POST and sends one of these JSON objects in the body of the request.

::
	
	POST /api/brasil/rules
	key: BDP0NyHZMDfz98kcmD3GuBIQGW9EZTgWGPf56dWnkD3LGM3dZPaZICrKVnTnQWh5YdGLh5SJ9ktg7ReR4le94zyxdigdLTHHf8s
	Content-Type: application/json
	{
		"log-end": true,
		"qos": {
			"marking": null,
			"type": null
		},
		"negate-source": false,
		"disabled": true,
		"rule-type": "universal",
		"tag": [],
		"log-start": false,
		"hip-profiles": [],
		"negate-destination": false,
		"description": null,
		"category": [
			"any"
		],
		"from": [
			"dmz"
		],
		"service": [
			"any"
		],
		"source": [
			"any"
		],
		"destination": [
			"10.10.50.2",
		],
		"application": [
			"web-browsing",
			"ssl"
		],
		"profile-setting": null,
		"log-setting": null,
		"to": [
			"untrust"
		],
		"schedule": null,
		"source-user": [
			"any"
		],
		"icmp-unreachable": false,
		"name": "Internet access",
		"disable-server-response-inspection": false,
		"action": "allow"
	}

