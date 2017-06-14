# Assimilator

The first restful API to control all firewall brands. Configure any firewall with restful API calls, no more manual rule configuration. Centralize all your firewalls into one API.

### <img src="http://www.psdgraphics.com/wp-content/uploads/2012/05/firewall-security.jpg" width=50 /> Multiplatform

- [ x ] : Palo Alto ( 100% )
- [ x ] : Juniper ( 100% )
- [   ] : Cisco ( 0% )
- [   ] : Fortinet ( 0% )
- [   ] : Checkpoint ( 0% )
- [   ] : PfSense ( 0% )
- [   ] : AWS ( 0% )

### <img src="http://www.iconsdb.com/icons/preview/orange/key-xxl.png" width=50 /> Authentication

 - API key through HTTP headers.
 - Flexible authorization, allow certain URI path with certain HTTP methods.

### <img src="http://cdn.crunchify.com/wp-content/uploads/2012/10/json_logo.png" width=50 /> JSON

 - All request/response body are in JSON. No more XML, plain text or custom responses.

### <img src="https://www.python.org/static/opengraph-icon-200x200.png" width=50 /> Python

 - Fully scripted in Python Flask.
 - Easy to update and add new modules.
 - Ready for any automatic task.

### <img src="https://upload.wikimedia.org/wikipedia/commons/thumb/4/42/Opensource.svg/220px-Opensource.svg.png" width=50 /> Open Source

 - No more Panorama, CSM or NSM.
 - Integrates with Apache2 with mod WSGI.
 - Assimilator gives a full RESTful experience for free.

## How it works

All firewalls share a common ground on their configuration, for example:

 - List of commands showing the actual configuration (AKA the running configuration).
 - Rules or policies filtering IP packets.
 - Objects:
	 - Addresses (i.e. 10.1.1.1 <-> Administration_Server).
	 - Address group (i.e. Administration_Farm <-> [ Administration_Server01 , Administration_Server02 ]).
	 - Port or service (i.e. TCP/80 <-> http).
	 - Port or service group (i.e. Application_ports <-> { TCP/6600 , TCP/6610 }).
 - Interfaces.
 - Zones.
 - Routing table.
 - PBR (policy based route).

Assimilator makes it possible to configure via the five RESTful methods all these portions of configuration with JSON objects:

 - GET: Show the object.
 - POST: Add new object.
 - PATCH: Append new data to object.
 - PUT: Replace data in object.
 - DELETE: Remove object from configuration.

#### URL Format
/api/***site***/***resource***

#### Example
```
Request: GET /api/headquarters/config

Response: HTTP 200
{"config" : "<...>"}

Request: POST /api/branch/rules
{"name" : "Test01", "from" : "trust", "to" : "untrust",
"source" : "10.1.1.1", "destination" : "8.8.8.8", "action" : "allow",
"application" : "junos-dns-udp"}
Response: HTTP 201
{}
Request: DELETE /api/branch1/rules
{"name" : "Permit Any"}
Response: HTTP 200
{}

Request: PUT /api/branch2/objects/address-group
{"name" : "Admin_Servers", "members" : [ "Server02" ] }
Response: HTTP 200
{}

Request: PATCH /api/paloalto/headquarters/route
{"name" : "internal", "destination" : "10.0.0.0/8", "next-hop" : "172.16.1.2" }
Response: HTTP 200
{}
```
## Installation
With Docker (recommended):
```bash
cd /opt
git clone https://github.com/videlanicolas/assimilator && cd assimilator
./generate_certificate.sh
docker build -t assimilator /opt/assimilator/
docker run -d -p 443:443/tcp assimilator
```
Without Docker:
```bash
cd /opt
git clone https://github.com/videlanicolas/assimilator && cd assimilator
./generate_certificate.sh
sudo ./install.sh
```

## Documentation
Read the <a href="http://assimilator.readthedocs.io/en/latest/">documentation</a>.
