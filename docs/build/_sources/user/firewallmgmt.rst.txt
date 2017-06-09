.. _firewall management:

Firewall management
===================

This is the second part of the admin configuration, this part should be accessed through HTTP authenteication with the user and password specified in assimilator.conf file. Here the admin configures all Firewall credentials, with this information Assimilator will then access each Firewall and retrieve the information requested through API calls.
Each Firewall brand has their our way to be accessed, in general it's an SSH connection but some of them use an API (PaloAlto or AWS).


Add a Firewall
--------------

To add a Firewall we make an admin POST request to /firewalls/<firewall key>, in the request's body we should send the JSON object with the Firewall's credentials.

::

	POST /firewalls/argentina HTTP/1.1
	Content-Type: application/json
	Authorization: Basic YWRtaW46c2VjcmV0
	{
		"brand" : <firewall brand>,
		"description" : <Some description about this device>,
		#JSON object keys for the Firewall brand
		...
	}

To remove a Firewall from Assimilator we make a DELETE request.

::

	DELETE /firewalls/argentina HTTP/1.1
	Content-Type: application/json
	Authorization: Basic YWRtaW46c2VjcmV0

To retrieve the Firewall configuration we make a GET request.

::

	GET /firewalls/argentina HTTP/1.1
	Content-Type: application/json
	Authorization: Basic YWRtaW46c2VjcmV0


Each Firewall brand is configured differently, this is because each Firewall has their way to be accessed. For each Firewall there is a unique JSON object format.
Below is the detailed configuration for each device.

Palo Alto
---------

PaloAlto firewalls have an XML API that only has the GET method. Through this Assimilator translates it to a friendlier API.

::

	GET /firewalls/argentina HTTP/1.1
	Content-Type: application/json
	Authorization: Basic YWRtaW46c2VjcmV0

::

	200 OK

.. code-block: json

   {
	"brand": "paloalto",
	"secondary": "192.168.1.2",
	"primary": "192.168.1.1",
	"key": "LUFRPT1fhejJjfjelajcmalseiVWFjhfu37Hu39fjLLifj38ejL00ffj398ejLKfjei4o0apLmfnjfkel49ii00fa9sf=",
	"description": "Firewall Argentina"
   }

The key is the Firewall name through the api, in this example the key is 'argentina'. Inside this JSON object we have the following keys:

::

	"brand" : The Firewall's brand, this will indicate which translator script should be invoked when connecting to this firewall.
	"primary" : The Firewall's primary IP address, in PaloAlto this should be the Management IP address.
	"secondary" : The Firewall's secondary IP address, in PaloAlto this should be the Management IP address.
	"key" : XML API key to be used by Assimilator when connecting to this PaloAlto Firewall.
	"description" : Some description about this device.


Juniper
-------

Junos SRX and SSG have a similar configuration, both are XML based and are accessed through SSH.

::

	GET /firewalls/datacenter HTTP/1.1
	Content-Type: application/json
	Authorization: Basic YWRtaW46c2VjcmV0

::

	200 OK

.. code-block: json

   {
	"description": "Firewall SRX Datacenter.",
	"brand": "juniper",
	"privatekey": "",
	"primary": "172.16.1.1",
	"secondary": "172.16.1.2",
	"privatekeypass": "",
	"user": "assimilator",
	"timeout": 1200,
	"pass": "somepassword",
	"port": 22,
	"name": "datacenter"
	}

The key is the Firewall name through the api, in this example the key is 'datacenter'. Juniper allows users to login either with a password or a certificate, the latter one is encouraged.
Inside this JSON object we have the following keys:

::

	"brand" : The Firewall's brand, this will indicate which translator script should be invoked when connecting to this firewall.
	"primary" : The Firewall's primary IP address, in Juniper this should be the trust IP address.
	"secondary" : The Firewall's secondary IP address, in Juniper this should the trust IP address.
	"user" : The username that Assimilator should use while logging in, it usually is 'assimilator'.
	"privatekey" : Location of the certificate file to be used for SSH authentication, if not specified then user/password will be used.
	"privatekeypass" : The password to decrypt the private key from the certificate, if not specified then user/password will be used.
	"pass" : The password to be used for SSH login, this is used if privatekey and privatekeypass is not specified.
	"port" : The SSH port on the Firewall, usually 22.
	"description" : Some description about this device.
