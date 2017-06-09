.. _first steps:

First steps
===========

The first thing you need to do is create a configuration file that adjusts to your needs. Many of these parameters have already been configured for you, but some minimal configuration is needed.

An `example configuration <https://github.com/videlanicolas/assimilator/blob/master/assimilator.conf>`_ file can be found in the repo. This file specifies the initial configuration for Assimilator, this should be mounted as a volume in the Docker container with the '-v' argument on '/etc/assimilator/'.

General
-------

Logfile indicates where logs should be stored.

	logfile = /var/log/assimilator.log

The log level that should be logged [DEBUG, INFO, WARN, ERROR, CRIT, FATAL].
	
	loglevel = WARN

The date and time format for the logs, the default is Syslog friendly.

	format = %d/%m/%Y %H:%M:%S

The location for the API keys of each user, this file should exist only. API keys are managed through the REST api.

	apikeyfile = /etc/assimilator/api.key

The location for all Firewall related authentication. This is managed thorugh the REST api.

	firewalls = /etc/assimilator/firewalls.json

Where the API should listen.

	address = 0.0.0.0

What port should Assimilator listen to, default is 443.

	port = 443

Key Management
--------------

This is the authentication required to modify Firewall credentials and user's API keys.

From where should Assimilator authenticate users? For now, the only option is 'static'.

	type = static

The user and password required for admin login to the API.
	
	user = admin
	password = secret


Firewall Management
-------------------

Same as Key Management, this section describes the admin user and password required to configure Firewall credentials.

From where should Assimilator authenticate users? For now, the only option is 'static'.

	type = static

The user and password required for admin login to the API.
	
	user = admin
	password = secret