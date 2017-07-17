#!/bin/bash

echo "Installing dependencies..."
apt-get update && apt-get install -y apache2 libapache2-mod-wsgi openssl python-lxml

echo "Creating directories..."
mkdir /etc/assimilator /var/www/assimilator /etc/apache2/ssl
touch /var/log/assimilator.log

echo "Copying configuration files..."
cp ${PWD}/assimilator_vhost.conf /etc/apache2/sites-available/assimilator_vhost.conf
cp ${PWD}/run.py /var/www/assimilator/run.py
cp ${PWD}/assimilator.wsgi /var/www/assimilator/assimilator.wsgi
cp ${PWD}/assimilator.conf /etc/assimilator/assimilator.conf
touch /etc/assimilator/firewalls.json
touch /etc/assimilator/api.key
touch /var/www/assimilator/__init__.py
cp -R ${PWD}/app /var/www/assimilator/

echo "Generating RSA key pair..."
openssl req -x509 -nodes -days 365 -newkey rsa:2048 -keyout /etc/apache2/ssl/assimilator.key -out /etc/apache2/ssl/assimilator.crt

echo "Asigning permissions..."
chown -R www-data /var/www/assimilator/ 
chgrp -R www-data /var/www/assimilator/
chown www-data /etc/apache2/ssl/assimilator.key /etc/apache2/ssl/assimilator.crt /etc/apache2/sites-available/assimilator_vhost.conf /var/log/assimilator.log /etc/assimilator/assimilator.conf /etc/assimilator/api.key /etc/assimilator/firewalls.json
chgrp www-data /etc/apache2/ssl/assimilator.key /etc/apache2/ssl/assimilator.crt /etc/apache2/sites-available/assimilator_vhost.conf /var/log/assimilator.log /etc/assimilator/assimilator.conf /etc/assimilator/api.key /etc/assimilator/firewalls.json
chmod 600 /etc/assimilator/*

echo "Enabling apache2 mods..."
a2enmod ssl wsgi

echo "Activating apache configuration file..."
a2ensite assimilator_vhost

echo "Restarting apache..."
service apache2 restart
