FROM ubuntu:xenial

#Install dependencies
RUN apt-get update &&\
	apt-get install -y apache2 libapache2-mod-wsgi openssl python-dev libxml2-dev libxslt1-dev python-pip lib32z1-dev libffi-dev && apt-get clean &&\
	rm -rf /var/lib/apt/lists/*

#Copy and install dependencies
COPY requirements.txt /tmp/requirements.txt
RUN pip install -r /tmp/requirements.txt

#Version information and maintainer
LABEL version:"1.2.3" maintainer:"Nicolas Videla"

#Expose only SSL
EXPOSE 443/tcp

#Create directories
RUN mkdir -p /var/www/assimilator/app /etc/apache2/ssl

#Create log file
RUN touch /var/log/assimilator.log

#Date
ARG CACHE_DATE=2016-01-01

#Copy configuration
COPY assimilator_vhost.conf /etc/apache2/sites-available/assimilator_vhost.conf
COPY run.py /var/www/assimilator/run.py
COPY assimilator.wsgi /var/www/assimilator/assimilator.wsgi
COPY assimilator.conf /etc/assimilator/assimilator.conf

#Create firewalls.json file
RUN touch /etc/assimilator/firewalls.json

#Create apikey storage
RUN touch /etc/assimilator/api.key
RUN touch /var/www/assimilator/__init__.py

#Install assimilator
COPY app/ /var/www/assimilator/app/

#Copy private RSA key
COPY assimilator.key /etc/apache2/ssl/assimilator.key
COPY assimilator.crt /etc/apache2/ssl/assimilator.crt

#Assigning permissions
RUN chown -R www-data:www-data /var/www/assimilator/
RUN chown www-data:www-data /etc/apache2/ssl/assimilator.key /etc/apache2/ssl/assimilator.crt /etc/apache2/sites-available/assimilator_vhost.conf /var/log/assimilator.log
RUN chmod 600 /etc/assimilator/*

#Enable mods
RUN a2enmod ssl wsgi

#Enable API
RUN a2ensite assimilator_vhost

#Run apache
COPY entrypoint /usr/bin/entrypoint
ENTRYPOINT entrypoint