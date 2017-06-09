.. _install:

Install
=======

Assimilator can be installed through Docker or cloned into a directory and run from there. Personally I prefer Docker since it's more reliable, but both ways work.

The Docker Way
--------------

The best way to install Assimilator is through `Docker <https://docs.docker.com/engine/installation/>`_:

	$ docker pull videlanicolas/assimilator:stable

The latest build is constantly improving, I recomend the stable version or instead the latest tag which are also stable:

	$ docker pull videlanicolas/assimilator:1.2.2

Run a container:

	$ docker run -d -v /path/to/configuration:/etc/assimilator/ -p 443:443 videlanicolas/assimilator:stable

Docker containers are not peristent, so if you want to maintain your configured Firewalls and API keys you should mount an external directory into the container, that's what the -v is for.

The Repo-Cloning Way
--------------------

A.K.A I don't trust your Docker image.

You can clone the repo from `Github <https://github.com/videlanicolas/assimilator.git>`_ and build your image of Assimilator from the `dockerfile <https://github.com/videlanicolas/assimilator/blob/master/Dockerfile>`_.

	$ git clone https://github.com/videlanicolas/assimilator.git
	$ docker build -t assimilator .

If you don't want to use Docker there is a `bash script <https://github.com/videlanicolas/assimilator/blob/master/install.sh>`_ to install the dependencies. Also there is `another bash script <https://github.com/videlanicolas/assimilator/blob/master/generate_certificate.sh>`_ to generate a random certificate for HTTPS connections.

	$ git clone https://github.com/videlanicolas/assimilator.git
	$ chmod +x install.sh generate_certificate.sh
	$ ./generate_certificate.sh
	$ ./install.sh