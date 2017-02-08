#!/bin/bash
openssl req -x509 -newkey rsa:4096 -keyout assimilator.key -out assimilator.crt -days 3650
openssl rsa -in assimilator.key -out assimilator.key
