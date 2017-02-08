activate_this = '/var/www/assimilator/flask/bin/activate_this.py'
execfile(activate_this, dict(__file__=activate_this))

import sys
sys.path.append('/var/www/assimilator')
sys.stdout = sys.stderr

from run import app as application