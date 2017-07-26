import sys
sys.path.append('/var/www/assimilator')
sys.stdout = sys.stderr

from run import app as application