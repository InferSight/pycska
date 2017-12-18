import time
from pycska.api import *

api = Api('cska', 'creds.json')

quarantine_group = api.get_security_group('Quarantine')

while True:
    threats, total = api.get_threats(threat_filter_list=['Custom Malware'])
    for threat in threats:
        print "Discovered threat and isolating %s"%threat.device.device_name
        threat.device.security_groups = [quarantine_group]
        api.update_device(threat.device)
    time.sleep(2)
