import time

from pycska.api import Api
from pycska.api import ApiException
from pycska.api import LICENSE_TYPE_SIGNER
from pycska.basetypes import ProfileDetails
from pycska.basetypes import ConfigProfile
from pycska.basetypes import LoggingPlugin
from pycska.basetypes import OAuthClient
from pycska.basetypes import SecurityGroup

CLIENT_ID = 'qYbaHYKNAUmDPF3M5K7wvyztzv2xNH1AidOMYKB_7n3Urjkg7TIC_i-C7QIC0iMY36KJ7wS1xdDLraMy9PSuzsQRkXi7-V-lSpcFOv4c2TKhNW-C6vWarNeyQvIFoUtBEYO6ppFbF8PkNAtShpJRYjY_dKvi3MyR5WFggLFrLDuIlU9Z-eIkTjjxsuNl0u6sF8IUY-AGmZvbyHgcjO-n-woWyLDKbSjmq3ULOXquraydeMfAHctz_fnu8sOsnJW9'
CLIENT_SECRET = 'TblRUULemU663UTafjgdh69oBauOlZ4yIMDC_W6S6g7nYodHN3resHMECAKY4tnB-Wci18uJ_QBpdwWHlrjnTFUBvmSXcEUe0U94C-HmH0rCv1qPx_w086LEWjULLgo8vPtAdEkgRAB6ijRJKCoswN7qz0r7KDyk1CPUsxQTLxFg_hveoY5v4785DDxdSwzWGAKttMq_pKHeKox5vrc5Rn5mb3VIpFK8ApCw1mrnBNdO1HY1R_3qhG3A3oFBmrRH'
OAUTH_TOKEN = 'eXBBAVnLQfEoIVwKrrM0Lrq29hw1VF'
OAUTH_TOKEN_SECRET = 'ax35zOIedSWoGNmXBX8EQyKl3GRVPJ'

api = Api('cska', CLIENT_ID, CLIENT_SECRET, OAUTH_TOKEN, OAUTH_TOKEN_SECRET)

try:
    signer_rule = api.get_user_rules(rule_name="Sign")[0]
    validator_rule = api.get_user_rules(rule_name="Validate")[0]
    new_group = SecurityGroup()
    new_group.group_name = "Test Group2"
    new_group.signer_rules = [signer_rule]
    new_group.validator_rules = [validator_rule]
    print api.post_security_group(new_group)
#    license = api.get_licenses(license_types=LICENSE_TYPE_SIGNER)[0]
#    print api.post_seat(device, license)
#    print api.delete_seat(device.signer_seat)
except ApiException as e:
    print 'Error: '+e.error
