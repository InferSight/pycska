from pycska.api import Api
from pycska.api import ApiException

CLIENT_ID = 'qYbaHYKNAUmDPF3M5K7wvyztzv2xNH1AidOMYKB_7n3Urjkg7TIC_i-C7QIC0iMY36KJ7wS1xdDLraMy9PSuzsQRkXi7-V-lSpcFOv4c2TKhNW-C6vWarNeyQvIFoUtBEYO6ppFbF8PkNAtShpJRYjY_dKvi3MyR5WFggLFrLDuIlU9Z-eIkTjjxsuNl0u6sF8IUY-AGmZvbyHgcjO-n-woWyLDKbSjmq3ULOXquraydeMfAHctz_fnu8sOsnJW9'
CLIENT_SECRET = 'TblRUULemU663UTafjgdh69oBauOlZ4yIMDC_W6S6g7nYodHN3resHMECAKY4tnB-Wci18uJ_QBpdwWHlrjnTFUBvmSXcEUe0U94C-HmH0rCv1qPx_w086LEWjULLgo8vPtAdEkgRAB6ijRJKCoswN7qz0r7KDyk1CPUsxQTLxFg_hveoY5v4785DDxdSwzWGAKttMq_pKHeKox5vrc5Rn5mb3VIpFK8ApCw1mrnBNdO1HY1R_3qhG3A3oFBmrRH'
OAUTH_TOKEN = 'eXBBAVnLQfEoIVwKrrM0Lrq29hw1VF'
OAUTH_TOKEN_SECRET = 'ax35zOIedSWoGNmXBX8EQyKl3GRVPJ'

api = Api('cska', CLIENT_ID, CLIENT_SECRET, OAUTH_TOKEN, OAUTH_TOKEN_SECRET)

try:
    print api.get_config_profiles()
except ApiException as e:
    print 'Error: '+e.error
