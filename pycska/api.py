'''
Low level interface to the OAuth1 API provided by the CSKA.
'''

#pylint: disable=too-many-arguments

import json
import urllib
import requests
from requests.packages.urllib3.exceptions import InsecureRequestWarning

from requests_oauthlib import OAuth1Session

requests.packages.urllib3.disable_warnings(InsecureRequestWarning)


class ApiException(BaseException):
    '''
    Exception for all Api calls.  Whenever an Api call fails, this exception
    will be thrown and the error property will represent the error that the
    CSKA detected.
    '''
    def __init__(self, error):
        BaseException.__init__(self, 'Error in CSKA Api')
        self.error = error


class Api(object):
    '''
    Low level interface to the OAuth API provided by the CSKA.

    Initialize instance of this class with the ip of the CSKA and your OAuth1 credentials.  Create
    credentials in the user interface under Configuration->OAuth Clients.
    '''

    def __init__(self, cska_ip, client_id, client_secret, oauth1_token, oauth1_token_secret):
        self.__base_url = 'https://'+cska_ip+'/public/api/1_0/'
        self.__oauth = OAuth1Session(client_id, client_secret, oauth1_token, oauth1_token_secret)


    def __get(self, endpoint, params=None):
        if params is None:
            params = {}

        if len(params.keys()) > 0:
            query_string = '?'+urllib.urlencode(params)
        else:
            query_string = ''

        raw_content = self.__oauth.get(self.__base_url+endpoint+query_string, verify=False).content

        try:
            content = json.loads(raw_content)
            if not content['ok']:
                raise ApiException(content['error'])
            return content['data']
        except ValueError:
            return raw_content


    def __post(self, endpoint, params=None):
        if params is None:
            params = {}
        content = json.loads(self.__oauth.post(self.__base_url+endpoint, data=params,
                                               verify=False).content)
        if not content['ok']:
            raise ApiException(content['error'])
        return content['data']


    def get_allowed_actions(self):
        '''
        Get a list of the allowed actions for user rules.

        :rtype: A list of objects

        Returned object::

              {'action_id': <int - represents the action>,
               'action': <str - represents the action>,
               'signer': <bool - is this a signer action>,
               'validator': <bool - is this a validator action>}

        '''
        return self.__get('allowed_actions')


    def post_block(self, device_ids=None, seat_ids=None):
        '''
        Block a given device or a seat on a device.

        :param device_ids: Optional Id or Ids representing the device(s) to block.
        :param seat_ids: Optional Id or Ids representing the seat(s) to block.
        :type seat_ids: String or List
        :rtype: An integer representing the number of devices blocked.

        '''
        params = {}
        if device_ids is not None:
            params['device_id'] = device_ids
        if seat_ids is not None:
            params['seat_id'] = seat_ids
        return self.__post('block', params)


    def get_builtin_rules(self):
        '''
        Get a list of the builtin rules to be used as templates for creating
        other rules.

        :rtype: A list of objects

        Returned object::

                           {'rule_id': <int - internal value identifying the rule>,
                            'start_port': <int - starting port of builtin rule>,
                            'end_port': <int - ending port of builtin rule>,
                            'name': <string - user facing name for the builtin rule>,
                            'protocol_id': <int - internal integer representing the protocol>,
                            'protocol': <str - string representing the protocol>}

        '''
        return self.__get('builtin_rules')


    def get_capture(self, threat_id):
        '''
        Get the contents of a packet capture generated from a given *threat_id*.

        :param threat_id: Id representing the threat Id.
        :type threat_id: String
        :rtype: The raw contents of the pcap.
        '''
        return self.__get('capture', {'threat_id':threat_id})


    def get_config_profiles(self):
        '''
        Get the list of configuration profiles.

        :rtype: A list of objects

        Returned object::
                           {'rule_id': <int - internal value identifying the rule>,
                            'start_port': <int - starting port of builtin rule>,
                            'end_port': <int - ending port of builtin rule>,
                            'name': <string - user facing name for the builtin rule>,
                            'protocol_id': <int - internal integer representing the protocol>,
                            'protocol': <str - string representing the protocol>}

        '''
        return self.__get('config_profiles')


    def post_unblock(self, device_ids=None, seat_ids=None):
        '''
        Unblock a given device or seat on a device.

        :param device_ids: Optional Id or Ids representing the device(s) to unblock.
        :type device_ids: List or String
        :param seat_ids: Optional Id or Ids representing the seat(s) to unblock.
        :type seat_ids: String or List
        :rtype: An integer representing the number of devices unblocked.
        '''
        params = {}
        if device_ids is not None:
            params['device_id'] = device_ids
        if seat_ids is not None:
            params['seat_id'] = seat_ids
        return self.__post('unblock', params)
