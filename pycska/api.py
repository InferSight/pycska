'''
Low level interface to the OAuth1 API provided by the CSKA.
'''

#pylint: disable=too-many-arguments, too-many-public-methods, too-many-lines

import json
import random
import binascii
import hashlib
import urllib
import requests
from requests.packages.urllib3.exceptions import InsecureRequestWarning

from requests_oauthlib import OAuth1Session

requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

from pycska.basetypes import ConfigProfile
from pycska.basetypes import Device
from pycska.basetypes import ProfileDetails
from pycska.basetypes import License
from pycska.basetypes import LoggingPlugin
from pycska.basetypes import OAuthClient
from pycska.basetypes import OAuthClientSecret
from pycska.basetypes import Rule
from pycska.basetypes import Seat
from pycska.basetypes import SecurityGroup
from pycska.basetypes import Stats
from pycska.basetypes import SystemStatus
from pycska.basetypes import Threat
from pycska.basetypes import User


LICENSE_TYPE_CSKA = 'Channel Signing Key Authority' #: CSKA License Type
LICENSE_TYPE_SIGNER = 'Channel Lock Signer' #: Signer License Type
LICENSE_TYPE_VALIDATOR = 'Channel Lock Validator' #: Validator License Type
LICENSE_TYPE_ALL = [LICENSE_TYPE_CSKA, LICENSE_TYPE_SIGNER, LICENSE_TYPE_VALIDATOR] #:All Licenses

RULE_ACTION_SIGN = 'Sign' #: Signing action for rules.
RULE_ACTION_VALIDATE = 'Validate and Strip' #: Validating action for rules.
RULE_ACTION_DROP = 'Drop' #: Drop action for rules.

RULE_PROTOCOL_UDP = 'UDP' #: UDP protocol type for rules.
RULE_PROTOCOL_TCP = 'TCP' #: TCP protocol type for rules.

RULE_HASH_ALGORITHM_XOR = 'xor' #: XOR hash algorithm for rules
RULE_HASH_ALGORITHM_SHA1 = 'sha1' #: SHA1 hash algorithm for rules


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
    credentials in the CSKA user interface under Configuration->OAuth Clients.

    Example instantiation::

      CLIENT_ID = 'your-client-id'
      CLIENT_SECRET = 'your-client-secret'
      OAUTH_TOKEN = 'your-oauth1-token'
      OAUTH_TOKEN_SECRET = 'your-oauth1-token-secret'
      CSKA_IP = 'cska-ip'

      api = Api(CSKA_IP, CLIENT_ID, CLIENT_SECRET, OAUTH_TOKEN, OAUTH_TOKEN_SECRET)

    The above code creates a new instance of this class to be used for all API functions below.
    '''

    def __init__(self, cska_ip, client_id_or_json, client_secret=None, 
                 oauth1_token=None, oauth1_token_secret=None):
        if client_secret is None:
            creds_json = json.loads(open(client_id_or_json, 'r').read())
            client_id = creds_json['CLIENT_ID']
            client_secret = creds_json['CLIENT_SECRET']
            oauth1_token = creds_json['OAUTH_TOKEN']
            oauth1_token_secret = creds_json['OAUTH_TOKEN_SECRET']
        self.__last_threat_count = None
        self.__base_url = 'https://'+cska_ip+'/public/api/1_0/'
        self.__oauth = OAuth1Session(client_id, client_secret, oauth1_token, oauth1_token_secret)
        self.__oauth.headers.update({'content-type': 'application/json',
                                     'accept': 'application/json'})


    def __get(self, endpoint, params=None, return_total=False):
        if params is None:
            params = {}

        # In get requests where we urlencode the querystring, boolean values don't pass
        # as expected - simply convert to 0's and 1's
        updated_params = {}
        for key, value in params.items():
            if isinstance(value, bool):
                value = int(value)
            updated_params[key] = value

        if len(params.keys()) > 0:
            query_string = '?'+urllib.urlencode(updated_params)
        else:
            query_string = ''

        raw_content = self.__oauth.get(self.__base_url+endpoint+query_string, verify=False).content

        try:
            content = json.loads(raw_content)
            if isinstance(content, str) or isinstance(content, unicode):
                return content
            else:
                if not content['ok']:
                    raise ApiException(content['error'])
                data = content['data']
                if not return_total:
                    return data
                else:
                    return data, content['total']
        except ValueError:
            return raw_content


    def __post(self, endpoint, params=None):
        if params is None:
            params = {}
        content = json.loads(self.__oauth.post(self.__base_url+endpoint, data=json.dumps(params),
                                               verify=False).content)
        if not content['ok']:
            raise ApiException(content['error'])
        return content['data']


    def __delete(self, endpoint, params=None):
        if params is None:
            params = {}
        content = json.loads(self.__oauth.delete(self.__base_url+endpoint, data=json.dumps(params),
                                                 verify=False).content)
        if not content['ok']:
            raise ApiException(content['error'])
        return content['data']


    def do_block(self, devices_or_device_names=None, seats=None):
        '''
        Block a list of devices or devices with the given seat licenses.  Devices can be
        specified either as a list of :py:class:`pycska.basetypes.Device` or as a list
        of device names.

        :param devices_or_device_names: Optional Device objects or device names to block.
        :type devices_or_device_names: List of :py:class:`pycska.basetypes.Device` or String

        :param seats: Optional Id or Ids representing the seat(s) to block.
        :type seats: List of :py:class:`pycska.basetypes.Seat`

        :rtype: An integer representing the number of devices blocked.

        Example usage::

          api.do_block(['test-signer-0', 'test-validator-0'])

        The above blocks access to devices with the names *test-signer-0* and *test-validator-0*.
        '''
        if devices_or_device_names is None:
            devices_or_device_names = []
        if not isinstance(devices_or_device_names, list):
            raise ValueError('Invalid type for devices_or_device_names')
        devices_param = []
        for device_or_device_name in devices_or_device_names:
            if isinstance(device_or_device_name, Device):
                devices_param.append(device_or_device_name.to_dict())
            elif isinstance(device_or_device_name, str) or \
                 isinstance(device_or_device_name, unicode):
                devices_param.append(self.get_device(device_name=device_or_device_name).to_dict())
            else:
                raise ValueError('Invalid type for device_or_device_name')
        if seats is None:
            seats = []
        if not isinstance(seats, list):
            raise ValueError('Invalid type for seats')
        for seat in seats:
            if not isinstance(seat, Seat):
                raise ValueError('Invalid type for seat')
        seats_param = [seat.to_dict() for seat in seats]
        return self.__post('block', {'devices':devices_param,
                                     'seats':seats_param})


    def get_capture(self, threat_or_threat_id):
        '''
        Get the contents of a packet capture generated from a given *threat_id*.

        :param threat_or_threat_id: Threat to get a capture for.
        :type threat_or_threat_id: :py:class:`pycska.basetypes.Threat` or String

        :rtype: The raw contents of the pcap.

        Example usage::

          threats, total = api.get_threats(0, 100)
          capture = api.get_capture(threats[0].threat_id)
          open('capture.pcap', 'wb+').write(capture)

        The above code gets the most recent 100 threats and then gets the pcap for the most
        recent threat and writes to *capture.pcap*.
        '''
        if isinstance(threat_or_threat_id, Threat):
            params = threat_or_threat_id.to_dict()
        elif isinstance(threat_or_threat_id, str) or isinstance(threat_or_threat_id, unicode):
            params = {'threat_id':threat_or_threat_id}
        else:
            raise ValueError('Invalid type for threat_or_threat_id')
        return self.__get('capture', params)


    def get_config_profile(self, profile_name=None, profile_id=None):
        '''
        Get a specific configuration profile by id or by name.

        :param profile_name: Optional value to filter the results on.
        :type profile_name: String

        :param profile_id: Optional value to filter the results on.
        :type profile_id: Integer

        :rtype: Type :py:class:`pycska.basetypes.ConfigProfile`

        Example usage::

          profile = api.get_config_profile('Default')

        The above code gets the config profile with the name *Default*.
        '''
        params = {}
        if profile_id is not None:
            params['profile_id'] = profile_id
        if profile_name is not None:
            params['profile_name'] = profile_name
        return ConfigProfile(self.__get('config_profile', params=params))


    def create_config_profile(self, profile_name, license_renew_time=7200, log_level='Info',
                              capture_threats=True, syslog_filter=''):
        '''
        Used to create a config profile.

        :param profile_name: Name to assign to config profile.
        :type profile_name: String

        :param license_renew_time: Optional - amount of seconds between license renew.
        :type license_renew_time: Integer

        :param log_level: Optional - log level for devices using this profile.
        :type log_level: String

        :param capture_threats: Optional - do validators attempt to capture threats.
        :type capture_threats: Boolean

        :param syslog_filter: Optional - do validators listen to third party syslog sources.
        :type capture_threats: Boolean

        :rtype: Type :py:class:`pycska.basetypes.ConfigProfile`

        Example usage::

          profile = api.create_config_profile('Test Profile', 3600, 'Error')

        The above code creates a new profile with the name *Test Profile*, a renew time of
        *1 hour*, and with a log level of *Error*.
        '''
        profile_details = ProfileDetails({'license_renew_time':license_renew_time,
                                          'log_level':log_level,
                                          'capture_threats':capture_threats,
                                          'syslog_filter':syslog_filter})
        profile = ConfigProfile({'profile_name':profile_name,
                                 'configuration':profile_details})
        profile_id = self.update_config_profile(profile)
        profile.profile_id = profile_id
        return profile


    def update_config_profile(self, config_profile):
        '''
        Used to update a config profile.

        :param config_profile: Config profile to update.
        :type config_profile: Type :py:class:`pycska.basetypes.ConfigProfile`

        :rtype: Integer representing the profile id of the profile created or updated.

        Example usage::

          default_profile = api.get_config_profile('Default')
          default_profile.configuration.log_level = 'Error'
          api.update_config_profile(default_profile)

        The above code updates the log_level on the *Default* profile to *Error*.
        '''
        if not isinstance(config_profile, ConfigProfile):
            raise ValueError('Invalid type for config_profile')
        return self.__post('config_profile', params=config_profile.to_dict())


    def delete_config_profile(self, config_profile_or_name):
        '''
        Delete a given configuration profile.

        :param config_profile_or_name: Configuration profile to delete.
        :type config_profile_or_name: Type :py:class:`pycska.basetypes.ConfigProfile` or String

        :rtype: Not applicable

        Example usage::

          test_profile = api.get_config_profile('Test Profile')
          api.delete_config_profile(test_profile)

        The above code gets the *Test Profile* configuration profile and deletes it.
        '''
        if isinstance(config_profile_or_name, ConfigProfile):
            params = config_profile_or_name.to_dict()
        elif isinstance(config_profile_or_name, str):
            params = {'profile_name':config_profile_or_name}
        else:
            raise ValueError('Invalid type for config_profile')
        self.__delete('config_profile', params)


    def get_config_profiles(self):
        '''
        Get the list of configuration profiles.

        :rtype: List of :py:class:`pycska.basetypes.ConfigProfile`

        Example usage::

          profiles = api.get_config_profiles()

        The above code gets the list of configuration profiles.
        '''
        return [ConfigProfile(content) for content in self.__get('config_profiles')]


    def delete_config_profiles(self, config_profiles=None, delete_all=False):
        '''
        Delete the list of configuration profiles.

        :param config_profiles: List of config profiles to delete.
        :type config_profiles: List of :py:class:`pycska.basetypes.ConfigProfile`

        :param delete_all: Are we deleting all config profiles.
        :type delete_all: Boolean

        :rtype: Not applicable

        Example usage::

          profile1 = api.get_config_profile('Profile 1')
          profile2 = api.get_config_profile('Profile 2')
          profile3 = api.get_config_profile('Profile 3')
          api.delete_config_profiles([profile1, profile2, profile3])

        The above code gets and deletes *profile1*, *profile2*, and *profile3*.
        '''
        if config_profiles is None:
            config_profiles = []
        if not isinstance(config_profiles, list):
            raise ValueError('Invalid type for config_profiles')
        for config_profile in config_profiles:
            if not isinstance(config_profile, ConfigProfile):
                raise ValueError('Invalid type for config_profile')
        params = {'profiles': [profile.to_dict() for profile in config_profiles],
                  'delete_all': delete_all}
        self.__delete('config_profiles', params=params)


    def get_device(self, device_name=None, device_id=None):
        '''
        Get the a specific device by device_id or by device_name.

        :param device_name: Optional value to filter the results on.
        :type device_name: String

        :param device_id: Optional value to filter the results on.
        :type device_id: Integer

        :rtype: Type :py:class:`pycska.basetypes.Device`

        Example usage::

          device = api.get_device('test-signer-0')

        The above code gets a device with the name *test-signer-0*.
        '''
        params = {}
        if device_id is not None:
            params['device_id'] = device_id
        if device_name is not None:
            params['device_name'] = device_name
        return Device(self.__get('device', params=params))


    def update_device(self, device):
        '''
        Used to update a device.  Only the profile and security groups are updated.

        :param device: Device to update.
        :type device: Type :py:class:`pycska.basetypes.Device`

        :rtype: Integer representing the profile id of the profile created or updated.

        Example usage::

          profile = api.get_config_profile('Test Profile')
          device = api.get_device('test-signer-0')
          device.profile = profile
          api.update_device(device)

        The above code will update the configuration profile to *Test Profile* for the
        device with the name *test-signer-0*.
        '''
        if not isinstance(device, Device):
            raise ValueError('Invalid type for device')
        return self.__post('device', params=device.to_dict())


    def get_devices(self, device_name=None, device_id=None, license_types=None):
        '''
        Get a list of all devices.

        :param device_name: Optional value to filter the results on.
        :type device_name: String

        :param device_id: Optional value to filter the results on.
        :type device_id: Integer

        :param license_types: Optional list of licenses to filter on, :py:data:`LICENSE_TYPE_CSKA`,
                              :py:data:`LICENSE_TYPE_SIGNER`, :py:data:`LICENSE_TYPE_VALIDATOR`,
                              :py:data:`LICENSE_TYPE_ALL`.
        :type license_types: List of String

        :rtype: List of :py:class:`pycska.basetypes.Device`

        Example usage::

          devices = api.get_devices(license_types=[LICENSE_TYPE_SIGNER])

        The above code will get all devices that are signers.
        '''
        filter_query = {}
        if device_name is not None:
            filter_query['device_name'] = device_name
        if device_id is not None:
            filter_query['device_id'] = device_id
        if license_types is not None:
            filter_query['license_types'] = license_types

        return [Device(content) for content in self.__get('devices',
                                                          params=filter_query)]


    def get_licenses(self, license_types=None):
        '''
        Get a list of all the licenses granted to the account.

        :param license_types: Which license types to grab or leave unspecified to get all.
        :type license_type: String

        :rtype: List of :py:class:`pycska.basetypes.License`

        Example usage::

          licenses = api.get_licenses()

        The above code is used to get the list of licenses granted to the account.
        '''
        if license_types is None:
            license_types = LICENSE_TYPE_ALL
        return [License(content) for content in self.__get('licenses') \
                  if content['license_type'] in license_types]


    def get_logs_by_date(self, from_date, to_date, is_usage=False, format_as='json'):
        '''
        Get the logs from the CSKA over a date range.

        :param from_date: Date to start retrieving logs from - seconds since epoch (UTC)
        :type from_date: Integer

        :param to_date: Date to end retrieving logs from - seconds since epoch (UTC)
        :type to_date: Integer

        :param is_usage: Usage or System logs.
        :type is_usage: Boolean

        :param format_as: Type of output - either json, raw, or csv
        :type format_as: String

        :rtype: String depending on format_as

        Example usage::

          from_date = time.time() - 60*60*24*7
          to_date = time.time()
          logs = api.get_logs_by_date(from_date, to_date, is_usage=False, format_as='json')

        Retrieves the last week of logs.
        '''
        return self.__get('logs', params={'from': int(from_date),
                                          'to': int(to_date),
                                          'format_as': format_as,
                                          'is_usage': is_usage})


    def create_logging_plugin(self, name, ip_address, port, protocol, url='', rfc3164=False):
        '''
        Create a logging plugin.

        :param name: Name of new logging plugin.
        :type name: String

        :param ip_address: Address of the logging store.
        :type ip_address: String

        :param port: Port logging store is listening on.
        :type port: Integer

        :param protocol: Protocol the logging store is listening for - UDP, TCP.
        :type protocol: String

        :param url: Optional - landing page for the logging store.
        :type url: String

        :param rfc3164: Optional - is the logging store expecting rfc3164 compliant logs.
        :type rfc3164: Boolean

        :rtype: Type :py:class:`pycska.basetypes.LoggingPlugin`

        Example usage::

          new_plugin = api.create_logging_plugin('New Logging Plugin', '1.1.1.1', 10000, 'UDP')

        Creates a new logging plugin.
        '''
        new_plugin = LoggingPlugin({'plugin_name':name, 'ip':ip_address, 'port':port,
                                    'protocol':protocol, 'url':url,
                                    'rfc3164':rfc3164})
        self.update_logging_plugin(new_plugin)
        return new_plugin


    def get_logging_plugin(self, plugin_name):
        '''
        Get a logging plugin by name.

        :param plugin_name: Name of plugin to get.
        :type plugin_name: String

        :rtype: Type :py:class:`pycska.basetypes.LoggingPlugin`

        Example usage::

          plugin = api.get_logging_plugin('My Logging Plugin')

        Get the plugin named *My Logging Plugin*.
        '''
        return LoggingPlugin(self.__get('logging_plugin', {'plugin_name':plugin_name}))


    def update_logging_plugin(self, plugin):
        '''
        Update a logging plugin.

        :param plugin: Plugin to update.
        :type plugin: :py:class:`pycska.basetypes.LoggingPlugin`

        :rtype: Type :py:class:`pycska.basetypes.LoggingPlugin`

        Example usage::

          plugin = api.get_logging_plugin('New Plugin')
          plugin.port = 15000
          api.update_logging_plugin(plugin)

        The above code gets the plugin name *New Plugin* and updates the port to 15000.
        '''
        return LoggingPlugin(self.__post('logging_plugin', plugin.to_dict()))


    def delete_logging_plugin(self, plugin_or_plugin_name):
        '''
        Update a logging plugin.

        :param plugin_or_plugin_name: Plugin to update.
        :type plugin_or_plugin_name: :py:class:`pycska.basetypes.LoggingPlugin`

        :rtype: Not applicable

        Example usage::

          api.delete_logging_plugin('My Logging Plugin')

        The above code deletes the plugin named *My Logging Plugiin*.
        '''
        if isinstance(plugin_or_plugin_name, LoggingPlugin):
            params = plugin_or_plugin_name.to_dict()
        elif isinstance(plugin_or_plugin_name, str):
            params = {'plugin_name':plugin_or_plugin_name}
        else:
            raise ValueError('Invalid type for config_profile')
        self.__delete('logging_plugin', params)


    def get_logging_plugins(self):
        '''
        Get the list of logging plugins.

        :rtype: List of :py:class:`pycska.basetypes.LoggingPlugin`

        Example usage::

          plugins = api.get_logging_plugins()

        The above command gets the list of logging plugins.
        '''
        return [LoggingPlugin(content) for content in self.__get('logging_plugins')]


    def update_logging_plugins(self, logging_plugins):
        '''
        Used to set the entire list of logging plugins.

        :param logging_plugins: List of logging plugins to update to.
        :type logging_plugins: List of :py:class:`pycska.basetypes.LoggingPlugin`

        :rtype: Not applicable

        Example usage::

          plugins = api.get_logging_plugins()
          plugins[0].port = 20000
          api.update_logging_plugins(plugins)

        The above command gets the list of plugins and modifies the port on the first one to 20000.
        '''
        if not isinstance(logging_plugins, list):
            raise ValueError('Invalid type for logging_plugins')
        for logging_plugin in logging_plugins:
            if not isinstance(logging_plugin, LoggingPlugin):
                raise ValueError('Invalid type for logging_plugin')
        params = {'plugins': [logging_plugin.to_dict() for logging_plugin in logging_plugins]}
        self.__post('logging_plugins', params=params)


    def delete_logging_plugins(self, logging_plugins=None, delete_all=False):
        '''
        Delete the list of logging plugins.

        :param logging_plugins: List of logging plugins to delete.
        :type logging_plugins: List of :py:class:`pycska.basetypes.LoggingPlugin`

        :param delete_all: Are we deleting all logging plugins.
        :type delete_all: Boolean

        :rtype: Not applicable

        Example usage::

          plugins = api.get_logging_plugins()
          udp_plugins = [plugin for plugin in plugins if plugin.protocol.lower() == 'udp']
          api.delete_logging_plugins(udp_plugins)

        The above commands get the list of udp plugins and then deletes them.
        '''
        if logging_plugins is None:
            logging_plugins = []
        if not isinstance(logging_plugins, list):
            raise ValueError('Invalid type for logging_plugins')
        for logging_plugin in logging_plugins:
            if not isinstance(logging_plugin, LoggingPlugin):
                raise ValueError('Invalid type for logging_plugin')
        logging_plugins = [logging_plugin.to_dict() for logging_plugin in logging_plugins]
        self.__delete('logging_plugins', {'plugins':logging_plugins,
                                          'delete_all':delete_all})


    def get_network_graph(self):
        '''
        Get a JSON representation of the network graph.

        :rtype: JSON object showing the nodes and edges in the network.

        Example usage::

          graph = api.get_network_graph()

        The above command gets the current nework topology.
        '''
        return self.__get('network_graph')


    def create_oauth_client(self, name, password, description='', allow_oauth1=True,
                            allow_oauth2=False, default_scopes_list=None,
                            redirect_uris_list=None):
        '''
        Create a new oauth client.

        :param name: Name to assign to new client.
        :type name: String

        :param password: Clear text password to give to client for retrieving secret tokens.
        :type password: String

        :param description: Optional - description for client.
        :type description: String

        :param allow_oauth1: Optional - is oauth1 allowed.
        :type allow_oauth1: Boolean

        :param allow_oauth2: Optional - is oauth2 allowed.
        :type allow_oauth2: Boolean

        :param default_scopes_list: Optional - comma separated list of scopes.  Default is fine.
        :type default_scopes_list: String

        :param redirect_uris_list: Optional - comma separated list of redirects.  Default is
                                   good for internal Mulesoft API explorer.
        :type redirect_uris_list: String

        :rtype: Type :py:class:`pycska.basetypes.OAuthClient`

        Example usage::

          new_client = api.create_oauth_client('New Client', 'mypassword', allow_oauth1=True)

        Creates a new oauth client.
        '''
        new_client = OAuthClient({'name':name, 'description':description,
                                  'allow_oauth1':allow_oauth1, 'allow_oauth2':allow_oauth2,
                                  'default_scopes_list':default_scopes_list,
                                  'redirect_uris_list':redirect_uris_list})
        new_client.client_id = self.update_oauth_client(new_client, password)
        return new_client


    def get_oauth_client(self, client_name=None, client_id=None):
        '''
        Get an oauth client by client_name or client_id.

        :param client_name: Name of oauth client to retrieve.
        :type client_name: String

        :param client_id: Id of oauth client to retrieve.
        :type client_id: String

        :rtype: Type :py:class:`pycska.basetypes.OAuthClient`

        Example usage::

          client = api.get_oauth_client('New Client')

        Gets the oauth client with the name *New Client*.
        '''
        params = {}
        if client_name is not None:
            params['client_name'] = client_name
        if client_id is not None:
            params['client_id'] = client_id
        return OAuthClient(self.__get('oauth_client', params=params))


    def update_oauth_client(self, oauth_client,
                            client_password=None, reset_token=False):
        '''
        Used to update/create an OAuth client.  Fields like 'name' and the 'password' are immutable.

        :param oauth_client: OAuth client to update.
        :type oauth_client: Type :py:class:`pycska.basetypes.OAuthClient`

        :param client_password: Client password.  Only relevant for new oauth clients.
        :type client_password: String

        :param reset_token: Should the oauth keys be reset.
        :type reset_token: False

        :rtype: String representing the client id.

        Example usage::

          client = api.get_oauth_client('New Client')
          client.description = "Needed a description"
          api.update_oauth_client(client)

        The above code adds a description to an existing oauth client.
        '''
        if not isinstance(oauth_client, OAuthClient):
            raise ValueError('Invalid type for oauth_client')
        params = {'client':oauth_client.to_dict(),
                  'reset_token':reset_token}
        if client_password is not None:
            params['client_password_hash'] = \
                binascii.hexlify(hashlib.sha256(client_password).digest())
        return self.__post('oauth_client', params=params)


    def delete_oauth_client(self, oauth_client_or_client_name):
        '''
        Delete a given oauth_client.

        :param oauth_client_or_client_name: OAuth client to delete.
        :type oauth_client_or_client_name: Type :py:class:`pycska.basetypes.OAuthClient` or String

        :rtype: Not applicable

        Example usage::

          api.delete_oauth_client('New Client')

        Delete an oauth client by name.
        '''
        if isinstance(oauth_client_or_client_name, str):
            oauth_client = self.get_oauth_client(oauth_client_or_client_name)
        elif isinstance(oauth_client_or_client_name, OAuthClient):
            oauth_client = oauth_client_or_client_name
        else:
            raise ValueError('Invalid type for oauth_client_or_client_name')
        self.__delete('oauth_client', params=oauth_client.to_dict())


    def get_oauth_client_secret(self, oauth_client_or_client_name, client_password):
        '''
        Get an oauth client secret tokens for a given oauth client.

        :param oauth_client_or_client_name: Client to update.
        :type oauth_client_or_client_name: Type :py:class:`pycska.basetypes.OAuthClient` or String

        :param client_password: Client password.  Used to unlock the tokens.
        :type client_password: String

        :rtype: Type :py:class:`pycska.basetypes.OAuthClientSecret`

        Example usage::

          secret = api.get_oauth_client_secret('New Client', 'mypassword')

        Get the oauth client secret given a client name and password.
        '''
        if isinstance(oauth_client_or_client_name, str):
            oauth_client = self.get_oauth_client(oauth_client_or_client_name)
        elif isinstance(oauth_client_or_client_name, OAuthClient):
            oauth_client = oauth_client_or_client_name
        else:
            raise ValueError('Invalid type for oauth_client_or_client_name')
        params = {'client_id': oauth_client.client_id,
                  'client_password_hash':binascii.hexlify(hashlib.sha256(client_password).digest())}
        secret = OAuthClientSecret(self.__get('oauth_client_secret', params=params))
        secret.client_id = oauth_client.client_id
        return secret


    def get_oauth_clients(self, client_names=None):
        '''
        Get the list of oauth clients.

        :param client_names: Optional list of names to filter results on.
        :type client_names: List of String

        :rtype: List of :py:class:`pycska.basetypes.OAuthClient`

        Example usage::

          clients = api.get_oauth_clients()

        Gets a list of all the oauth clients.
        '''
        return [OAuthClient(content) for content in self.__get('oauth_clients') \
                          if client_names is None or content['name'] in client_names]


    def delete_oauth_clients(self, oauth_clients_or_client_names):
        '''
        Deletes a list of oauth clients.

        :param oauth_clients_or_client_names: OAuth clients to delete.
        :type oauth_clients_or_client_names: List of :py:class:`pycska.basetypes.OAuthClient` or
                                             String

        :rtype: Not applicable

        Example usage::

          clients = api.get_oauth_clients()
          clients_to_delete = [client for client in clients \
                                 if 'other' in client.default_scopes_list]
          api.delete_oauth_clients(clients_to_delete)

        Deletes all the oauth clients that have 'other' in their default scopes.
        '''
        oauth_clients = []
        if not isinstance(oauth_clients_or_client_names, list):
            raise ValueError('Invalid type for oauth_clients_or_client_names')
        for oauth_client_or_client_name in oauth_clients_or_client_names:
            if isinstance(oauth_client_or_client_name, str) or \
               isinstance(oauth_client_or_client_name, unicode):
                oauth_clients.append(self.get_oauth_client(oauth_client_or_client_name))
            elif isinstance(oauth_client_or_client_name, OAuthClient):
                oauth_clients.append(oauth_client_or_client_name)
            else:
                raise ValueError('Invalid type for oauth_client')
        params = {'clients': [client.to_dict() for client in oauth_clients]}
        self.__delete('oauth_clients', params=params)


    def get_oauth_state(self):
        '''
        Get the state of the OAuth API Explorer.

        :rtype: Boolean indicating if the API Explorer is enabled.

        Example usage::

          state = api.get_oauth_state()

        Returns whether or not the internal oauth browser is enabled.
        '''
        return self.__get('oauth_state')


    def update_oauth_state(self, is_enabled):
        '''
        Set the state of the OAuth API Explorer.

        :param is_enabled: Is The OAuth API Explorer enabled.
        :type is_enabled: Boolean

        :rtype: Not applicable.

        Example usage::

          api.update_oauth_state(False)

        Updates whether or not the internal oauth browser is enabled.
        '''
        self.__post('oauth_state', {'oauth_browser': is_enabled})


    def get_overlay(self):
        '''
        Get the network overlay JSON used to overlay non channel locked devices
        on to the network graph.

        :rtype: String

        Example usage::

          overlay_contents = api.get_overlay()

        Returns contents of network overlay file.
        '''
        return self.__get('overlay')


    def update_overlay(self, overlay_contents):
        '''
        Set the network overlay JSON used to overlay non channel locked devices
        on to the network graph.

        :param overlay_contents: Contents of overlay file.
        :type overlay_contents: String

        :rtype: Not applicable.

        Example usage::

          api.update_overlay(overlay_contents)

        Updates contents of network overlay file.
        '''
        self.__post('overlay', overlay_contents)


    def delete_overlay(self):
        '''
        Delete the network overlay JSON used to overlay non channel locked devices
        on to the network graph.

        :rtype: Not applicable.

        Example usage::

          api.delete_overlay(overlay_contents)

        Deletes network overlay file.
        '''
        self.__delete('overlay')


    def get_remote_support(self):
        '''
        Get the state of remote support ssh access.

        :rtype: Boolean indicating whether SSH access is allowed.

        Example usage::

          is_on = api.get_remote_support()

        Returns whether or not remote access is enabled.
        '''
        return self.__get('remote_support')


    def update_remote_support(self, is_on):
        '''
        Set the state of remote support ssh access.

        :param is_on: Is SSH access to be enabled.
        :type is_on: Boolean

        :rtype: Not applicable.

        Example usage::

          api.update_remote_support(False)

        Turn off remote ssh access.
        '''
        self.__post('remote_support', {'is_on':is_on})


    def create_rule_bpf(self, rule_name, action, custom_bpf, layer=3,
                        hash_algorithm=RULE_HASH_ALGORITHM_XOR, include_dos_protection=True,
                        description=''):
        '''
        Create an advanced BPF filter rule.

        :param rule_name: Name to assign to rule.
        :type rule_name: String

        :param action: Action to perform on a rule match.  Example :py:data:`RULE_ACTION_SIGN`.
        :type action: String

        :param custom_bpf: Advanced BPF string for filter.  CSKA will validate.
        :type custom_bpf: String

        :param layer: Optional - lowest layer to apply rule to.
        :type layer: Integer

        :param hash_algorithm: Optional - hash applied.  Example :py:data:`RULE_HASH_ALGORITHM_XOR`.
        :type hash_algorithm: String

        :param include_dos_protection: Optional - whether additonal header is added to
                                       help protected against DOS attacks.
        :type include_dos_protection: Boolean

        :param description: Optional - description for rule.
        :type description: String

        :rtype: Type :py:class:`pycska.basetypes.Rule`

        Example usage::

          new_rule = api.create_rule_bpf('New Rule', RULE_ACTION_SIGN, 'host 1.1.1.1')

        Creates a new BPF signing rule.
        '''
        new_rule = Rule({'rule_name':rule_name, 'action':action, 'custom_bpf':custom_bpf,
                         'layer':layer, 'hash_algorithm':hash_algorithm,
                         'include_dos_protection':include_dos_protection,
                         'description':description})
        rule_id = self.update_rule(new_rule)
        new_rule.rule_id = rule_id
        return new_rule


    def create_rule(self, rule_name, action, protocol, start_port, end_port,
                    src_cidr, dst_cidr, layer=3, hash_algorithm=RULE_HASH_ALGORITHM_XOR,
                    include_dos_protection=True, description=''):
        '''
        Create a regular filter rule.

        :param rule_name: Name to assign to rule.
        :type rule_name: String

        :param action: Action to perform on a rule match.  Example :py:data:`RULE_ACTION_SIGN`.
        :type action: String

        :param protocol: Protocol that rule applies to.  Example :py:data:`RULE_PROTOCOL_UDP`.
        :type protocol: String

        :param start_port: Starting port that the rule applies to.
        :type start_port: Integer

        :param end_port: Starting port that the rule applies to.
        :type end_port: Integer

        :param src_cidr: CIDR range that applies to the src ip address.  Can specify Any, Public,
                         or proper CIDR address, i.e. 192.168.0.0/24
        :type src_cidr: String

        :param dst_cidr: CIDR range that applies to the dst ip address.  Can specify Any, Public,
                         or proper CIDR address, i.e. 192.168.0.0/24
        :type dst_cidr: String

        :param layer: Optional - lowest layer to apply rule to.
        :type layer: Integer

        :param hash_algorithm: Optional - hash applied.  Example :py:data:`RULE_HASH_ALGORITHM_XOR`.
        :type hash_algorithm: String

        :param include_dos_protection: Optional - whether additonal header is added to
                                       help protected against DOS attacks.
        :type include_dos_protection: Boolean

        :param description: Optional - description for rule.
        :type description: String

        :rtype: Type :py:class:`pycska.basetypes.Rule`

        Example usage::

          new_rule = api.create_rule('New Rule', RULE_ACTION_SIGN, RULE_PROTOCOL_UDP, 20000, 30000,
                                     '192.168.0.0/24', 'Public')

        Creates a new signing rule that will match UDP packets between ports 20000 and 30000 with
        a source ip in the subnet 192.168.0.0/24 and with a public destination address.
        '''

        new_rule = Rule({'rule_name':rule_name, 'action':action, 'start_port':start_port,
                         'end_port':end_port, 'src_cidr':src_cidr, 'dst_cidr':dst_cidr,
                         'protocol':protocol, 'layer':layer, 'hash_algorithm':hash_algorithm,
                         'include_dos_protection':include_dos_protection,
                         'description':description})
        rule_id = self.update_rule(new_rule)
        new_rule.rule_id = rule_id
        return new_rule


    def get_rule(self, rule_name=None, rule_id=None):
        '''
        Get a specific user rule.

        :param rule_name: Optional value to filter the results on.
        :type rule_name: Integer

        :param rule_id: Optional value to filter the results on.
        :type rule_id: Integer

        :rtype: Type :py:class:`pycska.basetypes.Rule`

        Example usage::

           rule = api.get_rule('New Rule')

        Get the rule with the name *New Rule*.
        '''
        params = {}
        if rule_name is not None:
            params['rule_name'] = rule_name
        if rule_id is not None:
            params['rule_id'] = rule_id
        return Rule(self.__get('rule', params=params))


    def update_rule(self, rule):
        '''
        Update a specific user rule or create a new rule.

        :param rule: Rule to update/create.  Leave rule_id blank to create a new rule.
        :type rule: Type :py:class:`pycska.basetypes.Rule`

        :rtype: Integer - rule_id

        Example usage::

           rule = api.get_rule('New Rule')
           rule.description = 'My good description'
           api.update_rule(rule)

        The above code will set the description on an existing rule.
        '''
        if not isinstance(rule, Rule):
            raise ValueError('Invalid type for rule')
        return self.__post('rule', params=rule.to_dict())


    def delete_rule(self, rule_or_rule_name):
        '''
        Delete a specific user rule.

        :param rule_or_rule_name: Rule to delete.
        :type rule_or_rule_name: Type :py:class:`pycska.basetypes.Rule` or String.

        :rtype: Not applicable

        Example usage::

          api.delete_rule('New Rule')

        Deletes the rule with the name *New Rule*.
        '''
        if isinstance(rule_or_rule_name, str) or isinstance(rule_or_rule_name, unicode):
            params = {'rule_name': rule_or_rule_name}
        elif isinstance(rule_or_rule_name, Rule):
            params = rule_or_rule_name.to_dict()
        else:
            raise ValueError('Invalid type for rule_or_rule_name')
        self.__delete('rule', params=params)


    def get_rules(self, rule_name=None, rule_id=None):
        '''
        Get a list of the user rules.

        :param rule_name: Optional value to filter the results on.
        :type rule_name: String

        :param rule_id: Optional value to filter the results on.
        :type rule_id: Integer

        :rtype: List of :py:class:`pycska.basetypes.Rule`

        Example usage::

            rules = api.get_rules()

        The above code gets a list of rules.
        '''
        params = {}
        if rule_id is not None:
            params['rule_id'] = rule_id
        if rule_name is not None:
            params['rule_name'] = rule_name
        return [Rule(content) for content in self.__get('rules', params=params)]


    def delete_rules(self, rules=None, delete_all=False):
        '''
        Delete the list of rules.

        :param rules: List of user rules to delete.
        :type rules: List of :py:class:`pycska.basetypes.Rule`

        :param delete_all: Are we deleting all user rules.
        :type delete_all: Boolean

        :rtype: Not applicable

        Example usage::

            rule = api.get_rule('New Rule')
            api.delete_rules([rule])

        The above code deletes a list of rules.
        '''
        if rules is None:
            rules = []
        if not isinstance(rules, list):
            raise ValueError('Invalid type for rules')
        for rule in rules:
            if not isinstance(rule, Rule):
                raise ValueError('Invalid type for rule')
        params = {'rules': [rule.to_dict() for rule in rules],
                  'delete_all': delete_all}
        self.__delete('rules', params=params)


    def update_seat(self, device, infersight_license):
        '''
        Assign the given InferSight license to the device.

        :param device: Device to assign license to.
        :type device: Type :py:class:`pycska.basetypes.Device`

        :param infersight_license: License to assign to device.
        :type infersight_license: Type :py:class:`pycska.basetypes.License`

        :rtype: Type :py:class:`pycska.basetypes.Seat`

        Example usage::

          signer_license = api.get_licenses([LICENSE_TYPE_SIGNER])[0]
          device = api.get_device('test-signer-0')
          api.update_seat(device, signer_license)

        Adds a signer license to the device with name *test-signer-0*.
        '''
        if not isinstance(device, Device):
            raise ValueError('Invalid type for device')
        if not isinstance(infersight_license, License):
            raise ValueError('Invalid type for infersight_license')
        seat_id = self.__post('seat', {'device': device.to_dict(),
                                       'license': infersight_license.to_dict()})
        return Seat({'seat_id': seat_id, 'license_name':infersight_license.license_type})


    def delete_seat(self, seat):
        '''
        Revoke the specified seat.

        :param seat: Seat to revoke.
        :type seat: Type :py:class:`pycska.basetypes.Seat`

        :rtype: Not applicable.

        Example usage::

          device = api.get_device('test-signer-0')
          api.delete_seat(device.validator_seat)

        Delete the validator seat that is on the device with name *test-signer-0*.
        '''
        if not isinstance(seat, Seat):
            raise ValueError('Invalid type for seat')
        self.__delete('seat', {'seat': seat.to_dict()})


    def create_security_group(self, group_name, description='', signer_rules=None,
                              validator_rules=None, validates_groups=None):
        '''
        Create a new security group.

        :param group_name: Name to give new security group.  Must be unique.
        :type group_name: String

        :param description: Optional - description for new group.
        :type description: String

        :param signer_rules: Optional - rules to apply for signers in the group.
        :type signer_rules: List of :py:class:`pycska.basetypes.Rule`

        :param validator_rules: Optional - rules to apply for validators in the group.
        :type validator_rules: List of :py:class:`pycska.basetypes.Rule`

        :param validates_groups: Optional - which groups will be validated.
        :type validates_groups: List of :py:class:`pycska.basetypes.SecurityGroup`

        :rtype: New security group - :py:class:`pycska.basetypes.SecurityGroup`

        Example usage::

          signer_rule = api.get_rule('Sign')
          validator_rule = api.get_rule('Validate Internal')
          group = api.create_security_group('My Group', '', [signer_rule], [validator_rule])

        The above code gets a signer and validator rule and creates a new security group using
        these rules.
        '''
        if signer_rules is None:
            signer_rules = []
        if validator_rules is None:
            validator_rules = []
        if validates_groups is None:
            validates_groups = []
        new_group = SecurityGroup({'group_name':group_name, 'description':description,
                                   'signer_rules':signer_rules, 'validator_rules':validator_rules,
                                   'validates_groups':validates_groups})
        group_id = self.update_security_group(new_group)
        new_group.group_id = group_id
        return new_group


    def get_security_group(self, group_name=None, group_id=None):
        '''
        Get the a specific security group by group_id or by group_name.

        :param group_name: Optional value to filter the results on.
        :type group_name: String

        :param group_id: Optional value to filter the results on.
        :type group_id: Integer

        :rtype: Type :py:class:`pycska.basetypes.SecurityGroup`

        Example usage::

          group = api.get_security_group('Test Group')

        Gets all the security groups created with the CSKA.
        '''
        params = {}
        if group_id is not None:
            params['group_id'] = group_id
        if group_name is not None:
            params['group_name'] = group_name
        return SecurityGroup(self.__get('security_group', params=params))


    def update_security_group(self, group):
        '''
        Used to create or update a security_group

        :param group: Security group to create or update.
        :type group: Type :py:class:`pycska.basetypes.SecurityGroup`

        :rtype: Integer representing the group id of the profile created or updated.

        Example usage::

          group = api.get_security_group('Test Group')
          group.description = 'New Description'
          api.update_security_group(group)

        Changes the description of a group to *New Description*.
        '''
        if not isinstance(group, SecurityGroup):
            raise ValueError('Invalid type for group')
        return self.__post('security_group', params=group.to_dict())


    def delete_security_group(self, group_or_group_name):
        '''
        Delete a security group.

        :param group_or_group_name: Group to delete.
        :type group_or_group_name: Type :py:class:`pycska.basetypes.SecurityGroup` or String

        :rtype: Not applicable
        '''
        if isinstance(group_or_group_name, str):
            group = self.get_security_group(group_or_group_name)
        elif isinstance(group_or_group_name, SecurityGroup):
            group = group_or_group_name
        else:
            raise ValueError('Invalid type for group_or_group_name')
        self.__delete('security_group', params=group.to_dict())


    def get_security_groups(self):
        '''
        Get all security groups.

        :rtype: List of :py:class:`pycska.basetypes.SecurityGroup`

        Example usage::

          groups = api.get_security_groups()

        Gets all the security groups created with the CSKA.
        '''
        return [SecurityGroup(content) for content in self.__get('security_groups')]


    def delete_security_groups(self, groups_or_group_names=None, delete_all=False):
        '''
        Delete a list of security groups.

        :param groups_or_group_names: Groups to delete.
        :type groups_or_group_names: List of :py:class:`pycska.basetypes.SecurityGroup`

        :param delete_all: Are we deleting all config profiles.
        :type delete_all: Boolean

        :rtype: Not applicable

        Example usage::

          api.delete_security_groups(['My Group', 'My Group2'])

        Deletes the security groups with names *My Group* and *My Group2*.
        '''
        if groups_or_group_names is None:
            groups_or_group_names = []
        groups = []
        if not isinstance(groups_or_group_names, list):
            raise ValueError('Invalid type for groups_or_group_name')
        for group_or_group_name in groups_or_group_names:
            if isinstance(group_or_group_name, str) or \
               isinstance(group_or_group_name, unicode):
                groups.append(self.get_security_group(group_or_group_name))
            elif isinstance(group_or_group_name, SecurityGroup):
                groups.append(group_or_group_name)
            else:
                raise ValueError('Invalid type for group_or_group_name')
        params = {'groups': [group.to_dict() for group in groups],
                  'delete_all': delete_all}
        self.__delete('security_groups', params=params)


    def get_stats(self, device_or_device_name=None, seat_or_seat_id=None):
        '''
        Get the stats for a given device or seat.

        :param device_or_device_name: Optional - device to get stats for.
        :type device_or_device_name: Type :py:class:`pycska.basetypes.Device` or String

        :param seat_or_seat_id: Optional - seat license to get stats for.
        :type seat_or_seat_id: Type :py:class:`pycska.basetypes.Seat` or String

        :rtype: List of :py:class:`pycska.basetypes.Stats`

        Example usage::

          stats = api.get_stats('test-signer-0')

        Get stats for the device with name *test-signer-0*.
        '''
        params = {}
        if device_or_device_name is not None:
            if isinstance(device_or_device_name, str) or \
               isinstance(device_or_device_name, unicode):
                params['device_name'] = device_or_device_name
            elif isinstance(device_or_device_name, Device):
                params['device_name'] = device_or_device_name.device_name
            else:
                raise ValueError('Invalid type for device_or_device_name')
        if seat_or_seat_id is not None:
            if isinstance(seat_or_seat_id, str) or \
               isinstance(seat_or_seat_id, unicode):
                params['seat_id'] = seat_or_seat_id
            elif isinstance(seat_or_seat_id, Seat):
                params['seat_id'] = seat_or_seat_id.seat_id
            else:
                raise ValueError('Invalid type for device_or_device_name')
        return [Stats(content) for content in self.__get('stats', params=params)]


    def delete_stats(self, device_or_device_name=None, seat_or_seat_id=None):
        '''
        Clear the stats for a given device or seat.

        :param device_or_device_name: Optional - device to clear stats for.
        :type device_or_device_name: Type :py:class:`pycska.basetypes.Device` or String

        :param seat_or_seat_id: Optional - seat license to clear stats for.
        :type seat_or_seat_id: Type :py:class:`pycska.basetypes.Seat` or String

        :rtype: Not applicable

        Example usage::

          api.delete_stats('test-signer-0')

        Clear stats for the device with name *test-signer-0*.
        '''
        params = {}
        if device_or_device_name is not None:
            if isinstance(device_or_device_name, str) or \
               isinstance(device_or_device_name, unicode):
                params['device_name'] = device_or_device_name
            elif isinstance(device_or_device_name, Device):
                params['device_name'] = device_or_device_name.device_name
            else:
                raise ValueError('Invalid type for device_or_device_name')
        if seat_or_seat_id is not None:
            if isinstance(seat_or_seat_id, str) or \
               isinstance(seat_or_seat_id, unicode):
                params['seat_id'] = seat_or_seat_id
            elif isinstance(seat_or_seat_id, Seat):
                params['seat_id'] = seat_or_seat_id.seat_id
            else:
                raise ValueError('Invalid type for device_or_device_name')
        self.__delete('stats', params=params)


    def get_system_status(self):
        '''
        Get the current system status.

        :rtype: Type :py:class:`pycska.basetypes.SystemStatus`

        Example usage::

            status = api.get_system_status()

        Gets the current system status summary.
        '''
        return SystemStatus(self.__get('system_status'))


    def get_threats(self, start=0, limit=None, load_acknowledged=False,
                    threat_filter_list=None,
                    get_device=True):
        '''
        Get the current list of threats.

        :param start: Index to start getting threats from - 0 based and start from most recent.
        :type start: Integer

        :param limit: Max number of threats to return.
        :type limit: Integer

        :param load_acknowledged: Load acknowledged as well as unacknowledged threats.
        :type load_acknowledged: Boolean

        :param threat_filter_list: Optional list of strings to filter threats on.
        :type threat_filter_list: List of Strings

        :param get_device: For each threat do we attempt to lookup the device that caused
                           the threat.
        :type get_device: Boolean

        :rtype: Tuple (List of :py:class:`pycska.basetypes.Threat`, Number of threats)

        Example usage::

            threats, total = api.get_threats(0, 100)

        Gets the most recent 100 threats.  The variable *total* contains the total number
        of theats that could be retrieved.
        '''
        if limit is None:
            params = {'start':0, 'limit':1000, 'load_acknowledged':False}
            threats, total = self.__get('threats', params, True)
            if self.__last_threat_count is None:
                self.__last_threat_count = total
            new_limit = total - self.__last_threat_count
            self.__last_threat_count = total
        else:
            new_limit = limit
        if new_limit <= 0:
            return ([], total)
        params = {'start':start, 'limit':new_limit, 'load_acknowledged':load_acknowledged}
        try:
            threats, total = self.__get('threats', params, True)
        except ApiException as e:
            print e.error
            return ([], 0)
        if threat_filter_list is None:
            filtered_threats = [Threat(content) for content in threats]
        else:
            filtered_threats = []
            for content in threats:
                threat = Threat(content)
                for threat_filter in threat_filter_list:
                    if threat_filter in threat.threat:
                        filtered_threats.append(threat)
                        break
        if get_device:
            for threat in filtered_threats:
                if threat.device_id is not None:
                    try:
                        device = self.get_device(device_id = threat.device_id)
                        threat.device = device
                    except ApiException:
                        pass
        return (filtered_threats, total)


    def update_threats(self, ack_state, threats=None, modify_all=False):
        '''
        Update the acknowledged state on a list of threats or on all threats.

        :param ack_state: Flag indicating the new state of the threat(s).
        :type ack_state: Boolean

        :param threats: Optional threat(s) to update the ack state for.
        :type threats: List of :py:class:`pycska.basetypes.Threat`

        :param modify_all: Optional flag indicating if all threats are to be updated.
        :type modify_all: Boolean

        :rtype: Not applicable

        Example usage::

            threats, total = api.get_threats(0, 10)
            api.update_threats(True, threats)

        The above code acknowledges the most recent 10 threats.
        '''
        if threats is None:
            threats = []
        threats_param = [threat.to_dict() for threat in threats]
        self.__post('threats', {'threats':threats_param,
                                'ack_state':ack_state,
                                'modify_all':modify_all})


    def delete_threats(self, threats=None, delete_all=False):
        '''
        Delete a list of threats or all threats.

        :param threats: Optional threat(s) to delete.
        :type threats: List of :py:class:`pycska.basetypes.Threat`

        :param delete_all: Optional flag indicating if all threats are to be deleted.
        :type delete_all: Boolean

        :rtype: Not applicable

        Example usage::

            threats, total = api.get_threats(0, 10)
            api.delete_threats(True, threats)

        The above code deletes the most recent 10 threats.
        '''
        if threats is None:
            threats = []
        threats_param = [threat.to_dict() for threat in threats]
        self.__delete('threats', {'threats':threats_param,
                                  'delete_all':delete_all})


    def create_ticket(self, priority, short_reason, long_reason, use_remote_support):
        '''
        Create a new support ticket.

        :param priority: Priority of support ticket (1-Critical, 2-Service Affecting, 3-General)
        :type priority: Integer

        :param short_reason: Short description of issue.
        :type short_reason: String

        :param long_reason: Long description of issue.
        :type long_reason: String

        :param use_remote_support: Should remote access be allowed to support.
        :type use_remote_support: Boolean

        :rtype: Not applicable

        Example usage::

          api.create_ticket(1, 'Short Reason', 'Long Reason', True)

        The above code submits a ticket to support and enables remote access.
        '''
        self.__post('ticket', {'priority':priority,
                               'short_reason':short_reason,
                               'long_reason':long_reason,
                               'use_remote_support':use_remote_support})


    def do_unblock(self, devices_or_device_names=None, seats=None):
        '''
        Unblock a list of devices or devices with the given seat licenses.  Devices can be
        specified either as a list of :py:class:`pycska.basetypes.Device` or as a list
        of device names.

        :param devices_or_device_names: Optional Device objects or device names to unblock.
        :type devices_or_device_names: List of :py:class:`pycska.basetypes.Device` or String

        :param seats: Optional Id or Ids representing the seat(s) to unblock.
        :type seats: List of :py:class:`pycska.basetypes.Seat`

        :rtype: An integer representing the number of devices unblocked.

        Example usage::

          api.do_unblock(['test-signer-0', 'test-validator-0'])

        The above unblocks access to devices with the names *test-signer-0* and *test-validator-0*.
        '''
        if devices_or_device_names is None:
            devices_or_device_names = []
        if not isinstance(devices_or_device_names, list):
            raise ValueError('Invalid type for devices_or_device_names')
        devices_param = []
        for device_or_device_name in devices_or_device_names:
            if isinstance(device_or_device_name, Device):
                devices_param.append(device_or_device_name.to_dict())
            elif isinstance(device_or_device_name, str) or \
                 isinstance(device_or_device_name, unicode):
                devices_param.append(self.get_device(device_name=device_or_device_name).to_dict())
            else:
                raise ValueError('Invalid type for device_or_device_name')
        if seats is None:
            seats = []
        if not isinstance(seats, list):
            raise ValueError('Invalid type for seats')
        for seat in seats:
            if not isinstance(seat, Seat):
                raise ValueError('Invalid type for seat')
        seats_param = [seat.to_dict() for seat in seats]
        return self.__post('unblock', {'devices':devices_param,
                                       'seats':seats_param})


    def create_user(self, user_name, full_name, password_clear):
        '''
        Create a new user.

        :param user_name: Name that is used to login to the CSKA.
        :type user_name: String

        :param full_name: Full name of user for display purposes.
        :type full_name: String

        :param password_clear: Password of new user.  User will be asked to change on first login.
        :type password_clear: String

        :rtype: Type :py:class:`pycska.basetypes.User`

        Example usage::

          new_user = api.create_user('jsmith', 'John Smith', 'goodpassword')

        The above code creates a new user with the login *jsmith*.
        '''
        new_user = User({'user_name':user_name, 'full_name':full_name})
        self.update_user(new_user, password_clear)
        return new_user


    def get_user(self, user_name=None):
        '''
        Get a user by user name.

        :param user_name: User name used to login to CSKA.
        :type user_name: String

        :rtype: Type :py:class:`pycska.basetypes.User`

        Example usage::

          user = api.get_user('admin')

        The above code gets the *admin* user.
        '''
        params = {}
        if user_name is not None:
            params['user_name'] = user_name
        return User(self.__get('user', params=params))


    def update_user(self, user, password_clear=None):
        '''
        Update a user.

        :param user: User to update or create.
        :type user: Type :py:class:`pycska.basetypes.User`

        :param password_clear: New password for user.
        :type password_clear: String

        :rtype: Not applicable

        Example usage::

          user = api.get_user('jsmith')
          user.full_name = 'John D Smith'
          api.update_user(user)

        The above code is used to update a user's full name.
        '''
        params = {'user':user.to_dict()}
        if password_clear is not None:
            params['password_salt'] = binascii.hexlify(hashlib.sha256(\
                ''.join([chr(int(random.random()*256)) for _ in range(256)])).digest())
            params['password'] = password_clear
        self.__post('user', params=params)


    def delete_user(self, user_or_user_name):
        '''
        Delete a user.  The CSKA will not delete the default admin user.

        :param user_or_user_name: User to delete.
        :type user_or_user_name: Type :py:class:`pycska.basetypes.User` or String

        :rtype: Not applicable

        Example usage::

          api.delete_user('jsmith')

        The above code will delete the user with the username *jsmith*.
        '''
        if isinstance(user_or_user_name, str) or isinstance(user_or_user_name, unicode):
            params = {'user_name': user_or_user_name}
        elif isinstance(user_or_user_name, User):
            params = user_or_user_name.to_dict()
        else:
            raise ValueError('Invalid type for user')
        self.__delete('user', params=params)


    def get_user_certificate(self, user_or_user_name):
        '''
        Get a user certificate by user or user_name.

        :param user_or_user_name: User to login to CSKA.
        :type user_or_user_name: Type :py:class:`pycska.basetypes.User` or String

        :rtype: String

        Example usage::

          cert = api.get_user_certificate('jsmith')

        The above code will retrieve the certificate for the given user.
        '''
        params = {}
        if isinstance(user_or_user_name, User):
            params['user_name'] = user_or_user_name.user_name
        elif isinstance(user_or_user_name, str) or isinstance(user_or_user_name, unicode):
            params['user_name'] = user_or_user_name
        else:
            raise ValueError('Invalid type for user')
        return self.__get('user_certificate', params=params)


    def get_user_certificate_state(self):
        '''
        Gets whether user certifcates are enforced.

        :rtype: Boolean

        Example usage::

          force_certs = api.get_user_certificate_state()

        The above code gets whether or not the CSKA is enforcing user side SSL certificates.
        '''
        return self.__get('user_certificate_state')


    def update_user_certificate_state(self, force_certificates):
        '''
        Sets whether user certifcates are enforced.

        :param force_certificates: Are user certficates forced.
        :type force_certificates: Boolean

        :rtype: Not applicable

        Example usage::

          api.update_user_certificate_state(True)

        The above code sets the CSKA to force user side SSL certificates.
        '''
        self.__post('user_certificate_state', {'force_certificates':force_certificates})


    def get_users(self):
        '''
        Get all the users.

        :rtype: List of :py:class:`pycska.basetypes.User`

        Example usage::

          users = api.get_users()

        The above code is used to get a list of all users created on the CSKA.
        '''
        return [User(content) for content in self.__get('users')]


    def delete_users(self, users):
        '''
        Delete a list of users.  The CSKA will not delete the default admin user.

        :param users: List of Users to delete.
        :type users: List of :py:class:`pycska.basetypes.User`

        :rtype: Not applicable

        Example usage::

          users = api.get_users()
          api.delete_users(users)

        The above code is used to delete all the users.  Note that the CSKA will not
        delete the default admin user.
        '''
        if users is None:
            users = []
        if not isinstance(users, list):
            raise ValueError('Invalid type for users')
        for user in users:
            if not isinstance(user, User):
                raise ValueError('Invalid type for user')
        params = {'users': [user.to_dict() for user in users]}
        self.__delete('users', params=params)


    def get_version(self):
        '''
        Get the current version of the CSKA.

        :rtype: String

        Example usage::

          version = api.get_version()

        The above code will get the current version of software running on the CSKA.
        '''
        return self.__get('version')
