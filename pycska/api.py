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

from pycska.basetypes import Action
from pycska.basetypes import ConfigProfile
from pycska.basetypes import Device
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


LICENSE_TYPE_CSKA = ["Channel Signing Key Authority"] #: CSKA License Type
LICENSE_TYPE_SIGNER = ["Channel Lock Signer"] #: Signer License Type
LICENSE_TYPE_VALIDATOR = ["Channel Lock Validator"] #: Validator License Type
LICENSE_TYPE_ALL = LICENSE_TYPE_CSKA + LICENSE_TYPE_SIGNER + LICENSE_TYPE_VALIDATOR #:All Licenses


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


    def get_allowed_actions(self):
        '''
        Get a list of the allowed actions for user rules.

        :rtype: List of :py:class:`pycska.basetypes.Action`
        '''
        return [Action(content) for content in self.__get('allowed_actions')]


    def post_block(self, devices=None, seats=None):
        '''
        Block a given device or a seat on a device.

        :param devices: Optional Id or Ids representing the device(s) to block.
        :type devices: List of :py:class:`pycska.basetypes.Device`
        :param seats: Optional Id or Ids representing the seat(s) to block.
        :type seats: List of :py:class:`pycska.basetypes.Seat`
        :rtype: An integer representing the number of devices blocked.
        '''
        if devices is None:
            devices = []
        if not isinstance(devices, list):
            raise ValueError("Invalid type for devices")
        for device in devices:
            if not isinstance(device, Device):
                raise ValueError("Invalid type for device")
        devices_param = [device.to_dict() for device in devices]
        if seats is None:
            seats = []
        if not isinstance(seats, list):
            raise ValueError("Invalid type for seats")
        for seat in seats:
            if not isinstance(seat, Seat):
                raise ValueError("Invalid type for seat")
        seats_param = [seat.to_dict() for seat in seats]
        return self.__post('block', {'devices':devices_param,
                                     'seats':seats_param})


    def get_capture(self, threat_id):
        '''
        Get the contents of a packet capture generated from a given *threat_id*.

        :param threat_id: Id representing the threat Id.
        :type threat_id: String
        :rtype: The raw contents of the pcap.
        '''
        return self.__get('capture', {'threat_id':threat_id})


    def get_config_profile(self, profile_id=None, profile_name=None):
        '''
        Get a specific configuration profile.

        :param profile_id: Optional value to filter the results on.
        :type profile_id: Integer

        :param profile_name: Optional value to filter the results on.
        :type profile_name: String

        :rtype: Type :py:class:`pycska.basetypes.ConfigProfile`
        '''
        params = {}
        if profile_id is not None:
            params['profile_id'] = profile_id
        if profile_name is not None:
            params['profile_name'] = profile_name
        return ConfigProfile(self.__get('config_profile', params=params))


    def post_config_profile(self, config_profile):
        '''
        Used to create or update a config profile.

        :param config_profile: Config profile to create or update.
        :type config_profile: Type :py:class:`pycska.basetypes.ConfigProfile`

        :rtype: Integer representing the profile id of the profile created or updated.
        '''
        if not isinstance(config_profile, ConfigProfile):
            raise ValueError("Invalid type for config_profile")
        return self.__post('config_profile', params=config_profile.to_dict())


    def delete_config_profile(self, config_profile):
        '''
        Delete a given configuration profile.

        :param config_profile: Configuration profile to delete.
        :type config_profile: Type :py:class:`pycska.basetypes.ConfigProfile`

        :rtype: Not applicable
        '''
        if not isinstance(config_profile, ConfigProfile):
            raise ValueError("Invalid type for config_profile")
        return self.__delete('config_profile', params=config_profile.to_dict())


    def get_config_profiles(self):
        '''
        Get the list of configuration profiles.

        :rtype: List of :py:class:`pycska.basetypes.ConfigProfile`
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
        '''
        if config_profiles is None:
            config_profiles = []
        if not isinstance(config_profiles, list):
            raise ValueError("Invalid type for config_profiles")
        for config_profile in config_profiles:
            if not isinstance(config_profile, ConfigProfile):
                raise ValueError("Invalid type for config_profile")
        params = {'profiles': [profile.to_dict() for profile in config_profiles],
                  'delete_all': delete_all}
        return self.__delete('config_profiles', params=params)


    def get_device(self, device_name=None, device_id=None):
        '''
        Get the a specific device by device_id or by device_name.

        :param device_name: Optional value to filter the results on.
        :type device_name: String

        :param device_id: Optional value to filter the results on.
        :type device_id: Integer

        :rtype: Type :py:class:`pycska.basetypes.Device`
        '''
        params = {}
        if device_id is not None:
            params['device_id'] = device_id
        if device_name is not None:
            params['device_name'] = device_name
        return Device(self.__get('device', params=params))


    def post_device(self, device):
        '''
        Used to update a device.  Only the profile and security groups are updated.

        :param device: Device to update.
        :type device: Type :py:class:`pycska.basetypes.Device`

        :rtype: Integer representing the profile id of the profile created or updated.
        '''
        if not isinstance(device, Device):
            raise ValueError("Invalid type for device")
        return self.__post('device', params=device.to_dict())


    def get_devices(self, device_id=None, device_name=None):
        '''
        Get a list of all devices.

        :param device_id: Optional value to filter the results on.
        :type device_id: Integer

        :param device_name: Optional value to filter the results on.
        :type device_name: String

        :rtype: List of :py:class:`pycska.basetypes.Device`
        '''
        filter_query = {}
        if device_id is not None:
            filter_query['device_id'] = device_id
        if device_name is not None:
            filter_query['device_name'] = device_name

        return [Device(content) for content in self.__get('devices',
                                                          params=filter_query)]


    def get_licenses(self, license_types=None):
        '''
        Get a list of all the licenses granted to the account.

        :param license_types: Which licenses to filter on, :py:data:`LICENSE_TYPE_CSKA`,
                              :py:data:`LICENSE_TYPE_SIGNER`, :py:data:`LICENSE_TYPE_VALIDATOR`,
                              :py:data:`LICENSE_TYPE_ALL`.
        :type license_types: String

        :rtype: List of :py:class:`pycska.basetypes.License`
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
        :type end_date: Integer

        :param is_usage: Usage or System logs.
        :type is_usage: Boolean

        :param format_as: Type of output - either json, raw, or csv
        :type format_as: String

        :rtype: String depending on format_as
        '''
        return self.__get('logs', params={'from': int(from_date),
                                          'to': int(to_date),
                                          'format_as': format_as,
                                          'is_usage': is_usage})


    def get_logging_plugins(self):
        '''
        Get the list of logging plugins.

        :rtype: List of :py:class:`pycska.basetypes.LoggingPlugin`
        '''
        return [LoggingPlugin(content) for content in self.__get('logging_plugins')]


    def get_network_graph(self):
        '''
        Get a JSON representation of the network graph.

        :rtype: JSON object showing the nodes and edges in the network.
        '''
        return self.__get('network_graph')


    def post_logging_plugins(self, logging_plugins):
        '''
        Used to set the entire list of logging plugins.

        :param logging_plugins: List of logging plugins to update to.
        :type logging_plugins: List of :py:class:`pycska.basetypes.LoggingPlugin`

        :rtype: Not applicable
        '''
        if not isinstance(logging_plugins, list):
            raise ValueError("Invalid type for logging_plugins")
        for logging_plugin in logging_plugins:
            if not isinstance(logging_plugin, LoggingPlugin):
                raise ValueError("Invalid type for logging_plugin")
        params = {'plugins': [logging_plugin.to_dict() for logging_plugin in logging_plugins]}
        return self.__post('logging_plugins', params=params)


    def delete_logging_plugins(self, logging_plugins=None, delete_all=False):
        '''
        Delete the list of logging plugins.

        :param logging_plugins: List of logging plugins to delete.
        :type logging_plugins: List of :py:class:`pycska.basetypes.LoggingPlugin`

        :rtype: Not applicable
        '''
        if logging_plugins is None:
            logging_plugins = []
        if not isinstance(logging_plugins, list):
            raise ValueError("Invalid type for logging_plugins")
        for logging_plugin in logging_plugins:
            if not isinstance(logging_plugin, LoggingPlugin):
                raise ValueError("Invalid type for logging_plugin")
        logging_plugins = [logging_plugin.to_dict() for logging_plugin in logging_plugins]
        return self.__delete('logging_plugins', {'plugins':logging_plugins,
                                                 'delete_all':delete_all})


    def get_oauth_client(self, client_name=None, client_id=None):
        '''
        Get an oauth client by client_name or client_id.

        :param client_name: Name of oauth client to retrieve.
        :type client_name: String

        :param client_id: Id of oauth client to retrieve.
        :type client_id: String

        :rtype: Type :py:class:`pycska.basetypes.OAuthClient`
        '''
        params = {}
        if client_name is not None:
            params['client_name'] = client_name
        if client_id is not None:
            params['client_id'] = client_id
        return OAuthClient(self.__get('oauth_client', params=params))


    def post_oauth_client(self, oauth_client, client_password=None, reset_token=False):
        '''
        Used to update/create an OAuth client.  Fields like 'name' and the 'password' are immutable.

        :param oauth_client: Client to update.
        :type oauth_client: Type :py:class:`pycska.basetypes.OAuthClient`

        :param client_password: Client password.  Only relevant for new oauth clients.
        :type client_password: String

        :param reset_token: Should the oauth keys be reset.
        :type reset_token: False

        :rtype: Integer representing the profile id of the profile created or updated.
        '''
        if not isinstance(oauth_client, OAuthClient):
            raise ValueError("Invalid type for oauth_client")
        params = {'client':oauth_client.to_dict(),
                  'reset_token':reset_token}
        if client_password is not None:
            params['client_password_hash'] = \
                binascii.hexlify(hashlib.sha256(client_password).digest())
        return self.__post('oauth_client', params=params)


    def delete_oauth_client(self, oauth_client):
        '''
        Delete a given oauth_client.

        :param oauth_client: OAuth client to delete.
        :type oauth_client: Type :py:class:`pycska.basetypes.OAuthClient`

        :rtype: Not applicable
        '''
        if not isinstance(oauth_client, OAuthClient):
            raise ValueError("Invalid type for oauth_client")
        return self.__delete('oauth_client', params=oauth_client.to_dict())


    def get_oauth_client_secret(self, oauth_client, client_password):
        '''
        Get an oauth client secret tokens for a given oauth client.

        :param oauth_client: Client to update.
        :type oauth_client: Type :py:class:`pycska.basetypes.OAuthClient`

        :param client_password: Client password.  Used to unlock the tokens.
        :type client_password: String

        :rtype: Type :py:class:`pycska.basetypes.OAuthClientSecret`
        '''
        params = {'client_id': oauth_client.client_id,
                  'client_password_hash':binascii.hexlify(hashlib.sha256(client_password).digest())}
        return OAuthClientSecret(self.__get('oauth_client_secret', params=params))


    def get_oauth_clients(self):
        '''
        Get the list of oauth clients.

        :rtype: List of :py:class:`pycska.basetypes.OAuthClient`
        '''
        return [OAuthClient(content) for content in self.__get('oauth_clients')]


    def delete_oauth_clients(self, oauth_clients):
        '''
        Deletes a list of oauth clients.

        :rtype: Not applicable
        '''
        if oauth_clients is None:
            oauth_clients = []
        if not isinstance(oauth_clients, list):
            raise ValueError("Invalid type for oauth_clients")
        for oauth_client in oauth_clients:
            if not isinstance(oauth_client, OAuthClient):
                raise ValueError("Invalid type for oauth_client")
        params = {'clients': [client.to_dict() for client in oauth_clients]}
        return self.__delete('oauth_clients', params=params),


    def get_oauth_state(self):
        '''
        Get the state of the OAuth API Explorer.

        :rtype: Boolean indicating if the API Explorer is enabled.
        '''
        return self.__get('oauth_state')


    def post_oauth_state(self, is_enabled):
        '''
        Set the state of the OAuth API Explorer.

        :param is_enabled: Is The OAuth API Explorer enabled.
        :type is_enabled: Boolean

        :rtype: Not applicable.
        '''
        return self.__post('oauth_state', {'oauth_browser': is_enabled})


    def get_overlay(self):
        '''
        Get the network overlay JSON used to overlay non channel locked devices
        on to the network graph.

        :rtype: String
        '''
        return self.__get('overlay')


    def post_overlay(self, overlay_contents):
        '''
        Set the network overlay JSON used to overlay non channel locked devices
        on to the network graph.

        :param overlay_contents: Contents of overlay file.
        :type overlay_contents: String

        :rtype: Not applicable.
        '''
        return self.__post('overlay', overlay_contents)


    def delete_overlay(self):
        '''
        Delete the network overlay JSON used to overlay non channel locked devices
        on to the network graph.

        :rtype: Not applicable.
        '''
        return self.__delete('overlay')


    def get_remote_support(self):
        '''
        Get the state of remote support ssh access.

        :rtype: Boolean indicating whether SSH access is allowed.
        '''
        return self.__get('remote_support')


    def post_remote_support(self, is_on):
        '''
        Set the state of remote support ssh access.

        :param is_on: Is SSH access to be enabled.
        :type is_on: Boolean

        :rtype: Not applicable.
        '''
        return self.__post('remote_support', {'is_on':is_on})


    def post_seat(self, device, infersight_license):
        '''
        Assign the given InferSight license to the device.

        :param device: Device to assign license to.
        :type device: Type :py:class:`pycska.basetypes.Device`

        :param infersight_license: License to assign to device.
        :type infersight_license: Type :py:class:`pycska.basetypes.License`

        :rtype: Type :py:class:`pycska.basetypes.License`
        '''
        if not isinstance(device, Device):
            raise ValueError("Invalid type for device")
        if not isinstance(infersight_license, License):
            raise ValueError("Invalid type for infersight_license")
        return self.__post('seat', {'device': device.to_dict(),
                                    'license': infersight_license.to_dict()})


    def delete_seat(self, seat):
        '''
        Revoke the specified seat.

        :param seat: Seat to revoke.
        :type seat: Type :py:class:`pycska.basetypes.Seat`

        :rtype: Not applicable.
        '''
        if not isinstance(seat, Seat):
            raise ValueError("Invalid type for seat")
        return self.__delete('seat', {'seat': seat.to_dict()})


    def get_security_group(self, group_name=None, group_id=None):
        '''
        Get the a specific security group by group_id or by group_name.

        :param group_name: Optional value to filter the results on.
        :type group_name: String

        :param group_id: Optional value to filter the results on.
        :type group_id: Integer

        :rtype: Type :py:class:`pycska.basetypes.SecurityGroup`
        '''
        params = {}
        if group_id is not None:
            params['group_id'] = group_id
        if group_name is not None:
            params['group_name'] = group_name
        return SecurityGroup(self.__get('security_group', params=params))


    def post_security_group(self, group):
        '''
        Used to create or update a security_group

        :param group: Security group to create or update.
        :type group: Type :py:class:`pycska.basetypes.SecurityGroup`

        :rtype: Integer representing the group id of the profile created or updated.
        '''
        if not isinstance(group, SecurityGroup):
            raise ValueError("Invalid type for group")
        return self.__post('security_group', params=group.to_dict())


    def delete_security_group(self, group):
        '''
        Delete a security group.

        :param group: Group to delete.
        :type group: Type :py:class:`pycska.basetypes.SecurityGroup`

        :rtype: Not applicable
        '''
        if not isinstance(group, SecurityGroup):
            raise ValueError("Invalid type for group")
        return self.__delete('security_group', params=group.to_dict())


    def get_security_groups(self):
        '''
        Get all security groups.

        :rtype: List of :py:class:`pycska.basetypes.SecurityGroup`
        '''
        return [SecurityGroup(content) for content in self.__get('security_groups')]

    def delete_security_groups(self, groups=None, delete_all=False):
        '''
        Delete a list of security groups.

        :param groups: Groups to delete.
        :type groups: List of :py:class:`pycska.basetypes.SecurityGroup`

        :param delete_all: Are we deleting all config profiles.
        :type delete_all: Boolean

        :rtype: Not applicable
        '''
        if groups is None:
            groups = []
        if not isinstance(groups, list):
            raise ValueError("Invalid type for groups")
        for group in groups:
            if not isinstance(group, SecurityGroup):
                raise ValueError("Invalid type for group")
        params = {'groups': [group.to_dict() for group in groups],
                  'delete_all': delete_all}
        return self.__delete('security_groups', params=params)


    def get_stats(self, device_id=None, seat_id=None):
        '''
        Get the stats for a given device or seat.

        :rtype: List of :py:class:`pycska.basetypes.Stats`
        '''
        params = {}
        if device_id is not None:
            params['device_id'] = device_id
        if seat_id is not None:
            params['seat_id'] = seat_id
        return [Stats(content) for content in self.__get('stats', params=params)]


    def delete_stats(self, device_id=None, seat_id=None):
        '''
        Clear the stats for a given device or seat.

        :rtype: Not applicable
        '''
        params = {}
        if device_id is not None:
            params['device_id'] = device_id
        if seat_id is not None:
            params['seat_id'] = seat_id
        return self.__delete('stats', params=params)


    def get_system_status(self):
        '''
        Get the current system status.

        :rtype: Type :py:class:`pycska.basetypes.SystemStatus`
        '''
        return SystemStatus(self.__get('system_status'))


    def get_threats(self, start, limit, load_acknowledged=False):
        '''
        Get the current list of threats.

        :rtype: Tuple (List of :py:class:`pycska.basetypes.Threat`, Number of threats)
        '''
        threats, total = self.__get('threats', {'start':start,
                                                'limit':limit,
                                                'load_acknowledged':load_acknowledged}, True)
        return ([Threat(content) for content in threats], total)


    def post_threats(self, ack_state, threats=None, modify_all=False):
        '''
        Update the acknowledged state on a list of threats or on all threats.

        :param ack_state: Flag indicating the new state of the threat(s).
        :type ack_state: Boolean

        :param threats: Optional threat(s) to update the ack state for.
        :type threats: List of :py:class:`pycska.basetypes.Threat`

        :param modify_all: Optional flag indicating if all threats are to be updated.
        :type modify_all: Boolean

        :rtype: Not applicable
        '''
        if threats is None:
            threats = []
        threats_param = [threat.to_dict() for threat in threats]
        return self.__post('threats', {'threats':threats_param,
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
        '''
        if threats is None:
            threats = []
        threats_param = [threat.to_dict() for threat in threats]
        return self.__delete('threats', {'threats':threats_param,
                                         'delete_all':delete_all})


    def post_ticket(self, priority, short_reason, long_reason, use_remote_support):
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
        '''
        return self.__post('ticket', {'priority':priority,
                                      'short_reason':short_reason,
                                      'long_reason':long_reason,
                                      'use_remote_support':use_remote_support})


    def post_unblock(self, devices=None, seats=None):
        '''
        Unblock a given device or a seat on a device.

        :param devices: Optional device(s) to unblock.
        :type devices: List of :py:class:`pycska.basetypes.Device`
        :param seats: Optional seat(s) to unblock.
        :type seats: List of :py:class:`pycska.basetypes.Seat`
        :rtype: An integer representing the number of devices unblocked.
        '''
        if devices is None:
            devices = []
        if not isinstance(devices, list):
            raise ValueError("Invalid type for devices")
        for device in devices:
            if not isinstance(device, Device):
                raise ValueError("Invalid type for device")
        devices_param = [device.to_dict() for device in devices]
        if seats is None:
            seats = []
        if not isinstance(seats, list):
            raise ValueError("Invalid type for seats")
        for seat in seats:
            if not isinstance(seat, Seat):
                raise ValueError("Invalid type for seat")
        seats_param = [seat.to_dict() for seat in seats]
        return self.__post('unblock', {'devices':devices_param,
                                       'seats':seats_param})


    def get_user(self, user_name=None):
        '''
        Get a user by user name.

        :param user_name: User name used to login to CSKA.
        :type user_name: String

        :rtype: Type :py:class:`pycska.basetypes.User`
        '''
        params = {}
        if user_name is not None:
            params['user_name'] = user_name
        return User(self.__get('user', params=params))


    def post_user(self, user, password_clear=None):
        '''
        Update a user.

        :param user: User to update or create.
        :type user: Type :py:class:`pycska.basetypes.user`

        :rtype: Not applicable
        '''
        params = {'user':user.to_dict()}
        if password_clear is not None:
            params['password_salt'] = binascii.hexlify(hashlib.sha256(\
                ''.join([chr(int(random.random()*256)) for _ in range(256)])).digest())
            params['password'] = password_clear
        return self.__post('user', params=params)


    def delete_user(self, user):
        '''
        Delete a user.

        :param user: User to delete.
        :type user: Type :py:class:`pycska.basetypes.user`

        :rtype: Not applicable
        '''
        if not isinstance(user, User):
            raise ValueError("Invalid type for user")
        return self.__delete('user', params=user.to_dict())


    def get_user_certificate(self, user_or_user_name):
        '''
        Get a user certificate by user or user_name.

        :param user: User to login to CSKA.
        :type user: Type :py:class:`pycska.basetypes.user` or String

        :rtype: String
        '''
        params = {}
        if isinstance(user_or_user_name, User):
            params['user_name'] = user_or_user_name.user_name
        elif isinstance(user_or_user_name, str) or isinstance(user_or_user_name, unicode):
            params['user_name'] = user_or_user_name
        else:
            raise ValueError("Invalid type for user")
        return self.__get('user_certificate', params=params)


    def get_user_certificate_state(self):
        '''
        Gets whether user certifcates are enforced.

        :rtype: Boolean
        '''
        return self.__get('user_certificate_state')


    def post_user_certificate_state(self, force_certificates):
        '''
        Sets whether user certifcates are enforced.

        :param force_certificates: Are user certficates forced.
        :type force_certificates: Boolean

        :rtype: Not applicable
        '''
        return self.__post('user_certificate_state', {'force_certificates':force_certificates})


    def get_user_rule(self, rule_id=None):
        '''
        Get a specific user rule.

        :param rule_id: Optional value to filter the results on.
        :type rule_id: Integer

        :rtype: Type :py:class:`pycska.basetypes.Rule`
        '''
        params = {}
        if rule_id is not None:
            params['rule_id'] = rule_id
        return Rule(self.__get('user_rule', params=params))


    def post_user_rule(self, rule):
        '''
        Update a specific user rule or create a new rule.

        :param rule: Rule to update/create.  Leave rule_id blank to create a new rule.
        :type rule: Type :py:class:`pycska.basetypes.Rule`

        :rtype: Integer - rule_id
        '''
        if not isinstance(rule, Rule):
            raise ValueError('Invalid type for rule')
        return self.__post('user_rule', params=rule.to_dict())


    def delete_user_rule(self, rule):
        '''
        Delete a specific user rule.

        :param rule: Rule to delete.
        :type rule: Type :py:class:`pycska.basetypes.Rule`

        :rtype: Not applicable
        '''
        if not isinstance(rule, Rule):
            raise ValueError('Invalid type for rule')
        return self.__delete('user_rule', params=rule.to_dict())


    def get_user_rules(self, rule_id=None, rule_name=None):
        '''
        Get a list of the user rules.

        :param rule_name: Optional value to filter the results on.
        :type rule_name: String

        :param rule_id: Optional value to filter the results on.
        :type rule_id: Integer

        :rtype: List of :py:class:`pycska.basetypes.Rule`
        '''
        params = {}
        if rule_id is not None:
            params['rule_id'] = rule_id
        if rule_name is not None:
            params['rule_name'] = rule_name
        return [Rule(content) for content in self.__get('user_rules', params=params)]


    def delete_user_rules(self, user_rules=None, delete_all=False):
        '''
        Delete the list of user_rules.

        :param user_rules: List of user rules to delete.
        :type user_rules: List of :py:class:`pycska.basetypes.Rule`

        :param delete_all: Are we deleting all user rules.
        :type delete_all: Boolean

        :rtype: Not applicable
        '''
        if user_rules is None:
            user_rules = []
        if not isinstance(user_rules, list):
            raise ValueError("Invalid type for user_rules")
        for user_rule in user_rules:
            if not isinstance(user_rule, Rule):
                raise ValueError("Invalid type for user_rule")
        params = {'rules': [rule.to_dict() for rule in user_rules],
                  'delete_all': delete_all}
        return self.__delete('user_rules', params=params)


    def get_users(self):
        '''
        Get all the users.

        :rtype: List of :py:class:`pycska.basetypes.User`
        '''
        return [User(content) for content in self.__get('users')]


    def delete_users(self, users):
        '''
        Delete the list of users.

        :param users: List of Users to delete.
        :type users: List of :py:class:`pycska.basetypes.User`

        :rtype: Not applicable
        '''
        if users is None:
            users = []
        if not isinstance(users, list):
            raise ValueError("Invalid type for users")
        for user in users:
            if not isinstance(user, User):
                raise ValueError("Invalid type for user")
        params = {'users': [user.to_dict() for user in users]}
        return self.__delete('users', params=params)


    def get_version(self):
        '''
        Get the current version of the CSKA.

        :rtype: String
        '''
        return self.__get('version')
