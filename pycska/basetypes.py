'''
API Data Types used in pycska.
'''

#pylint: disable=too-few-public-methods

import json

class CSKAType(object):
    '''
    Base type for all complex types used in the CSKA API.

    Must be subclassed by every complex type and each subclass must at the very
    least implement the **fields** property getter.  This property defines all
    the fields that are allowed in the type.  By default there is a 1:1 mapping
    of the field names specified in fields with the field names actually
    used in the API.  However, if the API changes we can keep the same field names
    in this file and simply implement the **_field_overrides** getter and specify
    the new mapping.  For instance in the ConfigProfile class below::

        @property
        def _field_overrides(self):
            return {'configuration':'config'}

    In the above case, the *configuration* field used in the CSKA Api was renamed to
    *config* in the software.  In order to keep users of this file from having to change,
    we can simply specify the mapping above.
    '''
    def __init__(self, raw_type=None):
        if raw_type is None:
            raw_type = {}
        if isinstance(raw_type, dict):
            for key, value in raw_type.items():
                if isinstance(value, list):
                    new_value = []
                    for item in value:
                        if hasattr(item, 'to_dict'):
                            new_value.append(item.to_dict())
                        else:
                            new_value.append(item)
                    raw_type[key] = new_value
                if hasattr(value, 'to_dict'):
                    raw_type[key] = value.to_dict()
            self.__dict__['_raw_type'] = raw_type
        else:
            raise ValueError("raw_type must be a dictionary")

    def __dir__(self):
        return self._fields

    def __setattr__(self, attr, value):
        if self.__dict__.has_key(attr):
            self.__dict__[attr] = value
            return
        if attr not in list(self._fields):
            raise ValueError
        complex_type = self._complex_fields.get(attr, None)
        attr = self._field_overrides.get(attr, attr)
        if complex_type is not None:
            if isinstance(value, list):
                value = [json.loads('%s'%item) for item in value]
            else:
                value = json.loads('%s'%value)
        self.__dict__['_raw_type'][attr] = value

    def __getattr__(self, attr):
        if self.__dict__.has_key(attr):
            return self.__dict__[attr]
        if attr not in list(self._fields):
            return None
        complex_type = self._complex_fields.get(attr, None)
        attr = self._field_overrides.get(attr, attr)
        raw_value = self._raw_type.get(attr, None)
        if complex_type is not None:
            if isinstance(raw_value, list):
                return [complex_type(item)  for item in raw_value]
            else:
                return complex_type(raw_value)
        return raw_value

    def __repr__(self):
        return json.dumps({key: value for key, value in self._raw_type.items() if key[0] != '_'})

    def to_dict(self):
        '''
        Convert back into a dictionary form that can be used for the actual API call.

        :rtype: Dictionary of fields relevant to the child type.
        '''
        return self._raw_type

    @property
    def _fields(self):
        '''
        Returns the list of valid fields for the given type.

        This getter must be implemented by the child type.

        :rtype: List of fields relevant to the child type.
        '''
        return NotImplemented

    @property
    def _field_overrides(self):
        '''
        Optional getter specifying a mapping between user field names and
        CSKA API field names.

        This is normally left as an empty dictionary but in
        the case where a field name changes in the API and we want to abstract this change
        from the user then we add a key/value pair to this dictionary where the key is
        the user's field name (or old name of the API field name) and the value specified is
        the new name for the field in the API.

        :rtype: Dictionary specifying 'old_name':'new_name'.
        '''
        return {}

    @property
    def _complex_fields(self):
        '''
        Returns a dictionary of field to complex class for any fields that
        need to be represented by another CSKAType.

        This getter is optionally implemented by the child type.

        :rtype: A dictionary where the keys are one of the fields and the value
                is a CSKAType class that represents the field.
        '''
        return {}


class ConfigProfile(CSKAType):
    '''
    Configuration profile for a device.

    Configuration profiles are specified with the following fields:
      - profile_id (int): Id representing profile - leave empty for new profiles.
      - profile_name (string): Name to give profile.
      - configuration: Type :py:class:`pycska.basetypes.ProfileDetails`
    '''
    @property
    def _fields(self):
        return ['profile_id', 'profile_name', 'configuration']

    @property
    def _complex_fields(self):
        return {'configuration':ProfileDetails}


class Device(CSKAType):
    '''
    Details for a device.

    Device details are specified with the following fields:
      - device_id (int): Internal Id representing the device.
      - device_name (string): Usually the hostname for the device.
      - number_interfaces (int): Number of physical interfaces (Not implemented on Windows).
      - platform_name (string): Linux, Windows.
      - profile: Type :py:class:`pycska.basetypes.ConfigProfile`
      - is_blocked (bool): Is the device currently blocked.
      - is_signer (bool): Is the device a signer.
      - signer_seat: Type :py:class:`pycska.basetypes.Seat`.
      - is_validator (bool): Is the device a validator.
      - validator_seat: Type :py:class:`pycska.basetypes.Seat`.
      - is_online (bool): Is the device currently online.
      - security_groups: List of :py:class:`pycska.basetypes.SecurityGroupSummary`
      - allocated_licenses: Object where key is the license type and value is the seat id.
      - requested_licenses: Object where key is the license type and value is timestamp when
                            license was requested (seconds since epoch).  Only licenses that
                            have not been allocated yet stay in this object.  Also, licenses
                            that haven't been requested for after a period of time will get
                            removed.  This happens if a device that is unallocated is offline
                            and is no longer requesting a license.
    '''
    @property
    def _fields(self):
        return ['device_id', 'device_name', 'number_interfaces', 'platform_name', 'profile',
                'is_blocked', 'is_signer', 'signer_seat', 'is_validator', 'validator_seat',
                'is_online', 'security_groups', 'allocated_licenses', 'requested_licenses']

    @property
    def _complex_fields(self):
        return {'profile':ConfigProfile, 'security_groups':SecurityGroupSummary,
                'signer_seat':Seat, 'validator_seat':Seat}


class License(CSKAType):
    '''
    Infersight License.

    Licenses are specified with the following fields:
      - license_id (int): Internal Id representing the Id for the given type of license.
      - amount (int): Number of this type of license granted to organization.
      - license_type (string): License name - i.e. Channel Lock Signer.
      - allocated (int): Number of this type already used up.
      - expire_date (int): Seconds since epoch (UTC) when the license will expire.
    '''
    @property
    def _fields(self):
        return ['license_id', 'amount', 'license_type', 'allocated', 'expire_date']


class LoggingPlugin(CSKAType):
    '''
    Logging Plugin details.

    Logging Plugins are specified with the following fields:
      - plugin_name (string): Name of logging plugin.
      - ip (string): Address of the logging store.
      - port (int): Port the logging store is listening on.
      - protocol (string): Protocol the logging store is listening for - UDP, TCP.
      - url (string): Optional landing page for the logging store.
      - rfc3164 (bool): Is the logging store expecting rfc3164 compliant logs.
      - reachable (bool): Is the configured landing page reachable.
    '''
    @property
    def _fields(self):
        return ['plugin_name', 'ip', 'port', 'protocol', 'url', 'rfc3164', 'reachable']


class OAuthClient(CSKAType):
    '''
    OAuth client details.

    OAuth clients are specified with the following fields:
      - client_id (string): Server created id representing the client.
      - name (string): Name of the oauth client.
      - description (string): Optional description to give the client.
      - allow_oauth1 (bool): Is OAuth1 allowed with this client.
      - allow_oauth2 (bool): Is OAuth2 allowed with this client.
      - default_scopes_list (list): List of scopes.
      - redirect_uris_list (list): List of possible redirects.
    '''
    @property
    def _fields(self):
        return ['client_id', 'name', 'description', 'allow_oauth1', 'allow_oauth2',
                'default_scopes_list', 'redirect_uris_list']


class OAuthClientSecret(CSKAType):
    '''
    OAuth client secret details.

    OAuth client secrets are specified with the following fields:
      - client_id (string): Server created id representing the client.
      - client_secret (string): OAuth1/2 client secret.
      - oauth1_token (string): OAuth1 token or empty if OAuth1 is not allowed.
      - oauth1_token_secret (string): OAuth1 token secret or empty if OAuth1 is not allowed.
      - oauth2_token (string): OAuth2 token or empty if OAuth2 is not allowed.
      - oauth2_refresh_token (string): OAuth2 refresh token or empty if OAuth2 is not allowed.
    '''
    @property
    def _fields(self):
        return ['client_id', 'client_secret', 'oauth1_token', 'oauth1_token_secret', 'oauth2_token',
                'oauth2_refresh_token']


class ProfileDetails(CSKAType):
    '''
    Configuration details of a given profile.  This is a subtype to ConfigProfile.

    Configuration details are specified with the following fields:
      - license_renew_time (int): Amount of time between license renewals in seconds.
      - log_level (string): Log level for devices using this profile - Error, Info, Debug.
      - capture_threats (bool): Are PCAPs generated for detected threats.
      - syslog_filter (string): Optional, syslog filter if listening to a third party syslog source.
    '''
    @property
    def _fields(self):
        return ['license_renew_time', 'capture_threats', 'log_level', 'syslog_filter']


class Rule(CSKAType):
    '''
    CSKA Rule.

    Rules are specified with the following fields:
      - rule_id (int): Internal Id representing the rule.
      - rule_name (string): Name of the rule.
      - description (string): Optional extra description specified for a rule.
      - meta (string): Optional extra data specified for a rule.
      - action (string): One of the allowed actions - i.e. Sign, Validate and Strip, Drop.
      - hash_algorithm (string): One of the allowed hash algorithms - i.e. xor, sha1.
      - layer (int): Lowest layer used for signing and validating - This layer and above are used.
      - include_dos_protection (bool): Is extra information added/verified for DOS protection.
      - custom_bpf (string): If specified then this overrides all other fields below.
      - protocol (string): Protocol used - TCP, UDP, UDP or TCP.
      - start_port (int): Beginning of port range that rule applies to.
      - end_port (int): End of port range that rule applies to.
      - src_cidr (string): Valid CIDR string representing source IP addresses.
      - dst_cidr (string): Valid CIDR string representing destination IP addresses.
    '''
    @property
    def _fields(self):
        '''
        List of relevant fields.

        :rtype: List of fields.
        '''
        return ['rule_id', 'rule_name', 'meta', 'action', 'hash_algorithm', 'layer',
                'include_dos_protection', 'custom_bpf', 'protocol', 'start_port',
                'end_port', 'src_cidr', 'dst_cidr', 'description']


class RuleSummary(CSKAType):
    '''
    Core details of a user rule.

    RuleSummary contains the following fields:
      - rule_id (int): Internal Id representing the user rule.
      - rule_name (string): Name of the user rule.
    '''
    @property
    def _fields(self):
        return ['rule_id', 'rule_name']


class Seat(CSKAType):
    '''
    license seat details.

    seat details contain the following fields:
      - seat_id (string): internal id representing the license seat.
      - license_name (string): type of license for the seat.
    '''
    @property
    def _fields(self):
        return ['seat_id', 'license_name']


class SecurityGroup(CSKAType):
    '''
    Full details of a security group.

    SecurityGroup contains the following fields:
      - group_id (int): Internal Id representing the security group.
      - group_name (string): Name of the security group.
      - description (string): Optional description for the group.
      - meta (string): Optional metadata for the group.
      - signer_rules: List of :py:class:`pycska.basetypes.RuleSummary`
      - validator_rules: List of :py:class:`pycska.basetypes.RuleSummary`
      - validates_groups: List of :py:class:`pycska.basetypes.SecurityGroupSummary`
    '''
    @property
    def _fields(self):
        return ['group_id', 'group_name', 'description', 'meta', 'signer_rules',
                'validator_rules', 'validates_groups']

    @property
    def _complex_fields(self):
        return {'signer_rules':RuleSummary, 'validator_rules':RuleSummary,
                'validates_groups':SecurityGroupSummary}


class StatsCounter(CSKAType):
    '''
    Common properties for all stats counters.

    Stats counters contain the following fields:
      - seconds: Current count per second.
      - minutes: Current count per minute.
      - hours: Current count per hour.
      - total: Total number of counter.
    '''
    @property
    def _fields(self):
        return ['seconds', 'minutes', 'hours', 'total']


class StatsDriver(CSKAType):
    '''
    The driver holds stats for different counters.

    Not all the counters are implemented for each seat type but the following
    fields are all possible counters that are kept track of:
      - signed_packets (:py:class:`pycska.basetypes.StatsCounter`)
        - Number of signed packets.
      - dropped_verify_bad_packets (:py:class:`pycska.basetypes.StatsCounter`)
        - Dropped due to bad verification.
      - seen_packets (:py:class:`pycska.basetypes.StatsCounter`)
        - Number of packets passed through driver.
      - accept_allow_all_packets (:py:class:`pycska.basetypes.StatsCounter`)
        - Number of packets accepted because driver is configured to allow all.
      - accept_unverified_packets (:py:class:`pycska.basetypes.StatsCounter`)
        - Number of packets accepted because rules are not set to verify the packet.
      - accept_verify_good_packets (:py:class:`pycska.basetypes.StatsCounter`)
        - Number of packets accepted because they were verified by the driver.
      - accept_allow_unsigned_packets (:py:class:`pycska.basetypes.StatsCounter`)
        - Number of packets accepted because they failed verification but mode is set to allow.
    '''
    @property
    def _fields(self):
        return ['signed_packets', 'dropped_verify_bad_packets', 'seen_packets',
                'accept_allow_all_packets', 'accept_unverified_packets',
                'accept_verify_good_packets', 'accept_allow_unsigned_packets']

    @property
    def _complex_fields(self):
        return {'signed_packets':StatsCounter,
                'dropped_verify_bad_packets':StatsCounter,
                'seen_packets':StatsCounter,
                'accept_allow_all_packets':StatsCounter,
                'accept_unverified_packets':StatsCounter,
                'accept_verify_good_packets':StatsCounter,
                'accept_allow_unsigned_packets':StatsCounter}


class Stats(CSKAType):
    '''
    Stats for a give seat license - either signer or validator.

    Stat details contain the following fields:
      - seat: Type :py:class:`pycska.basetypes.Seat`
      - up_time: How long has the seat been up in seconds.
      - last_updated: When did the seat last contact the CSKA.  Seconds since epoch (UTC).
      - cpu_percent: Current CPU utilization for device that the seat is running on.
      - memory_percent: Current memory utilization for device that the seat is running on.
      - driver: Stats details from the low level driver.
    '''
    @property
    def _fields(self):
        return ['seat', 'up_time', 'last_updated', 'cpu_percent', 'driver']

    @property
    def _complex_fields(self):
        return {'seat':Seat, 'driver':StatsDriver}


class SecurityGroupSummary(CSKAType):
    '''
    Core details of a security group.  This type or the core SecurityGroup type can be
    used when updating the security gorups that a device belongs to.

    SecurityGroupSummary contains the following fields:
      - group_id (int): Internal Id representing the security group.
      - group_name (string): Name of the security group.
    '''
    @property
    def _fields(self):
        return ['group_id', 'group_name']


class SystemStatus(CSKAType):
    '''
    System status details.

    System status contains the following fields:
      - num_offline (int): Number of devices currently offline.
      - num_online (int): Number of devices currently online.
      - num_threats (int): Number of un-acknowledged threats.
      - num_oauth1 (int): Number of clients that are allowed to used OAuth1.
      - num_oauth2 (int): Number of clients that are allowed to used OAuth2.
      - remote_support_enabled (bool): Is remote support access allowed.
    '''
    @property
    def _fields(self):
        return ['num_offline', 'num_online', 'num_threats', 'num_oauth1',
                'num_oauth2', 'remote_support_enabled']


class Threat(CSKAType):
    '''
    Threat details.

    Threat details contain the following fields:
      - time (int): Seconds since epoch (UTC) when threat occurred.
      - threat_id (string): Unique internal id representing the threat.
      - threat (string): Description of the threat.
      - count (int): Number of threats in this record.
      - has_capture (bool): Is there a capture available for this threat.
      - acknowledged (bool): Has this threat been acknowledged.
      - name (string): Name of signing device or the IP address if the source is unknown.
      - signer_seat_id (string): Seat id of the signer if the source is known.
      - device_id (string): Device id of the signer if the source is known.
      - device (:py:class:`pycska.basetypes.Device`)
        - Device of the signer if the source is known.
      - validator (string): Name of the validator that detected the issue.
      - validator_seat_id (string): Seat id of the validator that detected the issue.
      - seat_id (string): Seat id of the device that detected the issue - typically the validator.
    '''
    @property
    def _fields(self):
        return ['time', 'threat_id', 'threat', 'count', 'has_capture', 'acknowledged',
                'name', 'signer_seat_id', 'device_id', 'validator', 'validator_seat_id',
                'seat_id', 'device']

    @property
    def _complex_fields(self):
        return {'device':Device}


class User(CSKAType):
    '''
    User details.

    Users contain the following fields:
        - user_name (string): Name used to login to CSKA with.
        - full_name (string): Full name of user.
        - is_certificate_downloaded (bool): Has the user cert been downloaded yet.
        - password_salt (string): Hex Random value of up to 64 chars - usually sha256 of a random.
        - password_hash (string): Hex SHA256 hash of (clear text pwd + password_salt)
    '''
    @property
    def _fields(self):
        return ['user_name', 'full_name', 'is_certificate_downloaded', 'password_salt',
                'password_hash']
