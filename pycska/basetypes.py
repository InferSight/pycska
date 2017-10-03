'''
API Data Types used in pycska.
'''

import json

class CSKAType(object):
    '''
    Base type for all complex types used in the CSKA API.

    Must be subclassed by every complex type and each subclass must at the very
    least implement the **fields** property getter.  This property defines all
    the fields that are allowed in the type.  By default there is a 1:1 mapping
    of the field names specified in fields with the field names actually
    used in the API.  However, if the API changes we can keep the same field names
    in this file and simply implement the **field_overrides** getter and specify
    the new mapping.  For instance in the Action class below::

        @property
        def field_overrides(self):
            return {'signer':'signer_changed'}

    In the above case, the *signer* field used in the CSKA Api was renamed to
    *signer_changed*.  In order to keep this file the same so users of this code
    don't have to change, we can simply specify the mapping above.
    '''
    def __init__(self, raw_type=None):
        if raw_type is None:
            raw_type = {}
        if isinstance(raw_type, dict):
            self.__dict__['_raw_type'] = raw_type
        else:
            raise ValueError("raw_type must be a dictionary")

    def __setattr__(self, attr, value):
        if self.__dict__.has_key(attr):
            self.__dict__[attr] = value
            return
        if attr not in list(self.fields):
            raise ValueError
        complex_type = self.complex_fields.get(attr, None)
        attr = self.field_overrides.get(attr, attr)
        if complex_type is not None:
            if isinstance(value, list):
                value = [json.loads('%s'%item) for item in value]
            else:
                value = json.loads('%s'%value)
        self.__dict__['_raw_type'][attr] = value

    def __getattr__(self, attr):
        if self.__dict__.has_key(attr):
            return self.__dict__[attr]
        if attr not in list(self.fields):
            return None
        complex_type = self.complex_fields.get(attr, None)
        attr = self.field_overrides.get(attr, attr)
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
    def fields(self):
        '''
        Returns the list of valid fields for the given type.

        This getter must be implemented by the child type.

        :rtype: List of fields relevant to the child type.
        '''
        return NotImplemented

    @property
    def field_overrides(self):
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
    def complex_fields(self):
        '''
        Returns a dictionary of field to complex class for any fields that
        need to be represented by another CSKAType.

        This getter is optionally implemented by the child type.

        :rtype: A dictionary where the keys are one of the fields and the value
                is a CSKAType class that represents the field.
        '''
        return {}




class Action(CSKAType):
    '''
    CSKA Rule Actions.

    Actions are specified with the following fields:
      - action_id (int): Internal Id representing the rule action.
      - action (string): Name of rule action.
      - signer (bool): Does this application apply to signers.
      - validator (bool): Does this application apply to validators.
    '''
    @property
    def fields(self):
        '''
        List of relevant fields.

        :rtype: List of fields.
        '''
        return ['action_id', 'action', 'signer', 'validator']


class ConfigProfile(CSKAType):
    '''
    Configuration profile for a device.

    Configuration profiles are specified with the following fields:
      - profile_id (int): Id representing profile - leave empty for new profiles.
      - profile_name (string): Name to give profile.
      - configuration: Type :py:class:`pycska.basetypes.ProfileDetails`
    '''
    @property
    def fields(self):
        return ['profile_id', 'profile_name', 'configuration']

    @property
    def complex_fields(self):
        return {'configuration':ProfileDetails}


class Device(CSKAType):
    '''
    Details for a device.

    Device details are specified with the following fields:
      - device_id (int): Internal Id representing the device.
      - device_name (string): Usually the hostname for the device.
      - number_interfaces (int): Number of physical interfaces (Not implemented on Windows).
      - platform_name (string): Linux, Windows.
      - profile: Type :py:class:`pycska.basetypes.Profile`
      - is_blocked (bool): Is the device currently blocked.
      - is_signer (bool): Is the device a signer.
      - signer_seat_id (string): Identifies the signer license if this is a signer.
      - is_validator (bool): Is the device a validator.
      - validator_seat_id (string): Identifies the validator license if this is a validator.
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
    def fields(self):
        return ['device_id', 'device_name', 'number_interfaces', 'platform_name', 'profile',
                'is_blocked', 'is_signer', 'signer_seat_id', 'is_validator', 'validator_seat_id',
                'is_online', 'security_groups', 'allocated_licenses', 'requested_licenses']

    @property
    def complex_fields(self):
        return {'profile':ConfigProfile, 'security_groups':SecurityGroupSummary}


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
    def fields(self):
        return ['license_id', 'amount', 'license_type', 'allocated', 'expire_date']


class LoggingPlugin(CSKAType):
    '''
    Logging Plugin details.

    Logging Plugins are specified with the following fields:
      - name (string): Name of logging plugin.
      - ip (string): Address of the logging store.
      - port (int): Port the logging store is listening on.
      - protocol (string): Protocol the logging store is listening for - UDP, TCP.
      - url (string): Optional landing page for the logging store.
      - rfc3164 (bool): Is the logging store expecting rfc3164 compliant logs.
      - reachable (bool): Is the configured landing page reachable.
    '''
    @property
    def fields(self):
        return ['name', 'ip', 'port', 'protocol', 'url', 'rfc3164', 'reachable']


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
    def fields(self):
        return ['client_id', 'name', 'description', 'allow_oauth1', 'allow_oauth2',
                'default_scopes_list', 'redirect_uris_list']


class OAuthClientSecret(CSKAType):
    '''
    OAuth client secret details.

    OAuth client secrets are specified with the following fields:
      - client_secret (string): OAuth1/2 client secret.
      - oauth1_token (string): OAuth1 token or empty if OAuth1 is not allowed.
      - oauth1_token_secret (string): OAuth1 token secret or empty if OAuth1 is not allowed.
      - oauth2_token (string): OAuth2 token or empty if OAuth2 is not allowed.
      - oauth2_refresh_token (string): OAuth2 refresh token or empty if OAuth2 is not allowed.
    '''
    @property
    def fields(self):
        return ['client_secret', 'oauth1_token', 'oauth1_token_secret', 'oauth2_token',
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
    def fields(self):
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
    def fields(self):
        '''
        List of relevant fields.

        :rtype: List of fields.
        '''
        return ['rule_id', 'rule_name', 'meta', 'action', 'hash_algorithm', 'layer',
                'include_dos_protection', 'custom_bpf', 'protocol', 'start_port',
                'end_port', 'src_cidr', 'dst_cidr']


class SecurityGroupSummary(CSKAType):
    '''
    Core details of a security group.  This type or the core SecurityGroup type can be
    used when updating the security gorups that a device belongs to.

    SecurityGroupSummary contains the following fields:
      - group_id (int): Internal Id representing the security group.
      - group_name (string): Name of the security group.
    '''
    @property
    def fields(self):
        return ['group_id', 'group_name']


