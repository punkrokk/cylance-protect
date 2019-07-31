"""Cylance Protect ST2 Integration

The :class:`CylanceProtectClient` class provides a wrapper around the Cylance Protect API

Examples:

    Constructing a :class:`cylance` object takes a cylance tenant ID, an application ID, and application secret. These
    can be acquired on the cylance web application. A username and password is required to access the web application::

        # Initialization
        cylance = CylanceProtectClient(<tenant_id>, <application_id>, <application_secret>)

    Fetch cylance global list - GlobalQuarantine or GlobalSafe::

        # Quarantine
        response = CylanceProtectClient.get_global_list_v2('GlobalQuarantine')

        # GlobalSafe
        response = CylanceProtectClient.get_global_list('GlobalSafe')

    Delete an entry from a global list (GlobalQuarantine or GlobalSafe)::

        response = CylanceProtectClient.remove_hash_from_list(<hash_value>, <global_list>)

    Add an entry to a global list (GlobalQuarantine or GlobalSafe) with category(if GlobalSafe) and reason::

        response = CylanceProtectClient.add_hash_to_list(<entry_list>, <list_type>, <category>, <reason>)

    Query for threats::

        response = CylanceProtectClient.get_threats()

    Get details for a threat with a file hash::

        response = CylanceProtectClient.get_threat(<hash_value>)

    Update a device policy with a device name and policy name::

        response = CylanceProtectClient.update_device_policy(<device_name>, <policy_name>)

    Get device details with a device name::

        response = CylanceProtectClient.get_device(<device_name>)
"""

import jwt
import uuid
import requests
import os
import json
import requests

from datetime import datetime, timedelta

from syncurity_utils import typecheck


class CylanceProtectClient(object):
    """Construct a new connection to the Cylance Protect API - retrieve a JWT given correct tenant name, application ID,
    and application secret

    Args:
        tenant_value (str): The Cylance application's tenant value
        app_id (str): The Cylance application's application id
        app_secret (str): The Cylance application's application secret
        irflow_config_args (dict): Key, Value pairs of IR-Flow configuration arguments
        irflow_config_file (str): A path to a valid ``irflow_api.conf`` file

    Attributes:
        self.base_url (str): The base url for the Cylance API
        self.endpoints (dict): A dictionary of RESTFul endpoints
        self.session (session): Session object with JWT token and headers

    Raises:
        IOError: On a failure to open a config file
        KeyError: On failure to parse config file
        ValueError: On inability to get a valid auth token
        TypeError: This function is typechecked using the :mod:`irflow_integrations.typecheck` module
    """
    @typecheck(str, str, str)
    def __init__(self, tenant_value, app_id, app_secret):

        self.tenant_value = tenant_value
        self.app_id = app_id
        self.app_secret = app_secret
        self.base_url = "https://protectapi.cylance.com"

        self.session = requests.Session()

        self.endpoints = {
            'auth': '/auth/v2/token',
            'global_lists': '/globallists/v2',
            'devices': '/devices/v2',
            'policies': '/policies/v2',
            'threats': '/threats/v2',
            'zones': '/zones/v2',
            'threat_devices': '/threats/v2/{0}/devices?page=1&page_size=n',
            'threat_url': '/threats/v2/download?hash={0}',
            'detections': '/detections/v2',
        }

        self.session.token = self.get_jwt_token()

        if self.session.token is None:
            raise ValueError('Unable to get a valid token from cylance')

        self.session.headers = {"Content-Type": "application/json; charset=utf-8",
                                "Authorization": "Bearer {}".format(self.session.token)}

    @typecheck(str, dict, str)
    def _send_request(self, url, params=None, method='get'):
        """Request Handler for cylance API operations

        Args:
            url (str): Target endpoint for the request
            params (dict): A dictionary of query or parameter values for the request
            method (str): Request method: get, post, or patch are accepted

        Returns:
            Response: Response object returned from the request, ``None`` given a connection error or non-200 status
            code
         """
        timeout = (5, 30)

        try:
            if method == 'get':
                response = self.session.get(url, params=params, timeout=timeout)
            elif method == 'post':
                response = self.session.post(url, json=params, timeout=timeout)
            elif method == 'patch':
                response = self.session.patch(url, json=params, timeout=timeout)
            elif method == 'put':
                response = self.session.put(url, json=params, timeout=timeout)
            elif method == 'delete':
                response = self.session.delete(url, json=params, timeout=timeout)
            else:
                return False, 'Please enter a value request method: get, post, or patch.'

        except requests.exceptions.ConnectionError:
            return False, 'Connection Error triggered while attempting to connect with cylance at: ' + self.base_url + \
                         '. Please ensure that your connection to the internet is stable and that your firewall and ' \
                         'router are not interfering'
        except Exception as e:
            return False, e.__repr__()

        # If the status code is bad, then session authentication failed
        try:
            response.raise_for_status()
        except requests.HTTPError as e:
            return False, e.__str__()

        return True, response

    def get_jwt_token(self):
        """
        Function to retrieve cylance JWT token. This has been adapted from the V2 cylance User API guide

        Returns:
            dict: The JSON response from the API containing the JWT token, or ``None`` if the token was not acquired
        """

        # 30 minutes from now
        timeout = 1800
        now = datetime.utcnow()
        timeout_datetime = now + timedelta(seconds=timeout)
        epoch_time = int((now - datetime(1970, 1, 1)).total_seconds())
        epoch_timeout = int((timeout_datetime - datetime(1970, 1, 1)).total_seconds())
        jti_val = str(uuid.uuid4())

        auth_url = self.base_url + self.endpoints['auth']

        claims = {
            "exp": epoch_timeout,
            "iat": epoch_time,
            "iss": "http://cylance.com",
            "sub": self.app_id,
            "tid": self.tenant_value,
            "jti": jti_val
        }
        encoded = jwt.encode(claims, self.app_secret, algorithm='HS256')
        encoded = encoded.decode("utf-8")
        payload = {"auth_token": encoded}

        # send the request
        response = self._send_request(auth_url, params=payload, method='post')

        if response[0]:
            response_dict = json.loads(response[1].content)
            return response_dict['access_token']

        return None

    @typecheck(str)
    def get_global_list(self, list_type):
        """Get cylance Global GlobalSafe or GlobalQuarantine List

        Args:
            list_type (str): 'GlobalQuarantine' or 'GlobalSafe'

        Raises:
            TypeError: This function is typechecked using the :mod:`irflow_integrations.typecheck` module

        Returns:
            Response: Response object returned from the request, ``None`` given a connection error or non-200 status
            code
        """
        list_value = '1' if list_type == 'GlobalSafe' else '0'

        url = self.base_url + self.endpoints['global_lists'] + '?listTypeId=' + list_value + '&page=1&page_size=10'

        return self._send_request(url)

    @typecheck(str, str, int, int)
    def get_detections(self, start_time, severity='', page_number=1, page_size=10):
        """Get cylance Detections

        Args:
            start_time (str): The start date-time of the query range
            severity (str): Severity value, acceptable values are: Informational, Low, Medium, High
            page_number (int): Page number to access
            page_size (int): Number of detections on the page returned

        Returns:
            Response: Response object returned from the request, ``None`` given a connection error or non-200 status
            code
        """

        url = self.base_url + self.endpoints['detections']

        params = {
            'page': str(page_number),
            'page_size': str(page_size),
            'sort': 'OccurrenceTime',
            'start': start_time,
        }

        if severity:
            params.update({'severity': severity})

        return self._send_request(url, params=params, method='get')

    def get_devices(self):
        """Get cylance Device List

        Returns:
            Response: Response object returned from the request, ``None`` given a connection error or non-200 status
            code
        """

        url = self.base_url + self.endpoints['devices'] + '?page=1&page_size=10'

        return self._send_request(url)

    @typecheck(str)
    def get_device(self, device_name):
        """Get cylance device info given its device name

        Args:
            device_name (str): Name of the device

        Raises:
            TypeError: This function is typechecked using the :mod:`irflow_integrations.typecheck` module

        Returns:
            Response: Response object returned from the request, ``None`` given a connection error or non-200 status
            code
        """
        device_id = self._get_device_id(device_name)

        if not device_id:
            logger.info('Could not find a device ID for the given name')
            return None

        url = self.base_url + self.endpoints['devices'] + '/' + device_id

        return self._send_request(url)

    @typecheck(str)
    def _get_device_id(self, device_name):
        """Get an ID given a device's name

        Raises:
            TypeError: This function is typechecked using the :mod:`irflow_integrations.typecheck` module

        Returns:
            str: The given device's ID if found, ``None`` otherwise
        """

        device_list = self.get_devices()
        if device_list:
            device_list = json.loads(device_list.content)

            device_id = None
            for device in device_list['page_items']:
                if device['name'] == device_name:
                    device_id = device['id']
            return device_id

        return None

    @typecheck(str)
    def _get_zone_id(self, zone_name):
        """Get an ID given a zone's name

        Raises:
            TypeError: This function is typechecked using the :mod:`irflow_integrations.typecheck` module

        Returns:
            str: The given zone's ID, ``None`` otherwise
        """

        zone_list = self.get_zones()
        if zone_list:
            zone_id = None
            for zone in zone_list['page_items']:
                if zone['name'] == zone_name:
                    zone_id = zone['id']

            return zone_id

        return None

    def get_zones(self):
        """Get cylance Zone List

        Returns:
            Response: Response object returned from the request, ``None`` given a connection error or non-200 status
            code
        """

        url = self.base_url + self.endpoints['zones'] + '?page=1&page_size=10'

        return self._send_request(url)

    def get_policies(self):
        """Get cylance Policy List

        Returns:
            Response: Response object returned from the request, ``None`` given a connection error or non-200 status
            code
        """

        url = self.base_url + self.endpoints['policies'] + '?page=1&page_size=10'

        return self._send_request(url)

    @typecheck(str)
    def _get_policy_id(self, policy_name):
        """Get an ID given a policy's name

        Raises:
            TypeError: This function is typechecked using the :mod:`irflow_integrations.typecheck` module

        Returns:
            str: The given policy's ID, ``None`` otherwise
        """

        policy_list = self.get_policies()
        if policy_list:
            policy_list = json.loads(policy_list.content)

            policy_id = None
            for policy in policy_list['page_items']:
                if policy['name'] == policy_name:
                    policy_id = policy['id']

            return policy_id

        return None

    @typecheck(str)
    def get_threat(self, sha256):
        """Get cylance threat info given its hash value

        Args:
            sha256 (str): Hash value of the threat

        Raises:
            TypeError: This function is typechecked using the :mod:`irflow_integrations.typecheck` module

        Returns:
            Response: Response object returned from the request, ``None`` given a connection error or non-200 status
            code
        """

        url = self.base_url + self.endpoints['threats'] + '/' + sha256

        return self._send_request(url)

    @typecheck(str)
    def get_threat_url(self, sha256):
        """Get cylance threat URL given its hash value

        Args:
            sha256 (str): Hash value of the threat

        Raises:
            TypeError: This function is typechecked using the :mod:`irflow_integrations.typecheck` module

        Returns:
            Response: Response object returned from the request, ``None`` given a connection error or non-200 status
            code
        """

        url = self.base_url + self.endpoints['threat_url'].format(sha256)

        return self._send_request(url)

    @typecheck(int,int)
    def get_threats(self, page=1, page_size=10):
        """Get cylance Threat List

        Returns:
            Response: Response object returned from the request, ``None`` given a connection error or non-200 status
            code
        """

        url = self.base_url + self.endpoints['threats'] + '?page=' + str(page) + '&page_size=' + str(page_size)

        return self._send_request(url)

    def get_threat_devices(self, sha256):
        """Get threat details for a specific threat

        Returns:
            Response: Response object returned from the request, ``None`` given a connection error or non-200 status
            code
        """

        url = self.base_url + self.endpoints['threat_devices'].format(sha256)

        return self._send_request(url)

    @typecheck(str, str)
    def add_hash_to_list(self, sha256, list_type, category='Security Software', reason=None):
        """
        Update / Add hashes to a containment list

        Args:
            list_type (str): 'GlobalQuarantine' or 'GlobalSafe'
            sha256 (str): SHA256 string to add to the GlobalQuarantine or GlobalSafe
            category (str): Optional. Valid for Safe list only. Values can be: Admin Tool, Commercial Software, Drivers,
                                Internal Application, Operating System, Security Software, None
            reason (str): Optional. Reason to attach to the hash for cylance

        Raises:
            TypeError: This function is typechecked using the :mod:`irflow_integrations.typecheck` module

        Returns:
            Response: Response object returned from the request, ``None`` given a connection error or non-200 status
            code
        """

        if list_type != 'GlobalSafe' and list_type != 'GlobalQuarantine':
            logger.error('Valid list types are \'GlobalQuarantine\' and \'GlobalSafe\'')
            return None

        url = self.base_url + self.endpoints['global_lists']

        # construct the payload object
        data = {
            'sha256': sha256,
            'category': category,
            'list_type': list_type,
            'reason': reason if reason is not None else 'Added via IR-Flow'
        }

        return self._send_request(url, params=data, method='post')

    @typecheck(str, str)
    def remove_hash_from_list(self, sha256, list_type):
        """
        Remove a hash value from a containment list

        Args:
            sha256 (str): SHA256 string to remove to the Quarantine or Global Safe
            list_type (str): 'GlobalQuarantine' or 'GlobalSafe'

        Raises:
            TypeError: This function is typechecked using the :mod:`irflow_integrations.typecheck` module

        Returns:
            Response: Response object returned from the request, ``None`` given a connection error or non-200 status
            code
        """

        if list_type != 'GlobalSafe' and list_type != 'GlobalQuarantine':
            logger.error('Valid list types are \'GlobalQuarantine\' and \'GlobalSafe\'')
            return None

        url = self.base_url + self.endpoints['global_lists']

        # construct the payload object
        data = {
            'sha256': sha256,
            'list_type': list_type,
        }

        return self._send_request(url, params=data, method='delete')

    @typecheck(str, str)
    def update_device_policy(self, device_name, policy_name, zone_name=None):
        """
        Update a device's policy given a device name and policy name; zone_name has been included
        but it not deemed necessary at this time, but may be useful for future implementation

        Args:
            device_name (str): Selected device, ID will be fetched given this name
            policy_name (str): Policy to update on the device, ID will be fetched given this name
            zone_name (str): Zone to update, ID will be fetched given this name

        Raises:
            TypeError: This function is typechecked using the :mod:`irflow_integrations.typecheck` module

        Returns:
            Response: Response object returned from the request, ``None`` given a connection error or non-200 status
            code
        """

        device_id = self._get_device_id(device_name)

        if not device_id:
            logger.error('Could not find a device ID for the given name')
            return None

        policy_id = self._get_policy_id(policy_name)

        if not policy_id:
            logger.error('Could not find a policy ID for the given policy name')
            return None

        # construct the payload object
        data = {
            'name': device_name,
            'policy_id': policy_id,
        }

        if zone_name:
            zone_id = self._get_zone_id(zone_name)

            if not zone_id:
                logger.error('Could not find a zone ID for the given zone name')
                return None

            data['add_zone_ids'] = [zone_id]

        url = self.base_url + self.endpoints['devices'] + '/' + device_id

        return self._send_request(url, params=data, method='put')

    @typecheck(dict, str)
    def create_irflow_alert(self, fact_group, description):
        """Creates an IR-Flow alert based on the provided fact group and description
        Args:
            fact_group (dict): The alert fact group to upload to IR-Flow
            description (str): Description to set for created alerts
        Raises:
            TypeError: This function is typechecked using the :mod:`irflow_integrations.typecheck` module
        Returns:
            dict: The full response from IR-Flow if successful, ``None`` otherwise
        """
        response = self.irfc.create_alert(fact_group, description, incoming_field_group_name='cylance Detected Threat')

        if response is None:
            return None

        if 'errorCode' in response and response['errorCode'] is not None:
            logger.error('Got Error {0} from IR-Flow'.format(str(response['errorCode'])))
            return None
        elif 'errors' in response['data'] and len(response['data']['errors']) != 0:
            logger.warning('Submission to IR-Flow returned success, but with errors')
            for error in response['data']['errors']:
                logger.error(error['messages'])

        logger.debug(response['message'])

        return response
