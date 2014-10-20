import json

import requests


BASE_API_URL = 'https://api.nab.com.au/'


class UBankAPI(object):

    """This class provides a wrapper around the UBank HTTP API.

    Call `authenticate` before calling other methods. All methods return a dict
    representation of JSON data returned by the UBank API.
    """

    def __init__(self):
        self.session = requests.Session()

    def authenticate(self, username, password):
        """Authenticate with the UBank API.

        Return a dict with the API welcome message if authentication was
        successful.
        """
        url = '{}init/auth'.format(BASE_API_URL)
        params = {'v': '2'}
        headers = {'content-type': 'application/json'}
        data = {
            'loginRequest': {
                'appId': '73189799-4b8e-4215-b6aa-5e39e89bf490:34c92e53-975a-'
                         '4bfb-9221-c2f8ab449941',
                'brand': 'ubank',
                'credentials': {
                    'C1': {'password': password, 'username': username},
                    'C2': {'deviceRegId': '', 'passcode': ''},
                    'C3': {'deviceRegId': '', 'password': ''},
                    'apiStructType': 'C1'
                },
                'lob': 'ubank'
            }
        }
        json_response = self.session.post(
            url, data=json.dumps(data), headers=headers, params=params).json()
        if json_response['status']['code'] == 'API-1':
            return json_response

    def accounts(self):
        """Return a dict containing a summary of accounts."""
        url = '{}banking/ubank/accounts'.format(BASE_API_URL)
        params = {'v': '4'}
        json_response = self.session.get(url, params=params).json()
        if json_response['status']['code'] == 'API-200':
            return json_response

    def account(self, account_token):
        """Return a dict containing detailed account information for the given
        account token.
        """
        url = '{}banking/ubank/account/{}'.format(BASE_API_URL, account_token)
        params = {'v': '2'}
        json_response = self.session.get(url, params=params).json()
        if json_response['status']['code'] == 'API-200':
            return json_response

    def transactions(self, account_token):
        """Return a dict containing transaction data.

        Up to 100 of the last transactions are included.
        """
        url = '{}banking/ubank/account/{}/transactions/past'.format(
            BASE_API_URL, account_token)
        params = {'v': '2'}
        json_response = self.session.get(url, params=params).json()
        if json_response['status']['code'] == 'API-200':
            return json_response

    def billers(self):
        """Return a dict containing biller (BPAY) information."""
        url = '{}banking/ubank/billers'.format(BASE_API_URL)
        params = {'v': '2'}
        json_response = self.session.get(url, params=params).json()
        if json_response['status']['code'] == 'API-200':
            return json_response

    def payees(self):
        """Return a dict containing payee information."""
        url = '{}banking/ubank/payees'.format(BASE_API_URL)
        params = {'v': '2'}
        json_response = self.session.get(url, params=params).json()
        if json_response['status']['code'] == 'API-200':
            return json_response

    def log_out(self):
        """Log out of the UBank API.

        Return a dict with the log out response.
        """
        url = '{}init/auth'.format(BASE_API_URL)
        params = {'v': '1'}
        json_response = self.session.delete(url, params=params).json()
        if json_response['status']['code'] == 'API-200':
            return json_response
