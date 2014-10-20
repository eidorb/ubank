# ubank-api

A simple Python wrapper around UBank's HTTP API.

## Requirements

This module requires the [Requests](http://docs.python-requests.org/en/latest/)
Python library.

## API methods

The `UBankAPI` class methods wrap several UBank API methods. After
authenticating, you can retrieve information about accounts, transactions,
billers and payees. If successful, each method returns a `dict` representation
of JSON data returned by the underlying API HTTP request.

### `authenticate(username, password)`

Authenticate with the UBank API using `username` and `password`.

If successful, a `dict` representing the following JSON is returned:

    {
        "status": {
            "message": "Welcome to the API",
            "code": "API-1"
        }
    }

### `accounts()`

Return a brief summary of account data for each account.

If successful, a `dict` representing the following JSON is returned:

    {
        "status": {
            "message": "Success",
            "code": "API-200"
        },
        "accountsResponse": [
            {
                "status": <status>,
                "accountToken": <accountToken>,
                "accountIdDisplay": <accountIdDisplay>,
                "currentBalance": <currentBalance>,
                "type": <type>,
                "availableBalance": <availableBalance>,
                "name": <name>,
                "code": <code>,
                "nickname": <nickname>
            },
            ...
        ]
    }

### `account(account_token)`

Return detailed account information for the given `account_token` (returned
by `accounts()`).

If successful, a `dict` representing the following JSON is returned:

    {
        "status": {
            "message": "Success",
            "code": "API-200"
        },
        "accountDetailsResponse": {
            "productType": <productType>,
            "accountToken": <accountToken>,
            "currentAccount": {
                "interestEarnedInLastTaxYear": <interestEarnedInLastTaxYear>,
                "unclearBalance": <unclearBalance>,
                "netRate": <netRate>,
                "bonusRate": <bonusRate>,
                "availableBalance": <availableBalance>,
                "holdBalance": <holdBalance>,
                "stdRate": <stdRate>,
                "interestEarnedInCurrentTaxYear": <interestEarnedInCurrentTaxYear>
            },
            "apiStructType": <apiStructType>,
            "productCode": <productCode>,
            "productName": <productName>,
            "accountIdDisplay": <accountIdDisplay>,
            "currentBalance": <currentBalance>,
            "nickname": <nickname>
        }
    }

### `transactions(account_token)`

Return up to 100 of the latest transactions for the given `account_token`
(returned by `accounts()`).

If successful, a `dict` representing the following JSON is returned:

    {
        "status": {
            "message": "Success",
            "code": "API-200"
        },
        "transactionsResponse": {
            "totalRecords": <totalRecords>,
            "transactions": [
                {
                    "date": <date>,
                    "narrative": <narrative>,
                    "runningBalance": <runningBalance>,
                    "amount": <amount>,
                    "description": <description>
                },
                ...
            ],
            "accountIdDisplay": <accountIdDisplay>
        }
    }

### `billers()`

Return BPAY biller information.

If successful, a `dict` representing the following JSON is returned:

    {
        "status": {
            "message": "Success",
            "code": "API-200"
        },
        "billersResponse": [
            {
                "billerStatus": <billerStatus>,
                "nickname": <nickname>,
                "billerCode": <billerCode>,
                "crn": <crn>
            },
            ...
        ]
    }

### `payees()`

Return payee information.

If successful, a `dict` representing the following JSON is returned:

    {
        "status": {
            "message": "Success",
            "code": "API-200"
        },
        "payeesResponse": [
            {
                "apiStructType": <apiStructType>,
                "payeeType": <payeeType>,
                "accountType": <accountType>,
                "statementReference": <statementReference>,
                "accountIdDisplay": <accountIdDisplay>,
                "accountName": <accountName>,
                "remitterName": <remitterName>,
                "payeeToken": {
                    "token": <token>
                },
                "nickname": <nickname>
            },
            ...
        ]
    }
