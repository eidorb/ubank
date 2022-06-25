# ubank-api

Implements a [Requests](https://requests.readthedocs.io/) interface for interacting
with UBank's API.


# Getting started

## Authenticate

Authenticate with your username and password:

```python
from ubank import UBankSession

ubank_session = UBankSession("user@domain.com", "password")
```


## API endpoints

Here's a non-exhaustive list of API endpoints you may wish to try.

- [Accounts](#accounts)
- [Account details](#account-details)
- [Transactions](#transactions)
- [Cards](#cards)
- [Payments](#payments)
- [Payees](#payees)


### Accounts

```python
ubank_session.get("/v1/ubank/accounts", params={"include": "homeloan"}).json()
```

```js
{
    "accounts": [
        {
            "accountNumber": "...",
            "accountOpeningDate": "...",
            "availableBalance": "...",
            "bonusRate": "...",
            "currentBalance": "...",
            "entireAccountId": "...",
            "id": "...",
            "isEligibleForBonusRate": true,
            "legacyToken": "...",
            "nickname": "...",
            "ownership": "...",
            "productCode": "...",
            "productName": "...",
            "productType": "...",
            "status": "...",
            "visible": true
        },
        {
            "accountNumber": "...",
            "accountOpeningDate": "...",
            "availableBalance": "...",
            "bonusRate": "...",
            "currentBalance": "...",
            "entireAccountId": "...",
            "id": "...",
            "isEligibleForBonusRate": false,
            "legacyToken": "...",
            "linkedUsaverAccount": {
                "accountNumber": "...",
                "id": "...",
                "legacyToken": "..."
            },
            "nickname": "...",
            "ownership": "...",
            "productCode": "...",
            "productName": "...",
            "productType": "...",
            "status": "...",
            "visible": true
        }
    ]
}
```


### Account details

```python
ubank_session.get("/banking/ubank/account/<legacyToken>", params={"v": "4"}).json()
```

```js
{
    "accountDetailsResponse": {
        "accountIdDisplay": "...",
        "accountToken": "...",
        "apiStructType": "...",
        "currentAccount": {
            "availableBalance": "...",
            "bonusRate": "...",
            "holdBalance": "...",
            "interestEarnedInCurrentMonth": "...",
            "interestEarnedInCurrentTaxYear": "...",
            "interestEarnedInLastTaxYear": "...",
            "interestPaidInCurrentTaxYear": "...",
            "interestPaidInLastTaxYear": "...",
            "lastStatementGenerated": "...",
            "netRate": "...",
            "overdraftLimit": "...",
            "statementsDeliveryType": "...",
            "stdRate": "...",
            "unclearBalance": "..."
        },
        "currentBalance": "...",
        "isKYCConfirmed": true,
        "nickname": "...",
        "openingDate": "...",
        "productCode": "...",
        "productName": "...",
        "productType": "..."
    },
    "status": {
        "code": "API-200",
        "message": "Success"
    }
}
```


### Transactions

```python
ubank_session.get("/v1/ubank/accounts/<id>/transactions", params={"preferredPageSize": "20"}).json()
```

```js
{
    "accountNumber": "...",
    "bsb": "...",
    "next": "...",
    "transactions": [
        {
            "amount": "...",
            "currency": "...",
            "date": "...",
            "description": "...",
            "id": "...",
            "narrative": "...",
            "processingStatus": "...",
            "reference": "...",
            "runningBalance": "...",
            "timestamp": "...",
            "transactionId": "...",
            "transactionTypeCode": "..."
        },
        {
            "amount": "...",
            "categories": [
                {
                    "axisId": 1,
                    "axisLabel": "...",
                    "ubankAssignedCategoryId": 16,
                    "ubankAssignedCategoryLabel": "..."
                }
            ],
            "channel": "...",
            "currency": "...",
            "date": "...",
            "description": "...",
            "externalAccountName": "...",
            "fastPaymentReference": "",
            "id": "...",
            "narrative": "...",
            "processingStatus": "...",
            "reference": "...",
            "runningBalance": "...",
            "timestamp": "...",
            "transactionId": "...",
            "transactionTypeCode": "..."
        },
        {
            "amount": "...",
            "channel": "...",
            "currency": "...",
            "date": "...",
            "description": "...",
            "externalAccountName": "...",
            "fastPaymentReference": "",
            "id": "...",
            "narrative": "...",
            "processingStatus": "...",
            "reference": "...",
            "runningBalance": "...",
            "timestamp": "...",
            "transactionId": "...",
            "transactionTypeCode": "..."
        },
        {
            "amount": "...",
            "anzsicCategory": {
                "classCode": "...",
                "classTitle": "...",
                "divisionCode": "...",
                "divisionTitle": "...",
                "groupCode": "...",
                "groupTitle": "...",
                "subdivisionCode": "...",
                "subdivisionTitle": "..."
            },
            "categories": [
                {
                    "axisId": 1,
                    "axisLabel": "...",
                    "ubankAssignedCategoryId": 24,
                    "ubankAssignedCategoryLabel": "..."
                }
            ],
            "currency": "...",
            "date": "...",
            "description": "...",
            "id": "...",
            "merchantDetails": {
                "businessName": "",
                "phoneNumber": {
                    "international": "",
                    "local": ""
                },
                "website": ""
            },
            "merchantLocation": {
                "country": "",
                "formattedAddress": "",
                "geometry": {
                    "lat": "",
                    "lng": ""
                },
                "postalCode": "",
                "route": "",
                "routeNo": "",
                "state": "",
                "suburb": ""
            },
            "narrative": "...",
            "processingStatus": "...",
            "reference": "...",
            "runningBalance": "...",
            "timestamp": "...",
            "transactionId": "...",
            "transactionTypeCode": "..."
        },
        ...
    ]
}
```


### Cards

```python
ubank_session.get("/banking/ubank/cards/detailed)", params={"v": "6"}).json()
```

```js
{
    "cardsResponse": [
        {
            "cardId": "...",
            "cardNumberDisplay": "...",
            "cardSequenceNumber": "...",
            "cardToken": "...",
            "linkedAccounts": [
                {
                    "accountClass": "...",
                    "accountIdDisplay": "...",
                    "accountToken": "",
                    "attachedAccountType": "...",
                    "blockCode": "...",
                    "capabilities": [
                        "BURTEMPBLOCK",
                        "BURTEMPUNBLOCK",
                        "BURPERMBLOCK",
                        "BURREORDER",
                        "SETPIN",
                        "RESETPIN",
                        "PUSHSUBSCRIPTION",
                        "NABPAY",
                        "WALLET",
                        "CARDSLEDGERADDRESS",
                        "SMARTRECEIPTS"
                    ],
                    "cardholderRelationship": "...",
                    "isCardUsed": true,
                    "isOwned": true,
                    "primaryAccountHolder": false,
                    "scheme": "...",
                    "slot": "..."
                }
            ],
            "nameOnCard": "",
            "plasticType": "...",
            "productClass": "...",
            "productCode": "...",
            "productDescription": "...",
            "productName": "...",
            "productType": "..."
        }
    ],
    "status": {
        "code": "API-200",
        "message": "Success"
    }
}
```


### Payments

```python
ubank_session.get("/banking/ubank/payments/_/_/_/_/_/_/_/_/_/_", params={"v": "7"}).json()
```

```js
{
    "paymentsResponse": {
        "payments": [
            {
                "from": {
                    "account": {
                        "accountApca": {
                            "accountName": "...",
                            "accountNumber": "...",
                            "bsb": "..."
                        },
                        "apiStructType": "..."
                    }
                },
                "method": {
                    "apiStructType": "...",
                    "bill": {
                        "amount": "..."
                    }
                },
                "paymentId": "...",
                "paymentToken": "...",
                "recurrence": {
                    "apiStructType": "...",
                    "onceOff": {
                        "paymentDate": "..."
                    }
                },
                "status": "...",
                "to": {
                    "account": {
                        "apiStructType": "...",
                        "biller": {
                            "code": "...",
                            "crn": "...",
                            "name": "..."
                        }
                    }
                }
            },
            ...
        ],
        "totalRecords": ...
    },
    "status": {
        "code": "API-200",
        "message": "Success"
    }
}
```


### Payees

```python
ubank_session.get("/v1/ubank/payees").json()
```

```js
[
    {
        "billerCode": "...",
        "billerName": "...",
        "crn": "",
        "nickname": "...",
        "payeeId": "...",
        "payeeType": "...",
        "standardBiller": false,
        "version": "..."
    },
    ...
]
```
