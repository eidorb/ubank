# ubank

Access [ubank](https://www.ubank.com.au)'s API with Python.


## Contents

- [Contents](#contents)
- [Getting started](#getting-started)
- [ubank API](#ubank-api)
- [CLI help](#cli-help)
- [Testing](#testing)
- [Release](#release)
- [Changelog](#changelog)


## Getting started

Install the `ubank` package (Python 3.11+ required):

```console
$ pip install ubank
```

Register a new passkey with ubank:

```console
$ python -m ubank name@domain.com --output passkey.pickle
Enter ubank password:
Enter security code sent to 04xxxxx789: 123456
```

The above writes a new passkey to `passkey.pickle`.
You'll be prompted for your ubank username and SMS security code.

> [!CAUTION]
> Your passkey grants access to your bank account.
> It is **your** responsibility to keep it safe!

Use your passkey to access ubank's API in a Python script:

```python
from ubank import Client, Passkey

# Load passkey from file.
with open("passkey.pickle", "rb") as f:
    passkey = Passkey.load(f)

# Authenticate to ubank with passkey and print account balances.
with Client(passkey) as client:
    print("Account balances")
    for account in client.get("/app/v1/accounts").json()["linkedBanks"][0]["accounts"]:
        print(
            f"{account['label']} ({account['type']}): {account['balance']['available']} {account['balance']['currency']}"
        )

# Save updated passkey to file.
with open("passkey.pickle", "wb") as f:
    passkey.dump(f)
```

Resulting in the following output:

```
Account balances
Spend account (TRANSACTION): 765.48 AUD
Savings account (SAVINGS): 1577.17 AUD
```

> [!IMPORTANT]
> Passkeys increment an internal counter with each authentication attempt.
> You must save the updated passkey object which contains the modified counter value.
> Your authentication attempts **will fail** if you do not do this.


## ubank API

`ubank.Client` is an [`httpx.Client`](https://www.python-httpx.org/advanced/clients/)
with a familiar requests-style interface.
Its `base_url` is set to `https://api.ubank.com.au/`, so only the path is required when making API requests.

Here are some API endpoints to try (can you find more?):

```python
with Client(passkey) as client:
    print(client.get("/app/v1/accounts").json())
    print(client.get("/app/v1/accounts/summary").json())
    print(client.get("/app/v1/achievements").json())
    print(client.get("/app/v1/campaigns").json())
    print(client.get("/app/v1/cards").json())
    print(client.get("/app/v1/contacts").json())
    print(client.get("/app/v1/customer-details").json())
    print(client.get("/app/v1/insights").json())
    print(client.get("/app/v1/insights/interest").json())
    print(client.get("/app/v1/products").json())
    print(client.get("/app/v1/promotions").json())
    print(client.get("/app/v1/savings-goals").json())
    print(client.get("/app/v1/tfn").json())
```

`ubank.Client` is intended to be used as a context manager.
This ensures ubank sessions and HTTP connections are ended properly when leaving the `with` block.


## CLI help

```console
$ python -m ubank --help
usage: ubank.py [-h] [-o FILE] [-n PASSKEY_NAME] [-v] username

Registers new passkey with ubank. You will be asked for your ubank password and secret code interactively.

positional arguments:
  username              ubank username

options:
  -h, --help            show this help message and exit
  -o FILE, --output FILE
                        writes plaintext passkey to file (default: write to stdout)
  -n PASSKEY_NAME, --passkey-name PASSKEY_NAME
                        sets passkey name (default: ubank.py)
  -v, --verbose         displays httpx INFO logs
```


## Testing

Pull credentials from AWS:

```bash
aws-vault exec brodie@oasis -- python
Opening the SSO authorization page in your default browser (use Ctrl-C to abort)
https://device.sso.ap-southeast-2.amazonaws.com/?user_code=YMMV-CUMT
```

```python
>>> import json
>>>
>>> import boto3
>>>
>>> import ubank
>>>
>>>
>>> def get_device(parameter_name="/portfolio/ubank-device"):
...     """Returns ubank enrolled device from AWS Parameter Store."""
...     return ubank.Device(
...         **json.loads(
...             # Retrieve JSON string from decrypted parameter value.
...             boto3.client("ssm", region_name="us-east-1").get_parameter(
...                 Name=parameter_name, WithDecryption=True
...             )["Parameter"]["Value"]
...         )
...     )
...
>>>
>>> def save_device(device, parameter_name="/portfolio/ubank-device"):
...     """Saves ubank device credentials to AWS Parameter Store."""
...     return boto3.client("ssm", region_name="us-east-1").put_parameter(
...         Name=parameter_name,
...         Value=device.dumps(),
...         Type="SecureString",
...         Overwrite=True,
...     )
...
>>>
>>> # Get ubank account balances and trusted cookie.
>>> device = get_device()
>>> with ubank.Client(device) as client:
...     # Update stored device credentials.
...     save_device(client.device)
...     for account in client.get("/app/v1/accounts/summary").json()["linkedBanks"][0][
...         "accounts"
...     ]:
...         print(account)
...
{'Version': 77, 'Tier': 'Standard', 'ResponseMetadata': {'RequestId': '1dd6cfff-dead-beef-asdf-123ead7e3ba0', 'HTTPStatusCode': 200, 'HTTPHeaders': {'server': 'Server', 'date': 'Thu, 1 Nov 1970 01:23:45 GMT', 'content-type': 'application/x-amz-json-1.1', 'content-length': '32', 'connection': 'keep-alive', 'x-amzn-requestid': '1dd6cfff-dead-beef-asdf-123ead7e3ba0'}, 'RetryAttempts': 0}}
{'label': 'Spend account', 'type': 'TRANSACTION', 'balance': {'currency': 'AUD', 'current': 1000.00, 'available': 1000.00}, 'status': 'Active', 'id': '9a293f00-c000-45b2-b21e-28cf09453f73', 'nickname': 'USpend', 'number': '00000000', 'bsb': '000000', 'lastBalanceRefresh': '1970-01-01T01:23:45.678Z', 'openDate': '1970-01-01T01:23:45.678Z', 'isJointAccount': False, 'depositProductData': {'interestTiers': [{'interestRate': 0, 'minimumRange': 0}]}}
{'label': 'Save account', 'type': 'SAVINGS', 'balance': {'currency': 'AUD', 'current': 1000000.00, 'available': 1000000.00}, 'status': 'Active', 'id': '88bcd861-21ad-48d9-8c3d-d789c5845252', 'nickname': 'USave', 'number': '00000000', 'bsb': '000000', 'lastBalanceRefresh': '1970-01-01T01:23:45.678Z', 'openDate': '1970-01-01T01:23:45.678Z', 'isJointAccount': False, 'depositProductData': {'interestTiers': [{'interestRate': 5.5, 'minimumRange': 0, 'maximumRange': 100000}, {'interestRate': 5, 'minimumRange': 100000.01, 'maximumRange': 250000}, {'interestRate': 0, 'minimumRange': 250000.01}], 'interestPaymentFrequency': {'interestPaymentCountPerPeriod': 1, 'interestPeriod': '1 Month', 'interestPaymentSchedule': 'End'}}}
>>>
```


## Release

Bump project version. e.g.,

```console
$ poetry version patch
Bumping version from 0.1.1 to 0.1.2
```

Publish to PyPI:

```console
$ read -s PASSWORD
$ poetry publish --build -u __token__ -p "$PASSWORD"
```


## Changelog

### 2.0.0

- Implement passkey registration and authentication.
- Support Python 3.11+.
- Migrate from Poetry to uv.


### 1.1.0

- Set `x-api-version` to fix #4 (thanks [@jakepronger](https://github.com/jakepronger)!)


### 1.0.0

- Drop Playwright requirement.
- Re-implement with simpler and lightweight [httpx](https://www.python-httpx.org) libary.
- Easier access to full ubank API.


### 0.1.2

- Automate ubank access using [Playwright](https://playwright.dev) headless browser.
