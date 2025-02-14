# ubank

Access [ubank](https://www.ubank.com.au)'s API with Python.


## Contents

- [Contents](#contents)
- [Getting started](#getting-started)
- [ubank API](#ubank-api)
- [CLI help](#cli-help)
- [Testing](#testing)
- [How to publish a new release](#how-to-publish-a-new-release)
- [Changelog](#changelog)


## Getting started

Install the `ubank` package (Python 3.9+ required):

```console
$ pip install ubank
```

Register a new passkey with ubank:

```console
$ python -m ubank name@domain.com --output passkey.cbor
Enter ubank password:
Enter security code sent to 04xxxxx789: 123456
```

The above writes a new passkey to `passkey.cbor`.
You'll be prompted for your ubank username and SMS security code.

> [!CAUTION]
> Your passkey grants access to your bank account.
> It is **your** responsibility to keep it safe!

Use your passkey to access ubank's API in a Python script:

```python
from ubank import Client, Passkey

# Load passkey from file.
with open("passkey.cbor", "rb") as f:
    passkey = Passkey.load(f)

# Authenticate to ubank with passkey and print account balances.
with Client(passkey) as client:
    print("Account balances")
    for account in client.get("/app/v1/accounts").json()["linkedBanks"][0]["accounts"]:
        print(
            f"{account['label']} ({account['type']}): {account['balance']['available']} {account['balance']['currency']}"
        )
```

Resulting in the following output:

```
Account balances
Spend account (TRANSACTION): 765.48 AUD
Savings account (SAVINGS): 1577.17 AUD
```

Passkeys increment an internal counter with each authentication attempt.
`ubank.Client` automatically writes the updated passkey object to the passkey file after successful authentication.


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

Run tests locally:

```python
$ uv run pytest -v
```

`test_ubank_client` requires a valid `passkey.cbor` file for testing ubank
authentication.
Skip this test using the following expression:

```python
$ uv run pytest -v -k 'not test_ubank_client'
```

A GitHub Actions [workflow](.github/workflows/workflow.yml) runs tests across a number of Python versions.


## How to publish a new release

Bump project version with [hatch](https://hatch.pypa.io/latest/version/):

```console
$ uvx hatch version release
Old: 2.0.0rc2
New: 2.0.0
```

Update `test_version` test.

Create version tag and push to GitHub:

```console
$ git tag "v$(uvx hatch version)"
$ git push origin "v$(uvx hatch version)"
Total 0 (delta 0), reused 0 (delta 0), pack-reused 0
To github.com:eidorb/ubank.git
 * [new tag]         v2.0.0 -> v2.0.0
```

Open new release form for tag:

```shell
open "https://github.com/eidorb/ubank/releases/new?tag=v$(uvx hatch version)"
```

Publishing a release triggers this [workflow](.github/workflows/workflow.yml)
which builds and publishes the package to [PyPI](https://pypi.org/project/ubank/).


## Changelog

### 2.0.0

- Implement passkey registration and authentication (fixes [#6](https://github.com/eidorb/ubank/issues/6)).
- Automate releases.
- Support Python 3.9+.
- Migrate from Poetry to uv.


### 1.1.0

- Set `x-api-version` to fix [#4](https://github.com/eidorb/ubank/issues/4) (thanks [@jakepronger](https://github.com/jakepronger)!)


### 1.0.0

- Drop Playwright requirement.
- Re-implement with simpler and lightweight [httpx](https://www.python-httpx.org) libary.
- Easier access to full ubank API.


### 0.1.2

- Automate ubank access using [Playwright](https://playwright.dev) headless browser.
