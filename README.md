# ubank

Access [ubank](https://www.ubank.com.au)'s API with Python.


## Getting started

Install [uv](https://docs.astral.sh/uv/):

```shell
curl -LsSf https://astral.sh/uv/install.sh | sh
```

Register a new passkey with ubank:

```console
$ uvx --from git+https://github.com/eidorb/ubank ubank name@domain.com --output passkey.cbor
Enter ubank password:
Enter security code sent to 04xxxxx789: 123456
```

The above writes a new passkey to `passkey.cbor`.
You'll be prompted for your ubank username and SMS security code.

> [!CAUTION]
> Your passkey grants access to your bank account.
> It is **your** responsibility to keep it safe!

Create a script named `balances.py`:

```python
# /// script
# requires-python = ">=3.9"
# dependencies = [
#     "ubank",
# ]
#
# [tool.uv.sources]
# ubank = { git = "https://github.com/eidorb/ubank" }
# ///

from ubank import Api, Passkey

# Load passkey from file.
with open("passkey.cbor", "rb") as f:
    passkey = Passkey.load(f)

# Authenticate to ubank with passkey.
with Api(passkey) as api:
    for account in api.get_accounts().linkedBanks[0].accounts:
        print(
            f"{account.label} ({account.type}): {account.balance.available} {account.balance.currency}"
        )
```

Run it with uv:

```console
$ uv run balances.py
Spend account (TRANSACTION): 765.48 AUD
Savings account (SAVINGS): 1577.17 AUD
```


## Contents

- [Getting started](#getting-started)
- [Contents](#contents)
- [CLI help](#cli-help)
- [ubank API](#ubank-api)
- [How to set up a development environment](#how-to-set-up-a-development-environment)
- [How to test](#how-to-test)
- [How to publish a new release](#how-to-publish-a-new-release)
- [Changelog](#changelog)


## CLI help

```console
$ uvx ubank --help
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


## ubank API

`ubank.Api` provides a number of methods for accessing ubank's API:

```python
from datetime import date

from ubank import Api, Passkey, TransactionsSearchBody

with open("passkey.cbor", "rb") as f:
    passkey = Passkey.load(f)

with Api(passkey) as api:
    api.post_accounts_transactions_search(
        body=TransactionsSearchBody(fromDate=date(2025, 1, 1), toDate=date(2025, 2, 1))
    )
    bank = api.get_accounts().linkedBanks[0]
    api.get_account_transactions(
        account_id=bank.accounts[0].id,
        bank_id=bank.bankId,
        customerId=api.get_customer_details().customerId,
    )
    api.get_cards()
    api.get_contacts()
```


## How to set up a development environment

Clone this repository:

```shell
git clone git@github.com:eidorb/ubank.git
cd ubank
```

uv ensures Python dependencies compatible with those defined in [`pyproject.toml`](pyproject.toml)
are automatically installed:

```console
$ uv run python -c 'import ubank; print(ubank.__version__)'
Using CPython 3.13.2 interpreter at: /opt/homebrew/opt/python@3.13/bin/python3.13
Creating virtual environment at: .venv
Installed 17 packages in 22ms
2.0.0
```


## How to test

Run all tests:

```shell
uv run pytest -v
```

`test_ubank_client` requires a valid `passkey.cbor` file for testing ubank
authentication.
Skip this test using the following expression:

```shell
uv run pytest -v -k 'not test_ubank_client'
```


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
