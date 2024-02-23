# ubank

Access [ubank](https://www.ubank.com.au) programatically.

This does not provide true API-like interface, but you can retrieve information
using browser automation.


## Requirements

Python 3.8+ and [Playwright](https://playwright.dev/python/).


## Installation

Install from PyPI:

```console
$ pip install ubank
```

Install version of Firefox required by Playwright:

```console
$ playwright install --with-deps firefox
```


## Getting started

Create an instance of `UbankClient` and log in using a security code:

```python
>>> from ubank import UbankClient
>>> ubank_client = UbankClient()
>>> ubank_client.log_in_with_security_code('name@domain.com', 'SecretPassw0rd')
Enter security code: 123456
```

Then you can get account information:

```python
>>> ubank_client.get_accounts()
{'linkedBanks': [{'bankId': 1, 'shortBankName': 'ubank', 'accounts': [{'label': 'Spend account', 'nickname': 'Spend account', 'type': 'TRANSACTION', 'balance': {'currency': 'AUD', 'current': 1000, 'available': 1000}, 'status': 'Active'}, {'label': 'Save account', 'nickname': 'Save account', 'type': 'SAVINGS', 'balance': {'currency': 'AUD', 'current': 10000, 'available': 10000}, 'status': 'Active'}]}]}
```

After logging in with a security code, you can retrieve a trusted cookie:

```python
>>> ubank_client.get_trusted_cookie()
{'name': '026d9560-3c86-4680-b926-44bdd28eba94', 'value': 'YmxhaCBibGFoIGJsYWggYmxhaCBibGFoIGJsYWggYmxhaCBibGFo', 'domain': 'www.ubank.com.au', 'path': '/', 'expires': 1706758407, 'httpOnly': True, 'secure': True, 'sameSite': 'Strict'}
```

Use the cookie to log in without a security code:

```python
>>> ubank_client.log_in_with_trusted_cookie(
...     'name@domain.com',
...     'SecretPassw0rd',
...     {'name': '026d9560-3c86-4680-b926-44bdd28eba94', 'value': 'YmxhaCBibGFoIGJsYWggYmxhaCBibGFoIGJsYWggYmxhaCBibGFo', 'domain': 'www.ubank.com.au', 'path': '/', 'expires': 1706758407, 'httpOnly': True, 'secure': True, 'sameSite': 'Strict'}
... )
```

Stop Playwright gracefully when you're done:

```python
>>> ubank_client.stop()
```

You can also retrieve a trusted cookie by running the ubank module from the command
line. Use an environment variable to avoid storing your banking password in shell
history:

```console
$ read -s PASSWORD
SecretPassw0rd
```

Running ubank as a module will prompt for a security code and then display the trusted
cookie object:

```console
$ python -m ubank name@domain.com "$PASSWORD"
Enter security code: 123456
{'name': '026d9560-3c86-4680-b926-44bdd28eba94', 'value': 'YmxhaCBibGFoIGJsYWggYmxhaCBibGFoIGJsYWggYmxhaCBibGFo', 'domain': 'www.ubank.com.au', 'path': '/', 'expires': 1706758407, 'httpOnly': True, 'secure': True, 'sameSite': 'Strict'}
```

Secure storage of your username, password and trusted cookie is **your**
responsibility.


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
