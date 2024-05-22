# ubank

Access [ubank](https://www.ubank.com.au)'s API.


## Getting started

Install ubank with pip (Python 3.8+ is required):
```console
$ pip install ubank
```

Before accessing the API, you'll first need to enrol a new device with ubank.
Running ubank as a module helps with this task:
```console
$ python -m ubank --help
usage: ubank.py [-h] [-o FILE] [-v] username

Enrols new device with ubank. You will be asked for your ubank password and secret code interactively.

positional arguments:
  username              ubank username

optional arguments:
  -h, --help            show this help message and exit
  -o FILE, --output FILE
                        write JSON device credentials to file (default: write to stdout)
  -v, --verbose         displays httpx INFO logs
```

We'll enrol a new device and save the credentials to `device.json`.
Keep this file safe!
You'll be prompted for your ubank password and security code during this step.
```console
$  python -m ubank name@domain.com --output device.json
Enter ubank password:
Enter security code sent to 04xxxxx789: 123456
$ cat device.json
{
  "hardware_id": "35bd47b0-eced-4fb4-88e1-24657c2500ec",
  "device_id": "cc1d3291-8e7d-45fc-845b-326b65bffcb1",
  "device_meta": "{\"appVersion\": \"15.11.1\", \"binaryVersion\": \"15.11.1\", \"deviceName\": \"iPhone19-1\", \"environment\": \"production\", \"instance\": \"live\", \"native\": true, \"platform\": \"ios\"}",
  "hashed_pin": "N0ZsiU81f+qiOZvs424E06AasHBlHsSlH9Fj1J0Sz5c=",
  "secret": "c3e59465-2449-4692-8d0a-6dc9bb8b2ae2",
  "auth_key": "pLzKjKs0FW104tqaj5qD3wYmZf0Q+udRCsRgST1gRGwh9iaxVf5qZdn+LtidvqSx20Y=",
  "email": "name@domain.com",
  "mobile_number": "+61423456789",
  "user_id": "51457aec-9fb4-45c4-9ed0-4d17b70665ec",
  "username": "48b16c6f-19a5-46e7-855e-5d6922882276",
  "token": "dw2FYNdTRLgIS8YxZlQ0RnihkpgxRB/+a/o3vmQWWiRtrF11H4ZjA8ywZfaoUYK/Gkc="
}
```


## Accessing ubank's API

You won't use your username and password to access ubank's API.
Instead, you'll use the enrolled device's credentials (stored in `device.json`).

Instantiate a `ubank.Device` from `device.json`:
```python
import ubank

with open("device.json") as file:
    device = ubank.Device(**json.load(file))
```

Next, we'll instantiate `ubank.Client` with the `device` created above.
Use this class as a context manager.
This ensures ubank sessions and HTTP connections are properly cleaned when leaving
the `with` block.

`ubank.Client`'s `base_url` is set to `https://api.ubank.com.au/`, so only the API path is required when making requests.

> [!IMPORTANT]
> You **must** store the instance's `.device` attribute after instantiation.
> Otherwise the stored device credentials will be expired and you'll need to re-enrol.
>
> Instantiating `ubank.Client` refreshes the `auth_key` and long life `token`, held in the `.device` attribute.

```python
with ubank.Client(device) as client:
    with open("device.json", "w") as file:
        file.write(client.device.dumps())
    print(client.get("/app/v1/accounts/summary").json())

{'linkedBanks': [{'bankId': 1, 'shortBankName': 'ubank', 'accounts': [{'label': 'Spend', 'type': 'TRANSACTION', 'balance': {'currency': 'AUD', 'current': 100, 'available': 100}, 'status': 'Active', 'id': '695db516-b0e2-4807-baca-77314a6257ce', 'nickname': 'Spend', 'number': '12345678', 'bsb': '670864', 'lastBalanceRefresh': '2024-01-02T00:00:00.000Z', 'openDate': '2024-01-01T00:00:00.000Z', 'isJointAccount': False}, {'label': 'Save', 'type': 'SAVINGS', 'balance': {'currency': 'AUD', 'current': 1200.44, 'available': 1200.44}, 'status': 'Active', 'id': '5bad6edf-247e-4221-9bfc-e7608f5984cb', 'nickname': 'Save', 'number': '23456789', 'bsb': '670864', 'lastBalanceRefresh': '2024-01-02T00:00:00.000Z', 'openDate': '2024-01-01T00:00:00.000Z', 'isJointAccount': False}]}]}
```


## API endpoints

Here are some API endpoints to try:
```python
with ubank.Client(device) as client:
    with open("device.json", "w") as file:
        file.write(client.device.dumps())
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

### 1.0.0

- Drop Playwright requirement.
- Re-implement with simpler and lightweight [httpx](https://www.python-httpx.org) libary.
- Easier access to full ubank API.


### 0.1.2

- Automate ubank access using [Playwright](https://playwright.dev) headless browser.
