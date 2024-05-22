import argparse
import base64
import json
import logging
import secrets
import uuid
from dataclasses import asdict, dataclass
from getpass import getpass

import httpx

# Unchanging headers in every request.
base_headers = {
    "Origin": "ionic://bank86400",
    "x-private-api-key": "ANZf5WgzmVLmTUwAQyuCq7LspXF2pd4N",
}


@dataclass
class Device:
    """Represents an enrolled ubank device."""

    hardware_id: str
    device_id: str
    device_meta: str
    hashed_pin: str
    secret: str
    auth_key: str
    email: str
    mobile_number: str
    user_id: str
    username: str
    token: str

    def dumps(self) -> str:
        """Returns JSON string representation of self."""
        return json.dumps(asdict(self), indent=2)


class Client(httpx.Client):
    """ubank API client based on httpx.Client.

    Initialise `Client` with a `Device` (see [`enrol_device()`](enrol_device)).
    It's recommended to use this class as a context manager. This ensures ubank
    sessions and HTTP connections are properly cleaned when leaving the `with` block:
    ```python
    with ubank.Client(device) as client:
        ...
    ```

    Important! You **must** store the instance's `.device` attribute after
    instantiation. Otherwise the stored device credentials will be expired and you'll
    need to re-enrol.

    Instantiating `ubank.Client` refreshes the `auth_key` and long life `token`,
    held in the `.device` attribute.

    `base_url` is set to https://api.ubank.com.au/, so only the API path is required
    when making requests:
    ```python
    client.get("/app/v1/accounts/summary")
    ```
    """

    def __init__(self, device: Device) -> None:
        """Initialises ubank session using device credentials.

        Initialisation sets `self.device` containing an updated auth key and token.
        Be sure to save the updated device!

        :param device: A `Device` enrolled with ubank
        """
        with httpx.Client(
            headers={
                **base_headers,
                "x-hardware-id": device.hardware_id,
                "x-device-id": device.device_id,
                "x-device-meta": device.device_meta,
            },
        ) as client:
            # Authenticate with long life token.
            response = client.post(
                "https://api.ubank.com.au/app/v1/long-life-token/login",
                json={
                    "authKey": device.auth_key,
                    "deviceUuid": device.device_id,
                    "secret": device.secret,
                    "token": device.token,
                    "username": device.username,
                },
            )
            # Set access and auth token headers for future requests.
            self.access_token = client.headers["x-access-token"] = client.headers[
                "x-auth-token"
            ] = response.json()["accessToken"]
            # Store other tokens in order to kill session in future.
            self.refresh_token = response.json()["refreshToken"]
            self.session_token = response.json()["sessionToken"]
            # Update device's auth key.
            device.auth_key = response.json()["authKey"]

            # Associate session with new auth key.
            client.patch(
                url="https://api.ubank.com.au/app/v1/sessions",
                # Auth key UUID comes from previous response.
                json={"authKeyUuid": response.json()["authKeyUuid"]},
            )

            # Refresh long life token.
            response = client.post(
                "https://api.ubank.com.au/app/v1/long-life-token/refresh",
                json={"token": device.token},
            )
            # Update device token.
            device.token = response.json()["token"]

        # Maintain reference to updated device on this instance.
        self.device = device

        # Initialise new httpx.Client, keeping headers and cookies from client.
        super().__init__(
            headers=client.headers,
            cookies=client.cookies,
            base_url="https://api.ubank.com.au/",
        )

    def _delete_session(self) -> None:
        """Kills ubank session."""
        self.request(
            "DELETE",
            "/app/v1/sessions",
            json={
                "accessToken": self.access_token,
                "refreshToken": self.refresh_token,
                "sessionToken": self.session_token,
            },
        )

    def close(self) -> None:
        """Kills ubank session before closing."""
        self._delete_session()
        super().close()

    def __exit__(self, exc_type, exc_value, traceback) -> None:
        """Kills ubank session before exiting the context."""
        self._delete_session()
        super().__exit__(exc_type, exc_value, traceback)


def enrol_device(
    username: str, password: str, app_version="11.21.1", device_name="iPhone16-1"
) -> Device:
    """Enrols new device with ubank.

    You are responsible for securely storing the enrolled device's information returned
    by this function.

    :param username: ubank username
    :param password: ubank password
    :param app_version: Set ubank application version identifier. See versions here:
        https://apps.apple.com/au/app/id1449543099.
    :param device_name: Set device identifier. See "Hardware strings" row in this
        table: https://en.wikipedia.org/wiki/List_of_iPhone_models. Replace comma
        with hyphen.
    :return: Enrolled device credentials
    """
    # Generate a fresh hardware ID.
    hardware_id = str(uuid.uuid4())
    # Start with an empty device ID. ubank will assign one later.
    device_id = ""
    # Build device meta string from app version and device name.
    device_meta = json.dumps(
        {
            "appVersion": app_version,
            "binaryVersion": app_version,
            "deviceName": device_name,
            "environment": "production",
            "instance": "live",
            "native": True,
            "platform": "ios",
        }
    )

    with httpx.Client(
        headers={
            **base_headers,
            "x-hardware-id": hardware_id,
            "x-device-id": device_id,
            "x-device-meta": device_meta,
        }
    ) as client:
        # Start enrolment by identifying ourselves.
        response = client.post(
            url="https://api.ubank.com.au/app/v1/welcome",
            json={"identity": username},
        )

        # Next, authenticate with password.
        response = client.post(
            url="https://api.ubank.com.au/app/v1/challenge/password",
            json={"deviceName": device_name, "password": password},
            # Set access and auth token headers from previous response.
            headers={
                "x-access-token": response.json()["accessToken"],
                "x-auth-token": response.json()["accessToken"],
            },
        )
        # Set device ID assigned by ubank.
        device_id = client.headers["x-device-id"] = response.json()["deviceId"]

        # Generate a "hashed PIN", a random Base64 string.
        hashed_pin = base64.standard_b64encode(secrets.token_bytes(66)).decode("utf-8")

        # Authenticate with second factor: a security code sent to mobile.
        otp_response = client.post(
            url="https://api.ubank.com.au/app/v1/challenge/otp",
            # Set parameters returned in previous response.
            params={
                "nonce": response.json()["nonce"],
                "state": response.json()["state"],
                "session": response.json()["session"],
            },
            json={
                "deviceId": device_id,
                "hashedPin": hashed_pin,
                # Prompt interactively for security code.
                "otpValue": input(
                    f'Enter security code sent to {response.json()["maskedMobileNumber"]}: '
                ),
            },
            # Set access and auth token headers from previous response.
            headers={
                "x-access-token": response.json()["accessToken"],
                "x-auth-token": response.json()["accessToken"],
            },
        )
        # Set access and auth token headers for future requests.
        client.headers["x-access-token"] = client.headers["x-auth-token"] = (
            otp_response.json()["accessToken"]
        )

        # Generate a secret.
        secret = str(uuid.uuid4())

        # Obtain a long life token. This is used to authenticate in the future.
        response = client.post(
            url="https://api.ubank.com.au/app/v1/long-life-token/generate",
            json={"hashedPin": hashed_pin, "secret": secret},
        )

        # Clear this session's tokens.
        client.request(
            # Can't use client.delete() because bodies in DELETE requests have no
            # defined semantics.
            method="DELETE",
            url="https://api.ubank.com.au/app/v1/sessions",
            # Tokens were returned in /challenge/otp response.
            json={
                "accessToken": otp_response.json()["accessToken"],
                "refreshToken": otp_response.json()["refreshToken"],
                "sessionToken": otp_response.json()["sessionToken"],
            },
        )

        # The enrolled device's information is required for future authentication.
        return Device(
            hardware_id=hardware_id,
            device_id=device_id,
            device_meta=device_meta,
            hashed_pin=hashed_pin,
            secret=secret,
            auth_key=otp_response.json()["authKey"],
            email=otp_response.json()["email"],
            mobile_number=otp_response.json()["mobileNumber"],
            user_id=otp_response.json()["userId"],
            username=otp_response.json()["username"],
            token=response.json()["token"],
        )


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Enrols new device with ubank. "
        "You will be asked for your ubank password and secret code interactively.",
    )
    parser.add_argument("username", help="ubank username")
    parser.add_argument(
        "-o",
        "--output",
        default="-",
        type=argparse.FileType(mode="w"),
        help="write JSON device credentials to file (default: write to stdout)",
        dest="file",
    )
    parser.add_argument(
        "-v", "--verbose", action="store_true", help="displays httpx INFO logs"
    )
    args = parser.parse_args()
    if args.verbose:
        # Displays basic httpx request information.
        logging.basicConfig(level=logging.INFO)
    args.file.write(
        enrol_device(args.username, password=getpass("Enter ubank password: ")).dumps()
    )
