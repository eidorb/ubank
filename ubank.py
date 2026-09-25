"""Access ubank's API using Python.

Run as a script to create a new passkey.

There are many clients...:
- Client is a ubank API client (this is what you use)
- meatie_httpx.Client is Client's base class
- HttpClient is a lower-level client that implements passkey authentication
- httpx.Client is HttpClient's base class

Client relies upon an instance of HttpClient to make the actual HTTP requests.
"""

from __future__ import annotations

import argparse
import json
import logging
import re
import time
import uuid
from base64 import b64encode, urlsafe_b64encode
from getpass import getpass
from typing import IO, Annotated, AnyStr, Optional

import httpx
import meatie_httpx
from cryptography.fernet import Fernet
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from fido2 import cbor
from meatie import api_ref, endpoint
from wre_client_akamai import AkamaiClient, AkamaiConfig, RequestInput

from models import (
    Cards,
    Contacts,
    Customer,
    Device,
    Filter,
    LinkedBanks,
    SearchResults,
    TransactionsSummary,
)
from soft_webauthn_patched import SoftWebauthnDevice

__version__ = "2.2.5"

# Referenced in Client and add_passkey() for attestation and assertion.
origin = "www.ubank.com.au"


class Passkey:
    """Represents a passkey registered with ubank."""

    def __init__(self, name: str):
        """name is passkey/device name shown in emails and app."""
        super().__init__()
        self.name = name
        # Generate a fresh hardware ID.
        hardware_id = str(uuid.uuid1())
        # Start with an empty device ID. ubank will assign one later.
        device_id = ""
        # Start with empty username, it will be assigned by ubank later.
        username = ""
        self.name = name
        self.hardware_id = hardware_id
        self.device_id = device_id
        self.username = username
        self.soft_webauthn_device = SoftWebauthnDevice()

    def dump(self, file: IO[bytes], password: str = ""):
        """Serializes passkey to file, encrypted with a password.

        Uses the following as a guide for password encryption: https://cryptography.io/en/latest/fernet/#using-passwords-with-fernet

        This uses a hardcoded salt because I'm not interested in additionally keeping
        track of unique salts. A password alone will have to be good enough!

        AI suggests generating random hardcoded salts, derived from a hash of password.
        But I'm hard coding it to b"". Not sure random hardcoded salts give benefit
        in this case. If someone knows your password, you're popped!

        Not supplying a password encrypts the file using a key derived from an empty string.
        """
        fernet = Fernet(derive_key(password))
        file.write(
            fernet.encrypt(
                cbor.encode(
                    {
                        "name": self.name,
                        "hardware_id": self.hardware_id,
                        "device_id": self.device_id,
                        "username": self.username,
                        "soft_webauthn_device_dict": to_dict(self.soft_webauthn_device),
                    }
                )
            )
        )

    @classmethod
    def load(cls, file: IO[AnyStr], password: str = "") -> Passkey:
        """Deserializes passkey from `file`, decrypted with `password`."""
        fernet = Fernet(derive_key(password))
        deserialized_passkey = cbor.decode(fernet.decrypt(file.read()))
        passkey = Passkey(deserialized_passkey["name"])
        passkey.hardware_id = deserialized_passkey["hardware_id"]
        passkey.device_id = deserialized_passkey["device_id"]
        passkey.username = deserialized_passkey["username"]
        passkey.soft_webauthn_device = from_dict(
            deserialized_passkey["soft_webauthn_device_dict"]
        )
        return passkey


class Client(meatie_httpx.Client):
    """A ubank Meatie client.

    Requests are authenticated with the given passkey.

    Use as a context manager to ensure underlying clients are closed:

        with Client(passkey) as client:
            ...

    If required, you can override `api_version` and `app_version` to change the
    values sent in requests.

    Methods are defined interacting with the following ubank resources:

    - customer details
    - accounts
    - transactions
    - cards
    - contacts
    - authentication devices (includes passkeys)

    API endpoints as implemented as they are, as ugly or weird as they may be. You
    can extend with your own helper methods.

    This Meatie client has a bunch of methods defined... with nothing in them!

    The Meatie library generates code for calling endpoints automatically. It does
    this by inspecting type signatures (among many other things).

    It relies heavily upon [descriptors](https://docs.python.org/3/howto/descriptor.html).
    I've heard of decorators, but not descriptors. Sounds powerful. Worth looking into.
    """

    def __init__(
        self, passkey: Passkey, api_version="37", app_version="2.242.1"
    ) -> None:
        super().__init__(HttpClient(passkey, api_version, app_version))

    @endpoint("/app/v1/customer-details")
    def get_customer_details(self) -> Customer:
        """Returns customer details."""

    @endpoint("/app/v1/accounts")
    def get_linked_banks(
        self, externalRefresh: str = "false", refresh: str = "false", type: str = "all"
    ) -> LinkedBanks:
        """Returns bank account details (including linked external accounts).

        - `externalRefresh` set to 'true' initiates a refresh of linked account data.
        - `type` sets type of accounts returned: 'internal', 'external', or 'all'.
        """

    @endpoint("/app/v1/accounts/{account_id}/bank/{bank_id}/transactions")
    def search_account_transactions(
        self,
        account_id: str,
        bank_id: str,
        customerId: str,
        limit: int = 50,
        pageId: str = "",
        query: str = "",
    ) -> SearchResults:
        """Searches a single account for transactions.

        When total transactions exceeds limit, set pageId to value of
        SearchResults.nextPageId from previous response in subsequent requests.
        """

    @endpoint("/app/v1/accounts/transactions/search", method="POST")
    def summarise_transactions(
        self,
        # Exclude any Filter fields set to None before sending.
        body: Annotated[
            Filter, api_ref(fmt=lambda body: body.model_dump(exclude_none=True))
        ],
    ) -> TransactionsSummary:
        """Returns filtered transactions from all accounts.

        When total transactions exceeds limit, set Filter.paginationToken to value
        of TransactionSummary.nextPageId from previous response in subsequent requests.
        """

    @endpoint("/app/v1/cards")
    def get_cards(self) -> Cards:
        """Returns details of payment cards."""

    @endpoint("/app/v1/v2/devices")
    def get_devices(self, deviceUuid: str) -> list[Device]:
        """Returns enrolled authentication devices."""

    @endpoint("/app/v1/device/{device_id}")
    def delete_device(self, device_id: str) -> str:
        """Removes (invalidates) authentication device."""

    @endpoint("/app/v1/contacts")
    def get_contacts(self) -> Contacts:
        """Returns details of payment contacts."""


class AkamaiTransport(httpx.BaseTransport):
    """httpx transport using AkamaiClient to handle requests.

    `header_blacklist` names headers controlled by AkamaiClient. We don't want httpx
    to interfere with these.
    """

    def __init__(
        self,
        akamai_client: AkamaiClient,
        *,
        telemetry: bool = True,
        header_blacklist: set[str] = {
            "user-agent",
            "accept",
            "accept-language",
            "accept-encoding",
            "origin",
            "referer",
            "cookie",
            "host",
            "connection",
            "content-length",
            "transfer-encoding",
            "akamai-bm-telemetry",
        },
    ):
        self.akamai_client = akamai_client
        self.telemetry = telemetry
        self.header_blacklist = header_blacklist

    def handle_request(self, request: httpx.Request) -> httpx.Response:
        request.read()  # full body - wre doesn't stream
        answered = self.akamai_client.request(
            RequestInput(
                url=str(request.url),  # this includes query params
                method=request.method,
                # drop incoming headers that are blacklisted
                headers={
                    k: v
                    for k, v in request.headers.items()
                    if k.lower() not in self.header_blacklist
                },
                # httpx already encodes incoming json body in request.content
                # don't need to double handle encoding
                body=request.content.decode("utf-8") if request.content else None,
                telemetry=self.telemetry,
            )
        )
        return httpx.Response(
            status_code=answered["status"],
            headers=answered.get("headers") or [],
            content=(answered.get("body") or "").encode("utf-8"),
            request=request,
        )

    def close(self):
        # client closed when transport closed
        self.akamai_client.close()


def add_request_id(request: httpx.Request) -> None:
    """Sets unique x-request-id header on request."""
    request.headers["x-request-id"] = str(uuid.uuid1())


class HttpClient(httpx.Client):
    """httpx client customised to authenticate with ubank.

    Requests are authenticated with a passkey, if supplied. Authenticate manually
    with `.authenticate(passkey)`.

    Set `api_version` to customise `x-api-version` header value.
    Set `app_version` to customise app version in `x-device-meta` header value.

    Use as a context manager so the Akamai transport client is closed:

        with HttpClient(passkey) as client:
            ...

    `base_url` is set to https://www.ubank.com.au. Use relative paths in requests:

    ```python
    client.get("/app/v1/accounts/summary")
    ```
    """

    def __init__(
        self, passkey: Optional[Passkey] = None, api_version="37", app_version="2.242.1"
    ) -> None:
        self.akamai_client = AkamaiClient.open(
            AkamaiConfig(page_url="https://www.ubank.com.au/welcome/login/username")
        )
        self.akamai_client.solve({})  # solve some puzzles
        super().__init__(
            # standard headers for every request
            headers={
                "x-api-version": api_version,
                "x-device-meta": generate_device_meta(
                    self.akamai_client.info()["user_agent"], app_version
                ),
            },
            # requests get a x-request-id
            event_hooks={"request": [add_request_id]},
            base_url="https://www.ubank.com.au",
            transport=AkamaiTransport(self.akamai_client),
        )
        if passkey is not None:
            self.authenticate(passkey)

    def authenticate(self, passkey: Passkey) -> None:
        """Authenticates session with supplied passkey.

        This method performs performs webauthn authentication with ubank -- the
        Relying Party (RP):
        - we request challenge from RP
        - we sign assertion with challenge and send to RP for verification
        - RP responds with tokens
        - we configure HTTP client with tokens

        Caught HTTPStatusErrors are re-raised with a note containing the API's error
        response text. This requires Python >= 3.11.
        """
        self.headers["x-device-id"] = passkey.device_id
        # Hack signature counter to Unix time. This 32-bit counter value can
        # be incremented by *any* positive value. By using Unix time, we don't
        # have to muck about keeping track of counter values in the passkey file.
        # https://www.w3.org/TR/webauthn-2/#signature-counter
        passkey.soft_webauthn_device.sign_count = int(time.time())

        # Initiate auth flow by identifying ourselves. Here, identity is a uuid
        # rather than email/mobile username.
        try:
            response = self.post(
                "/app/v1/welcome", json={"identity": passkey.username}
            ).raise_for_status()
        except httpx.HTTPStatusError as e:
            e.add_note(e.response.text)
            raise
        response_json = response.json()

        # update headers with xsrf token from this response
        assert response_json["xsrfToken"]
        self.headers["x-xsrf-token"] = response_json["xsrfToken"]
        # Receive challenge from relying party (ubank).
        try:
            response = self.get(
                "/app/v1/session/authorize",
                params={"username": passkey.username},
            ).raise_for_status()
        except httpx.HTTPStatusError as e:
            e.add_note(e.response.text)
            raise
        response_json = response.json()

        # Parse credential request options from response.
        options = parse_public_key_credential_request_options(
            response_json["publicKeyCredentialRequestOptions"]
        )
        # Make assertion object suitable for ubank by making values JSON-serializable.
        assertion = prepare_assertion(passkey.soft_webauthn_device.get(options, origin))
        # Complete authentication flow by sending signed assertion to relying
        # party.
        try:
            response = self.post(
                "/app/v1/challenge/fido2-assertion",
                # Query parameters come from previous response.
                params={
                    "nonce": response_json["nonce"],
                    "state": response_json["state"],
                    "session": response_json["session"],
                },
                json={
                    "assertion": json.dumps(assertion),
                    # flowID comes from previous response.
                    "flowId": response_json["flowId"],
                    "origin": origin,
                },
            ).raise_for_status()
        except httpx.HTTPStatusError as e:
            e.add_note(e.response.text)
            raise
        response_json = response.json()

        # update headers once again with xsrf token from this response
        assert response_json["xsrfToken"]
        self.headers["x-xsrf-token"] = response_json["xsrfToken"]
        # useful for other paths not under /app/v1/
        self.headers["Authorization"] = f"Bearer {response_json['xsrfToken']}"


def derive_key(password: str, salt=b"") -> bytes:
    """Returns key derived from from password.

    https://cryptography.io/en/latest/fernet/#using-passwords-with-fernet
    """
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=1_000_000,
    )
    return urlsafe_b64encode(kdf.derive(password.encode("utf-8")))


def int8array_to_bytes(array: list[int]) -> bytes:
    """Converts Javascript Int8Array to unsigned bytes."""
    return b"".join(
        # length and byteorder must be specified for Python < 3.11.
        int8.to_bytes(length=1, byteorder="big", signed=True)
        for int8 in array
    )


def parse_public_key_credential_creation_options(string: str) -> dict:
    """Returns SoftWebauthnDevice create options dict parsed from ubank's
    publicKeyCredentialCreationOptions."""
    # Deserialize string.
    options = {"publicKey": json.loads(string)}
    # Convert Int8Arrays to bytes.
    options["publicKey"]["user"]["id"] = int8array_to_bytes(
        options["publicKey"]["user"]["id"]
    )
    options["publicKey"]["challenge"] = int8array_to_bytes(
        options["publicKey"]["challenge"]
    )
    for credential in options["publicKey"]["excludeCredentials"]:
        credential["id"] = int8array_to_bytes(credential["id"])
    # Fix alg values; should be int not string.
    # https://developer.mozilla.org/en-US/docs/Web/API/PublicKeyCredentialCreationOptions#alg
    for param in options["publicKey"]["pubKeyCredParams"]:
        param["alg"] = int(param["alg"])

    return options


def parse_public_key_credential_request_options(string: str) -> dict:
    """Returns SoftWebauthnDevice get options dict parsed from ubank's
    publicKeyCredentialRequestOptions."""
    # Deserialize string.
    options = {"publicKey": json.loads(string)}
    # Convert Int8Arrays to bytes.
    options["publicKey"]["challenge"] = int8array_to_bytes(
        options["publicKey"]["challenge"]
    )
    for credential in options["publicKey"]["allowCredentials"]:
        credential["id"] = int8array_to_bytes(credential["id"])

    return options


def prepare_attestation(attestation: dict) -> dict:
    """Creates JSON-serializable attestation from SoftWebauthnDevice attestation object."""
    return {
        # id is base64 bytes, decode to base64 string.
        "id": attestation["id"].decode("ascii"),
        # rawId is bytes, convert to base64 encoded string.
        "rawId": b64encode(attestation["rawId"]).decode("ascii"),
        # clientDataJSON and attestationObject are bytes, convert to base64 encoded
        # strings.
        "response": {
            key: b64encode(value).decode("ascii")
            for key, value in attestation["response"].items()
        },
        "type": attestation["type"],
    }


def prepare_assertion(assertion: dict) -> dict:
    """Creates JSON-serializable assertion from SoftWebauthnDevice assertion object."""
    return {
        # id is base64 bytes, decode to base64 string.
        "id": assertion["id"].decode("ascii"),
        # rawId is bytes, convert to base64 encoded string.
        "rawId": b64encode(assertion["rawId"]).decode("ascii"),
        # clientDataJSON, attestationObject, signature and userHandle are bytes,
        # convert to base64 encoded strings.
        "response": {
            key: b64encode(value).decode("ascii")
            for key, value in assertion["response"].items()
        },
        "type": assertion["type"],
    }


def add_passkey(username: str, password: str, passkey_name: str) -> Passkey:
    """Returns new passkey registered with ubank after prompting for security code
    sent to mobile.

    This function returns sensitive key material. You are responsible for securing
    it!

    - `username` is your ubank username
    - `password` is your ubank password
    - `passkey_name` sets passkey name (shown in ubank app)
    """
    # Initialise a software-based passkey.
    passkey = Passkey(name=passkey_name)

    with HttpClient() as client:
        # Start enrolment by identifying ourselves.
        try:
            response = client.post(
                url="/app/v1/welcome",
                json={"identity": username},
            ).raise_for_status()
        except httpx.HTTPStatusError as e:
            e.add_note(e.response.text)
            raise
        response_json = response.json()

        # Next, authenticate with password.
        try:
            response = client.post(
                url="/app/v1/challenge/password",
                json={"deviceName": passkey_name, "password": password},
                # xsrf token from previous response
                headers={"x-xsrf-token": response_json["xsrfToken"]},
            ).raise_for_status()
        except httpx.HTTPStatusError as e:
            e.add_note(e.response.text)
            raise
        response_json = response.json()

        # Authenticate with second factor: a security code sent to mobile.
        try:
            otp_response = client.post(
                url="/app/v1/challenge/otp",
                # Set parameters returned in previous response.
                params={
                    "nonce": response_json["nonce"],
                    "state": response_json["state"],
                    "session": response_json["session"],
                },
                json={
                    # flowID comes from previous response.
                    "flowId": response_json["flowId"],
                    # Prompt interactively for security code.
                    "otpValue": input(
                        f"Enter security code sent to {response_json['maskedMobileNumber']}: "
                    ),
                },
                # xsrf token from previous response
                headers={"x-xsrf-token": response_json["xsrfToken"]},
            ).raise_for_status()
        except httpx.HTTPStatusError as e:
            e.add_note(e.response.text)
            raise
        otp_response_json = otp_response.json()
        # Store username UUID assigned by ubank contained in this response.
        passkey.username = otp_response_json["username"]

        # Initiate registration of new credential (passkey) with relying party (ubank).
        try:
            response = client.post(
                url="/app/v1/v2/device",
                json={"deviceName": passkey_name, "type": "FIDO2"},
                # xsrf token from previous response
                headers={"x-xsrf-token": otp_response_json["xsrfToken"]},
            ).raise_for_status()
        except httpx.HTTPStatusError as e:
            e.add_note(e.response.text)
            raise
        response_json = response.json()
        # This response contains a device ID assigned by ubank. It's not set in
        # headers just quite yet though.
        passkey.device_id = response_json["deviceId"]
        # Parse credential creation options from response.
        options = parse_public_key_credential_creation_options(
            response_json["publicKeyCredentialCreationOptions"]
        )
        # Make attestation object suitable for ubank by making values JSON-serializable.
        attestation = prepare_attestation(
            passkey.soft_webauthn_device.create(options, origin)
        )

        # Send public key credential attestation to relying party (ubank).
        try:
            client.post(
                url=f"/app/v1/v2/device/{passkey.device_id}/activate",
                json={
                    "attestation": json.dumps(attestation),
                    "origin": origin,
                    "type": "FIDO2",
                },
                # xsrf token from otp response
                headers={"x-xsrf-token": otp_response_json["xsrfToken"]},
            ).raise_for_status()
        except httpx.HTTPStatusError as e:
            e.add_note(e.response.text)
            raise

        return passkey


def to_dict(device: SoftWebauthnDevice) -> dict:
    """Converts SoftWebauthnDevice instance to dict with serialized private key."""
    serialized_private_key = (
        device.private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )
        if device.private_key
        else b""
    )
    return {
        "credential_id": device.credential_id,
        "serialized_private_key": serialized_private_key,
        "aaguid": device.aaguid,
        "rp_id": device.rp_id,
        "user_handle": device.user_handle,
        "sign_count": device.sign_count,
    }


def from_dict(device_dict: dict) -> SoftWebauthnDevice:
    """Returns device instantiated from dict."""
    device = SoftWebauthnDevice()
    device.credential_id = device_dict["credential_id"]
    device.private_key = serialization.load_pem_private_key(
        device_dict["serialized_private_key"],
        password=None,
        backend=default_backend(),
    )
    device.aaguid = device_dict["aaguid"]
    device.rp_id = device_dict["rp_id"]
    device.user_handle = device_dict["user_handle"]
    device.sign_count = device_dict["sign_count"]
    return device


def generate_device_meta(user_agent: str, app_version: str) -> str:
    """Returns x-device-meta string from user agent and app version.

    Supply `user_agent` from call to `.info()["user_agent"]` on an instance of
    AkamaiClient. (Assumes MacOS Chrome user agent.)

    See https://www.ubank.com.au/welcome/login/username for latest app version.
    """
    assert "Chrome/" in user_agent
    browser_name = "Chrome"
    match = re.search(r"Chrome/([\d.]+)", user_agent)
    assert match
    browser_version = match.group(1)
    # truncate version to 3 components
    browser_version = ".".join(browser_version.split(".")[:3])
    assert "Macintosh" in user_agent
    browser_os = "Mac OS"
    return json.dumps(
        {
            "appVersion": app_version,
            "browserInfo": {
                "browserName": browser_name,
                "browserOs": browser_os,
                "browserType": "browser",
                "browserVersion": browser_version,
            },
            "deviceName": user_agent,
            "environment": "production",
            "instance": "live",
            "platform": "IB",
        },
        separators=(",", ":"),
    )


def cli():
    parser = argparse.ArgumentParser(
        description="Returns a new passkey registered with ubank.",
        epilog="You will be asked for your ubank password and secret code interactively. "
        "The passkey is encrypted with your ubank password.",
    )
    parser.add_argument("username", help="ubank username")
    parser.add_argument(
        "-o",
        "--output",
        default="-",
        type=argparse.FileType(mode="wb"),
        help="writes encrypted passkey to file (default: write to stdout)",
        dest="file",
    )
    parser.add_argument(
        "-n",
        "--passkey-name",
        default="ubank.py",
        help="sets passkey name (default: ubank.py)",
    )
    parser.add_argument(
        "-v", "--verbose", action="store_true", help="displays httpx INFO logs"
    )
    args = parser.parse_args()
    if args.verbose:
        # Displays basic httpx request information.
        logging.basicConfig(level=logging.INFO)
    password = getpass("Enter ubank password: ")
    passkey = add_passkey(
        args.username,
        password=password,
        passkey_name=args.passkey_name,
    )
    passkey.dump(args.file, password=password)


if __name__ == "__main__":
    cli()
