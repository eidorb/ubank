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
import time
import uuid
from base64 import b64encode, urlsafe_b64encode
from datetime import date, datetime
from decimal import Decimal
from getpass import getpass
from typing import IO, AnyStr, Optional

import httpx
import meatie_httpx
from cryptography.fernet import Fernet
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from fido2 import cbor
from meatie import endpoint
from pydantic import BaseModel, ConfigDict, Field

from soft_webauthn_patched import SoftWebauthnDevice

__version__ = "2.2.2"


# Unchanging headers in every request.
base_headers = {
    "Origin": "ionic://bank86400",
    "x-api-version": "33",
    "x-private-api-key": "ANZf5WgzmVLmTUwAQyuCq7LspXF2pd4N",
}

# Referenced in Client and add_passkey() for attestation and assertion.
origin = "https://www.ubank.com.au"


class Address(BaseModel):
    addressFormat: Optional[str]
    addressType: Optional[str]
    flatOrBoxNumber: Optional[str]
    flatOrBoxType: Optional[str]
    postcode: Optional[str]
    propertyName: Optional[str]
    state: Optional[str]
    streetName: Optional[str]
    streetNumber: Optional[str]
    streetType: Optional[str]
    suburb: Optional[str]


class Customer(BaseModel):
    addresses: list[Address]
    countriesOfCitizenship: list[str]
    customerId: Optional[str]
    dateCreated: date
    dateOfBirth: date
    email: Optional[str]
    emailVerified: bool
    fatcaCrsProvided: bool
    firstName: Optional[str]
    middleName: Optional[str]
    lastName: Optional[str]
    additionalNames: Optional[str]
    mobileNumber: Optional[str]
    externalCustomerNumber: Optional[str]
    jurisdictionSourceOfWealth: list
    natureAndPurposeOfRelationship: list
    nonResidentTaxDetails: list
    occupationId: Optional[str]
    title: Optional[str]
    userId: str
    financialCrime: dict
    editAddressEnabled: bool


class Balance(BaseModel):
    currency: str
    current: float
    available: float


class Account(BaseModel):
    id: str
    number: str
    label: str
    nickname: str
    type: str
    balance: Balance
    status: str
    openDate: datetime

    # Other fields depend on account type, access them through .__pydantic_extra__.
    model_config = ConfigDict(extra="allow")


class Bank(BaseModel):
    bankId: int
    shortBankName: str
    accounts: list[Account]

    # Linked external banks have other fields accessible through .__pydantic_extra__.
    model_config = ConfigDict(extra="allow")


class LinkedBanks(BaseModel):
    linkedBanks: list[Bank]


class Value(BaseModel):
    amount: Decimal
    currency: str


class From(BaseModel):
    name: Optional[str] = None
    legalName: Optional[str] = None
    bsb: Optional[str] = None
    number: Optional[str] = None
    description: Optional[str] = None


To = From


class Transaction(BaseModel):
    id: str
    cbsId: str
    bankId: str
    accountId: str
    # It seems almost every field is potentially optional.
    posted: Optional[datetime] = None
    completed: Optional[datetime] = None
    value: Optional[Value] = None
    type: Optional[str] = None
    shortDescription: Optional[str] = None
    narration: Optional[Value] = None
    balance: Optional[Value] = None
    debitOrCredit: Optional[str] = None
    description: Optional[str] = None
    category: Optional[str] = None
    paymentScheme: Optional[str] = None
    receiptNumber: Optional[str] = None
    from_: Optional[From] = Field(default=None, alias="from")
    bpayBiller: Optional[dict] = None
    to: Optional[To] = None
    walletType: Optional[str] = None
    cardNumber: Optional[str] = None
    nppTransactionId: Optional[str] = None
    nppServiceOverlay: Optional[str] = None
    nppCategoryPurposeCode: Optional[str] = None
    nppCreditorReference: Optional[str] = None
    nppIdentification: Optional[str] = None
    nppSchemeName: Optional[str] = None
    terminalId: Optional[str] = None
    systemTraceAuditNumber: Optional[str] = None
    visaTerminalId: Optional[str] = None
    typeCode: Optional[str] = None
    longDescription: Optional[str] = None
    lwc: Optional[dict] = None

    # If other fields (not defined above) are returned in the response, they are
    # made available through __pydantic_extra__.
    model_config = ConfigDict(extra="allow")


class TransactionsSummary(BaseModel):
    nextPageId: str
    totalCount: int
    totalAmount: str
    transactions: list[Transaction]


class Filter(BaseModel):
    timezone: str = "Australia/Lord_Howe"
    fromDate: date
    toDate: date
    limit: int = 5


class SearchResults(BaseModel):
    nextPageId: str
    transactions: list[Transaction]
    pendingTransactions: list


class Device(BaseModel):
    type: str
    deviceUuid: str
    deviceName: str
    deviceCreatedOn: Optional[str] = None
    dateCreated: int
    dateCreatedTimestamp: datetime
    enabled: bool
    isEditable: bool


class Card(BaseModel):
    accountIds: list[str]
    cardToken: str
    cardNumber: str
    bankId: int
    cardId: str
    nameOnCard: str
    cardStatus: str
    expiryDate: str
    cardType: str
    panReferenceId: str
    locked: bool
    cardArtName: str
    lastProductionDate: datetime
    cardControls: list[dict]


class Cards(BaseModel):
    cards: list[Card]
    cardReplacements: list


class Contacts(BaseModel):
    contacts: list[dict]


class Passkey:
    """Represents a passkey registered with ubank."""

    def __init__(self, name: str):
        """name is passkey/device name shown in emails and app."""
        super().__init__()
        self.name = name
        # Generate a fresh hardware ID.
        hardware_id = str(uuid.uuid4())
        # Start with an empty device ID. ubank will assign one later.
        device_id = ""
        # Hard coded device meta string from app version and device name.
        device_meta = json.dumps(
            {
                # Keep track with the latest version in case API blocks old versions: https://apps.apple.com/au/app/id1449543099.
                "appVersion": "11.133.3",
                "binaryVersion": "11.133.3",
                # Keep track with latest iPhone model in case API blocks old models.
                # Matches format of "Hardware strings" row in this table, replacing ',' with '-':
                # https://en.wikipedia.org/wiki/List_of_iPhone_models
                "deviceName": "iPhone17-3",
                "environment": "production",
                "instance": "live",
                "native": True,
                "platform": "ios",
            }
        )
        # Start with empty username, it will be assigned by ubank later.
        username = ""
        self.name = name
        self.hardware_id = hardware_id
        self.device_id = device_id
        self.device_meta = device_meta
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
                        "device_meta": self.device_meta,
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
        passkey.device_meta = deserialized_passkey["device_meta"]
        passkey.username = deserialized_passkey["username"]
        passkey.soft_webauthn_device = from_dict(
            deserialized_passkey["soft_webauthn_device_dict"]
        )
        return passkey


class Client(meatie_httpx.Client):
    """A ubank Meatie client.

    Provides methods for interacting with the following resources:

    - customer details
    - accounts
    - transactions
    - cards
    - contacts
    - authentication devices (includes passkeys)

    This Meatie client has a bunch of methods defined... with nothing in them!

    The Meatie library generates code for calling endpoints automatically. It does
    this by inspecting type signatures (among many other things).

    It relies heavily upon [descriptors](https://docs.python.org/3/howto/descriptor.html).
    I've heard of decorators, but not descriptors. Sounds powerful. Worth looking into.
    """

    def __init__(self, passkey: Passkey) -> None:
        super().__init__(HttpClient(passkey))

    @endpoint("customer-details")
    def get_customer_details(self) -> Customer:
        """Returns customer details."""

    @endpoint("accounts")
    def get_linked_banks(
        self, externalRefresh: str = "false", refresh: str = "false", type: str = "all"
    ) -> LinkedBanks:
        """Returns bank account details (including linked external accounts).

        - `externalRefresh` set to 'true' initiates a refresh of linked account data.
        - `type` sets type of accounts returned: 'internal', 'external', or 'all'.
        """

    @endpoint("accounts/{account_id}/bank/{bank_id}/transactions")
    def search_account_transactions(
        self,
        account_id: str,
        bank_id: str,
        customerId: str,
        limit: int = 50,
        pageId: str = "",
        query: str = "",
    ) -> SearchResults:
        """Searches a single account for transactions."""

    @endpoint("accounts/transactions/search", method="POST")
    def summarise_transactions(self, body: Filter) -> TransactionsSummary:
        """Returns combined transactions of all accounts."""

    @endpoint("cards")
    def get_cards(self) -> Cards:
        """Returns details of payment cards."""

    @endpoint("v2/devices")
    def get_devices(self, deviceUuid: str) -> list[Device]:
        """Returns enrolled authentication devices."""

    @endpoint("device/{device_id}")
    def delete_device(self, device_id: str) -> str:
        """Removes (invalidates) authentication device."""

    @endpoint("contacts")
    def get_contacts(self) -> Contacts:
        """Returns details of payment contacts."""


class HttpClient(httpx.Client):
    """httpx client customised to authenticate with ubank.

    Requests are authenticated using the supplied passkey.

    Use this class with a context manager to ensure ubank sessions and HTTP connections
    are properly closed.

    ```python
    with Client(passkey) as client:
        ...
    ```

    `base_url` is set to https://api.ubank.com.au/app/v1/. Use relative paths in requests:

    ```python
    client.get("accounts/summary")
    ```
    """

    def __init__(self, passkey: Passkey) -> None:
        """Initialises authenticated session with passkey.

        This method performs performs webauthn authentication with ubank -- the
        Relying Party (RP):
        - we request challenge from RP
        - we sign assertion with challenge and send to RP for verification
        - RP responds with tokens
        - we configure HTTP client with tokens

        Caught HTTPStatusErrors are re-raised with a note containing the API's error
        response text. This requires Python >= 3.11.
        """
        with httpx.Client(
            # Headers that are present from the get go. Not all
            headers={
                **base_headers,
                "x-hardware-id": passkey.hardware_id,
                "x-device-id": passkey.device_id,
                "x-device-meta": passkey.device_meta,
            },
        ) as client:
            # Hack signature counter to Unix time. This 32-bit counter value can
            # be incremented by *any* positive value. By using Unix time, we don't
            # have to muck about keeping track of counter values in the passkey file.
            # https://www.w3.org/TR/webauthn-2/#signature-counter
            passkey.soft_webauthn_device.sign_count = int(time.time())

            # Initiate authentication flow to receive challenge from relying party
            # (ubank).
            try:
                response = client.get(
                    "https://api.ubank.com.au/app/v1/session/authorize",
                    params={
                        "username": passkey.username,
                    },
                ).raise_for_status()
            except httpx.HTTPStatusError as e:
                e.add_note(e.response.text)
                raise

            # Parse credential request options from response.
            options = parse_public_key_credential_request_options(
                response.json()["publicKeyCredentialRequestOptions"]
            )
            # Make assertion object suitable for ubank by making values JSON-serializable.
            assertion = prepare_assertion(
                passkey.soft_webauthn_device.get(options, origin)
            )
            # Complete authentication flow by sending signed assertion to relying
            # party.
            try:
                response = client.post(
                    "https://api.ubank.com.au/app/v1/challenge/fido2-assertion",
                    # Query parameters come from previous response.
                    params={
                        "nonce": response.json()["nonce"],
                        "state": response.json()["state"],
                        "session": response.json()["session"],
                    },
                    json={
                        "assertion": json.dumps(assertion),
                        # flowID comes from previous response.
                        "flowId": response.json()["flowId"],
                        "origin": origin,
                    },
                    # Set access and auth token headers from previous response.
                    headers={
                        "x-access-token": response.json()["accessToken"],
                        "x-auth-token": response.json()["accessToken"],
                    },
                ).raise_for_status()
            except httpx.HTTPStatusError as e:
                e.add_note(e.response.text)
                raise
            # Set access and auth token headers for future requests.
            self.access_token = client.headers["x-access-token"] = client.headers[
                "x-auth-token"
            ] = response.json()["accessToken"]
            # Store other tokens in order to kill session in future.
            self.refresh_token = response.json()["refreshToken"]
            self.session_token = response.json()["sessionToken"]

        # Initialise new httpx.Client, keeping headers and cookies from client.
        super().__init__(
            headers=client.headers,
            cookies=client.cookies,
            base_url="https://api.ubank.com.au/app/v1/",
        )

    def _delete_session(self) -> None:
        """Kills ubank session."""
        self.request(
            "DELETE",
            "sessions",
            json={
                "accessToken": self.access_token,
                "refreshToken": self.refresh_token,
                "sessionToken": self.session_token,
            },
        ).raise_for_status()

    def close(self) -> None:
        """Kills ubank session before closing."""
        self._delete_session()
        super().close()

    def __exit__(self, exc_type, exc_value, traceback) -> None:
        """Handle use in context manager Kills ubank session before exiting the context."""
        self._delete_session()
        super().__exit__(exc_type, exc_value, traceback)


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

    :param username: ubank username
    :param password: ubank password
    :param passkey_name: Set passkey name (shown in ubank app)
    :return: New passkey
    """
    # Initialise a software-based passkey.
    passkey = Passkey(name=passkey_name)

    # Use a Client to persist cookies and setting default headers.
    with httpx.Client(
        headers={
            **base_headers,
            "x-hardware-id": passkey.hardware_id,
            "x-device-id": passkey.device_id,
            "x-device-meta": passkey.device_meta,
        }
    ) as client:
        # Start enrolment by identifying ourselves.
        try:
            response = client.post(
                url="https://api.ubank.com.au/app/v1/welcome",
                json={"identity": username},
            ).raise_for_status()
        except httpx.HTTPStatusError as e:
            e.add_note(e.response.text)
            raise

        # Next, authenticate with password.
        try:
            response = client.post(
                url="https://api.ubank.com.au/app/v1/challenge/password",
                json={"deviceName": passkey_name, "password": password},
                # Set access and auth token headers from previous response.
                headers={
                    "x-access-token": response.json()["accessToken"],
                    "x-auth-token": response.json()["accessToken"],
                },
            ).raise_for_status()
        except httpx.HTTPStatusError as e:
            e.add_note(e.response.text)
            raise

        # Authenticate with second factor: a security code sent to mobile.
        try:
            otp_response = client.post(
                url="https://api.ubank.com.au/app/v1/challenge/otp",
                # Set parameters returned in previous response.
                params={
                    "nonce": response.json()["nonce"],
                    "state": response.json()["state"],
                    "session": response.json()["session"],
                },
                json={
                    # flowID comes from previous response.
                    "flowId": response.json()["flowId"],
                    # Prompt interactively for security code.
                    "otpValue": input(
                        f"Enter security code sent to {response.json()['maskedMobileNumber']}: "
                    ),
                },
                # Set access and auth token headers from previous response.
                headers={
                    "x-access-token": response.json()["accessToken"],
                    "x-auth-token": response.json()["accessToken"],
                },
            ).raise_for_status()
        except httpx.HTTPStatusError as e:
            e.add_note(e.response.text)
            raise
        # Store username UUID assigned by ubank contained in this response.
        passkey.username = otp_response.json()["username"]
        # Set access and auth token headers for future requests.
        client.headers["x-access-token"] = client.headers["x-auth-token"] = (
            otp_response.json()["accessToken"]
        )

        # Initiate registration of new credential (passkey) with relying party (ubank).
        try:
            response = client.post(
                url="https://api.ubank.com.au/app/v1/v2/device",
                json={"deviceName": passkey_name, "type": "FIDO2"},
            ).raise_for_status()
        except httpx.HTTPStatusError as e:
            e.add_note(e.response.text)
            raise
        # This response contains a device ID assigned by ubank. It's not set in
        # headers just quite yet though.
        passkey.device_id = response.json()["deviceId"]
        # Parse credential creation options from response.
        options = parse_public_key_credential_creation_options(
            response.json()["publicKeyCredentialCreationOptions"]
        )
        # Make attestation object suitable for ubank by making values JSON-serializable.
        attestation = prepare_attestation(
            passkey.soft_webauthn_device.create(options, origin)
        )

        # Send public key credential attestation to relying party (ubank).
        try:
            client.post(
                url=f"https://api.ubank.com.au/app/v1/v2/device/{passkey.device_id}/activate",
                json={
                    "attestation": json.dumps(attestation),
                    "origin": origin,
                    "type": "FIDO2",
                },
            ).raise_for_status()
        except httpx.HTTPStatusError as e:
            e.add_note(e.response.text)
            raise

        # Set device ID header for future requests.
        client.headers["x-device-id"] = passkey.device_id

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
