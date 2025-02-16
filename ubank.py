"""Access ubank with Python."""

import argparse
import json
import logging
import time
import uuid
from base64 import b64encode
from datetime import date, datetime
from decimal import Decimal
from getpass import getpass
from typing import IO, Optional

import httpx
import soft_webauthn
from cryptography.hazmat.primitives import serialization
from meatie import endpoint
from meatie_httpx import Client as MeatieClient
from pydantic import BaseModel, Field

__version__ = "2.0.0"


# Unchanging headers in every request.
base_headers = {
    "Origin": "ionic://bank86400",
    "x-api-version": "32",
    "x-private-api-key": "ANZf5WgzmVLmTUwAQyuCq7LspXF2pd4N",
}

# Used in passkey creation and various requests.
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


class CustomerDetails(BaseModel):
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
    bsb: str
    label: str
    nickname: str
    type: str
    balance: Balance
    status: str
    lastBalanceRefresh: datetime
    openDate: datetime
    isJointAccount: bool
    depositProductData: dict
    metadata: Optional[dict] = None


class LinkedBank(BaseModel):
    bankId: int
    shortBankName: str
    accounts: list[Account]


class AccountsResponse(BaseModel):
    linkedBanks: list[LinkedBank]


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
    posted: datetime
    completed: datetime
    value: Value
    type: str
    shortDescription: str
    # Everything else seems optional.
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


class TransactionsSearchResponse(BaseModel):
    nextPageId: str
    totalCount: int
    totalAmount: str
    transactions: list[Transaction]


class TransactionsSearchBody(BaseModel):
    timezone: str = "Etc/UTC"
    fromDate: date
    toDate: date
    limit: int = 5


class TransactionsResponse(BaseModel):
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


class CardsResponse(BaseModel):
    cards: list[Card]
    cardReplacements: list


class Passkey(soft_webauthn.SoftWebauthnDevice):
    """Extends SoftWebauthnDevice with ubank-specific attributes and serialization
    methods."""

    def __init__(self, name: str, app_version="11.103.3", device_name="iPhone17-3"):
        """Initialise your passkey with a name.

        :param name: Set passkey name (shown in ubank app)
        :param app_version: Set ubank application version identifier. See versions here:
            https://apps.apple.com/au/app/id1449543099.
        :param device_name: Set device identifier. See "Hardware strings" row in this
            table: https://en.wikipedia.org/wiki/List_of_iPhone_models. Replace comma
            with hyphen.
        """
        super().__init__()
        self.name = name
        # Generate a fresh hardware ID.
        self.hardware_id = str(uuid.uuid4())
        # Start with an empty device ID. ubank will assign one later.
        self.device_id = ""
        # Build device meta string from app version and device name.
        self.device_meta = json.dumps(
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
        # Start with empty username, it will be assigned by ubank later.
        self.username = ""

    # TODO: Remove if custom flag support merged https://github.com/bodik/soft-webauthn/pull/15
    def create(self, options, origin):
        """IDENTICAL to super().create(), except User Verification flag set."""
        if {"alg": -7, "type": "public-key"} not in options["publicKey"][
            "pubKeyCredParams"
        ]:
            raise ValueError(
                "Requested pubKeyCredParams does not contain supported type"
            )

        if ("attestation" in options["publicKey"]) and (
            options["publicKey"]["attestation"] not in [None, "none"]
        ):
            raise ValueError("Only none attestation supported")

        # prepare new key
        self.cred_init(
            options["publicKey"]["rp"]["id"], options["publicKey"]["user"]["id"]
        )

        # generate credential response
        client_data = {
            "type": "webauthn.create",
            "challenge": soft_webauthn.urlsafe_b64encode(
                options["publicKey"]["challenge"]
            )
            .decode("ascii")
            .rstrip("="),
            "origin": origin,
        }

        rp_id_hash = soft_webauthn.sha256(self.rp_id.encode("ascii"))
        # Set Bit 2, User Verification (UV) also.
        # https://developer.mozilla.org/en-US/docs/Web/API/Web_Authentication_API/Authenticator_data
        flags = b"\x45"  # attested_data + user_present + user_verified
        sign_count = soft_webauthn.pack(">I", self.sign_count)
        credential_id_length = soft_webauthn.pack(">H", len(self.credential_id))
        cose_key = soft_webauthn.cbor.encode(
            soft_webauthn.ES256.from_cryptography_key(self.private_key.public_key())
        )
        attestation_object = {
            "authData": rp_id_hash
            + flags
            + sign_count
            + self.aaguid
            + credential_id_length
            + self.credential_id
            + cose_key,
            "fmt": "none",
            "attStmt": {},
        }

        return {
            "id": soft_webauthn.urlsafe_b64encode(self.credential_id),
            "rawId": self.credential_id,
            "response": {
                "clientDataJSON": json.dumps(client_data).encode("utf-8"),
                "attestationObject": soft_webauthn.cbor.encode(attestation_object),
            },
            "type": "public-key",
        }

    # TODO: Remove if custom flag support merged https://github.com/bodik/soft-webauthn/pull/15
    def get(self, options, origin):
        """IDENTICAL to super().create(), except User Verification flag set."""

        if self.rp_id != options["publicKey"]["rpId"]:
            raise ValueError("Requested rpID does not match current credential")

        self.sign_count += 1

        # prepare signature
        client_data = json.dumps(
            {
                "type": "webauthn.get",
                "challenge": soft_webauthn.urlsafe_b64encode(
                    options["publicKey"]["challenge"]
                )
                .decode("ascii")
                .rstrip("="),
                "origin": origin,
            }
        ).encode("utf-8")
        client_data_hash = soft_webauthn.sha256(client_data)

        rp_id_hash = soft_webauthn.sha256(self.rp_id.encode("ascii"))
        # Set Bit 2, User Verification (UV) also.
        # https://developer.mozilla.org/en-US/docs/Web/API/Web_Authentication_API/Authenticator_data
        flags = b"\x05"
        sign_count = soft_webauthn.pack(">I", self.sign_count)
        authenticator_data = rp_id_hash + flags + sign_count

        signature = self.private_key.sign(
            authenticator_data + client_data_hash,
            soft_webauthn.ec.ECDSA(soft_webauthn.hashes.SHA256()),
        )

        # generate assertion
        return {
            "id": soft_webauthn.urlsafe_b64encode(self.credential_id),
            "rawId": self.credential_id,
            "response": {
                "authenticatorData": authenticator_data,
                "clientDataJSON": client_data,
                "signature": signature,
                "userHandle": self.user_handle,
            },
            "type": "public-key",
        }

    # TODO: Replace if serialization PR merged https://github.com/bodik/soft-webauthn/pull/11
    def dump(self, file: IO[bytes]):
        """Serializes passkey to `file`."""
        passkey_dict = {name: value for name, value in vars(self).items()}
        passkey_dict["private_key"] = self.private_key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
        file.write(soft_webauthn.cbor.dump_dict(passkey_dict))

    # TODO: Replace if serialization PR merged https://github.com/bodik/soft-webauthn/pull/11
    @classmethod
    def load(cls, file: IO[bytes]):
        """Deserializes passkey from `file`."""
        passkey_dict = soft_webauthn.cbor.decode(file.read())
        passkey = Passkey(passkey_dict["name"])
        for name, value in passkey_dict.items():
            setattr(passkey, name, value)
        passkey.private_key = serialization.load_pem_private_key(
            passkey.private_key,
            password=None,
            backend=soft_webauthn.default_backend(),
        )
        return passkey


class Api(MeatieClient):
    """Some useful ubank API endpoints.

    Meatie translates these annotated method signatures into code that performs
    the underlying HTTP requests model validation.
    """

    def __init__(self, passkey: Passkey) -> None:
        super().__init__(Client(passkey))

    @endpoint("customer-details")
    def get_customer_details(self) -> CustomerDetails: ...

    @endpoint("accounts")
    def get_accounts(self) -> AccountsResponse: ...

    @endpoint("accounts/summary")
    def get_accounts_summary(self) -> AccountsResponse: ...

    @endpoint("accounts/{account_id}/bank/{bank_id}/transactions")
    def get_account_transactions(
        self,
        account_id: str,
        bank_id: str,
        customerId: str,
        limit: int = 50,
        pageId: str = "",
        query: str = "",
    ) -> TransactionsResponse: ...

    @endpoint("accounts/transactions/search")
    def post_accounts_transactions_search(
        self, body: TransactionsSearchBody
    ) -> TransactionsSearchResponse: ...

    @endpoint("cards")
    def get_cards(self) -> CardsResponse: ...

    @endpoint("v2/devices")
    def get_devices(self, deviceUuid: str) -> list[Device]: ...

    @endpoint("device/{device_id}")
    def delete_device(self, device_id: str) -> str: ...

    @endpoint("contacts")
    def get_contacts(self) -> dict: ...


class Client(httpx.Client):
    """ubank API client based on httpx.Client.

    Requests are authenticated using the supplied passkey.

    Use this class as a context manager to ensure ubank sessions and HTTP connections
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
        """Initialises ubank session using passkey to authenticate.

        :param passkey: `Passkey` registered with ubank
        """
        with httpx.Client(
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
            passkey.sign_count = int(time.time())

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
            assertion = prepare_assertion(passkey.get(options, origin))
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
        """Kills ubank session before exiting the context."""
        self._delete_session()
        super().__exit__(exc_type, exc_value, traceback)


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


def add_passkey(
    username: str,
    password: str,
    passkey_name: str,
) -> Passkey:
    """Registers new passkey with ubank after prompting for security code sent to
    mobile.

    This function returns sensitive key material. You are responsible for securing
    it!

    :param username: ubank username
    :param password: ubank password
    :param passkey_name: Set passkey name (shown in ubank app)
    :return: New passkey
    """
    # Initialise a software-based passkey. We also store various ubank IDs and metadata
    # in this object's attributes.
    passkey = Passkey(passkey_name)

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
        attestation = prepare_attestation(passkey.create(options, origin))

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


def cli():
    parser = argparse.ArgumentParser(
        description="Registers new passkey with ubank. "
        "You will be asked for your ubank password and secret code interactively.",
    )
    parser.add_argument("username", help="ubank username")
    parser.add_argument(
        "-o",
        "--output",
        default="-",
        type=argparse.FileType(mode="wb"),
        help="writes plaintext passkey to file (default: write to stdout)",
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
    # Write passkey to file.
    add_passkey(
        args.username,
        password=getpass("Enter ubank password: "),
        passkey_name=args.passkey_name,
    ).dump(args.file)


if __name__ == "__main__":
    cli()
