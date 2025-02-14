import argparse
import json
import logging
import pickle
import uuid
from base64 import b64encode
from getpass import getpass
from typing import IO

import httpx
import soft_webauthn
from cryptography.hazmat.primitives import serialization

__version__ = "2.0.0rc0"

# Unchanging headers in every request.
base_headers = {
    "Origin": "ionic://bank86400",
    "x-api-version": "32",
    "x-private-api-key": "ANZf5WgzmVLmTUwAQyuCq7LspXF2pd4N",
}

# Used in passkey creation and various requests.
origin = "https://www.ubank.com.au"


class Passkey(soft_webauthn.SoftWebauthnDevice):
    """Extends SoftWebauthnDevice with ubank-specific attributes and serialization
    methods."""

    def __init__(
        self, passkey_name: str, app_version="11.103.3", device_name="iPhone17-3"
    ):
        """Initialise your passkey with a name.

        :param passkey_name: Set passkey name (shown in ubank app)
        :param app_version: Set ubank application version identifier. See versions here:
            https://apps.apple.com/au/app/id1449543099.
        :param device_name: Set device identifier. See "Hardware strings" row in this
            table: https://en.wikipedia.org/wiki/List_of_iPhone_models. Replace comma
            with hyphen.
        """
        super().__init__()
        self.passkey_name = passkey_name
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
        """Writes pickled passkey to `file`."""
        serialized_passkey = Passkey(self.passkey_name)
        for name, value in vars(self).items():
            setattr(serialized_passkey, name, value)
        serialized_passkey.private_key = self.private_key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
        pickle.dump(serialized_passkey, file)

    # TODO: Replace if serialization PR merged https://github.com/bodik/soft-webauthn/pull/11
    @classmethod
    def load(cls, file: IO[bytes]):
        """Returns passkey unpickled from `file`."""
        serialized_passkey = pickle.load(file)
        passkey = Passkey(serialized_passkey.passkey_name)
        for name, value in vars(serialized_passkey).items():
            setattr(passkey, name, value)
        passkey.private_key = serialization.load_pem_private_key(
            serialized_passkey.private_key,
            password=None,
            backend=soft_webauthn.default_backend(),
        )
        # Maintain reference to pickled passkey file.
        passkey.filename = file.name
        return passkey


class Client(httpx.Client):
    """ubank API client based on httpx.Client.

    This class is initialised with a `Passkey` obtained from `add_passkey()`.

    It's recommended to use this class as a context manager. This ensures ubank
    sessions and HTTP connections are properly cleaned when leaving the `with` block:

    ```python
    with Client(passkey) as client:
        ...
    ```

    `base_url` is set to https://api.ubank.com.au/, so only the API path is required
    when making requests:

    ```python
    client.get("/app/v1/accounts/summary")
    ```
    """

    def __init__(self, passkey: Passkey) -> None:
        """Initialises ubank session using passkey to authenticate.

        The passkey's `sign_count` attribute is incremented each time it is used.
        Be sure to store the updated passkey after use.

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
            # Initiate authentication flow to receive challenge from relying party
            # (ubank).
            response = client.get(
                "https://api.ubank.com.au/app/v1/session/authorize",
                params={
                    "username": passkey.username,
                },
            )
            # Parse credential request options from response.
            options = parse_public_key_credential_request_options(
                response.json()["publicKeyCredentialRequestOptions"]
            )
            # Make assertion object suitable for ubank by making values JSON-serializable.
            assertion = prepare_assertion(passkey.get(options, origin))

            # Complete authentication flow by sending signed assertion to relying
            # party.
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
            )
            # Raise exception if passkey authentication was unsuccessful.
            try:
                response.raise_for_status()
            except httpx.HTTPStatusError as e:
                raise ValueError(f"{response.status_code=} {response.text=}") from e
            # Serialize passkey to file after successful authentication.
            with open(passkey.filename, "wb") as f:
                passkey.dump(f)
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


def int8array_to_bytes(array: list[int]) -> bytes:
    """Converts Javascript Int8Array to unsigned bytes."""
    return b"".join(int8.to_bytes(signed=True) for int8 in array)


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
        response = client.post(
            url="https://api.ubank.com.au/app/v1/welcome",
            json={"identity": username},
        )

        # Next, authenticate with password.
        response = client.post(
            url="https://api.ubank.com.au/app/v1/challenge/password",
            json={"deviceName": passkey_name, "password": password},
            # Set access and auth token headers from previous response.
            headers={
                "x-access-token": response.json()["accessToken"],
                "x-auth-token": response.json()["accessToken"],
            },
        )

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
        )
        # Store username UUID assigned by ubank contained in this response.
        passkey.username = otp_response.json()["username"]
        # Set access and auth token headers for future requests.
        client.headers["x-access-token"] = client.headers["x-auth-token"] = (
            otp_response.json()["accessToken"]
        )

        # Initiate registration of new credential (passkey) with relying party (ubank).
        response = client.post(
            url="https://api.ubank.com.au/app/v1/v2/device",
            json={"deviceName": passkey_name, "type": "FIDO2"},
        )
        # Raise exception if passkey registration could not be initiated.
        try:
            response.raise_for_status()
        except httpx.HTTPStatusError as e:
            raise ValueError(f"{response.status_code=} {response.text=}") from e
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
        response = client.post(
            url=f"https://api.ubank.com.au/app/v1/v2/device/{passkey.device_id}/activate",
            json={
                "attestation": json.dumps(attestation),
                "origin": origin,
                "type": "FIDO2",
            },
        )
        # Raise exception if passkey registration was unsuccessful.
        try:
            response.raise_for_status()
        except httpx.HTTPStatusError as e:
            raise ValueError(f"{response.status_code=} {response.text=}") from e
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


if __name__ == "__main__":
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
