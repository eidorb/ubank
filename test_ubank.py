from base64 import urlsafe_b64encode

from cryptography.hazmat.primitives import serialization

from ubank import (
    Client,
    Passkey,
    __version__,
    int8array_to_bytes,
    parse_public_key_credential_creation_options,
    parse_public_key_credential_request_options,
    prepare_assertion,
    prepare_attestation,
)


def test_version():
    assert __version__ == "2.0.0rc1"


def test_int8array_to_bytes():
    """Tests bytes are correctly converted from Int8 to Uint8."""
    assert list(int8array_to_bytes([57, 18, 31, -66, -42, -43, -119, 90])) == [
        57,
        18,
        31,
        190,
        214,
        213,
        137,
        90,
    ]


def test_parse_public_key_credential_creation_options():
    """Tests options values are properly converted."""
    options = parse_public_key_credential_creation_options(
        '{"rp":{"id":"www.ubank.com.au","name":"www.ubank.com.au"},"user":{"id":[57,18,31,-66,-42,-43,-119,90],"displayName":"a663a471-01d67-4f5-aca3-2f9ae784c84d","name":"a663a471-01d67-4f5-aca3-2f9ae784c84d"},"challenge":[-128,-115,84,-82,90,35,20,-7,96,-121,-61,56,-59,93,-128,-37,-107,-41,37,62,-14,23,-102,23,-118,-76,-111,41,-88,36,59,36],"pubKeyCredParams":[{"type":"public-key","alg":"-7"},{"type":"public-key","alg":"-37"},{"type":"public-key","alg":"-257"}],"timeout":120000,"excludeCredentials":[{"type":"public-key","id":[57,18,31,-66,-42,-43,-119,91]}],"authenticatorSelection":{"authenticatorAttachment":"platform","residentKey":"required","requireResidentKey":true,"userVerification":"required"},"attestation":"none","extensions":{"credProps":true,"hmacCreateSecret":true}}'
    )
    assert options["publicKey"]["user"]["id"] == b"9\x12\x1f\xbe\xd6\xd5\x89Z"
    assert (
        options["publicKey"]["challenge"]
        == b"\x80\x8dT\xaeZ#\x14\xf9`\x87\xc38\xc5]\x80\xdb\x95\xd7%>\xf2\x17\x9a\x17\x8a\xb4\x91)\xa8$;$"
    )
    assert {"type": "public-key", "alg": -7} in options["publicKey"]["pubKeyCredParams"]
    # We captured the following challenge value from the wire sent back to ubank
    # (without the trailing '='). This verifies the conversion of the challenge
    # value from signed ints, to bytes and to base64 encoded bytes.
    assert (
        urlsafe_b64encode(options["publicKey"]["challenge"])
        == b"gI1UrlojFPlgh8M4xV2A25XXJT7yF5oXirSRKagkOyQ="
    )


def test_parse_public_key_credential_request_options():
    """Tests challenge value is properly converted."""
    options = parse_public_key_credential_request_options(
        '{"challenge":[-128,-115,84,-82,90,35,20,-7,96,-121,-61,56,-59,93,-128,-37,-107,-41,37,62,-14,23,-102,23,-118,-76,-111,41,-88,36,59,36],"timeout":120000,"rpId":"www.ubank.com.au","allowCredentials":[{"type":"public-key","id":[-50,90,62]},{"type":"public-key","id":[-29,89,87]}],"userVerification":"required"}'
    )
    assert (
        options["publicKey"]["challenge"]
        == b"\x80\x8dT\xaeZ#\x14\xf9`\x87\xc38\xc5]\x80\xdb\x95\xd7%>\xf2\x17\x9a\x17\x8a\xb4\x91)\xa8$;$"
    )


def test_serialize_attestation():
    """Tests bytes are converted to JSON-serializable strings."""
    attestation = {
        "id": b"VYVXb72FcRIDNpt2fYxxeCg62d_XBOdVoGqfSPGfJ5Q=",
        "rawId": b"U\x85Wo\xbd\x85q\x12\x036\x9bv}\x8cqx(:\xd9\xdf\xd7\x04\xe7U\xa0j\x9fH\xf1\x9f'\x94",
        "response": {
            "clientDataJSON": b'{"type": "webauthn.create", "challenge": "FPlgldclPvKHwzjFXYDbFw", "origin": "https://www.ubank.com.au"}',
            "attestationObject": b"\xa3cfmtdnonegattStmt\xa0hauthDataX\xa4\xf3\n\x01h\xc8E\xb5\xe5\x97>Q\x0c\xf2/\x0e\xfa\x80\x02\x9d\x15\xd6U\\\xab\x85\x9b\x0f\xbb\xfd%@^A\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00 U\x85Wo\xbd\x85q\x12\x036\x9bv}\x8cqx(:\xd9\xdf\xd7\x04\xe7U\xa0j\x9fH\xf1\x9f'\x94\xa5\x01\x02\x03& \x01!X \xc2^\x9b\x11\x87\xc1\xb9\xa3t\xae\x0bR\xe4_\x189\xbf\xfa\xba\xc8=fy\xf6!h~7\xdb0\x8a1\"X \x93\xa7\xb3\x8d\xc4\x94\xa3\xadm\xb6\xc8_\x06\xbf]\xf6\xb6B\xae\x18^\xd3\x1e\xaaA\x00\x88\x05\x9a\xc1\x06B",
        },
        "type": "public-key",
    }

    assert prepare_attestation(attestation) == {
        "id": "VYVXb72FcRIDNpt2fYxxeCg62d_XBOdVoGqfSPGfJ5Q=",
        "rawId": "VYVXb72FcRIDNpt2fYxxeCg62d/XBOdVoGqfSPGfJ5Q=",
        "response": {
            "clientDataJSON": "eyJ0eXBlIjogIndlYmF1dGhuLmNyZWF0ZSIsICJjaGFsbGVuZ2UiOiAiRlBsZ2xkY2xQdktId3pqRlhZRGJGdyIsICJvcmlnaW4iOiAiaHR0cHM6Ly93d3cudWJhbmsuY29tLmF1In0=",
            "attestationObject": "o2NmbXRkbm9uZWdhdHRTdG10oGhhdXRoRGF0YVik8woBaMhFteWXPlEM8i8O+oACnRXWVVyrhZsPu/0lQF5BAAAAAAAAAAAAAAAAAAAAAAAAAAAAIFWFV2+9hXESAzabdn2McXgoOtnf1wTnVaBqn0jxnyeUpQECAyYgASFYIMJemxGHwbmjdK4LUuRfGDm/+rrIPWZ59iFofjfbMIoxIlggk6ezjcSUo61ttshfBr9d9rZCrhhe0x6qQQCIBZrBBkI=",
        },
        "type": "public-key",
    }


def test_serialize_assertion():
    """Tests bytes are converted to JSON-serializable strings."""
    assertion = {
        "id": b"AI71FKYn9UU0GlDFWF03d7LKJu_cHdo3gJUJRao39bQ=",
        "rawId": b"\x00\x8e\xf5\x14\xa6'\xf5E4\x1aP\xc5X]7w\xb2\xca&\xef\xdc\x1d\xda7\x80\x95\tE\xaa7\xf5\xb4",
        "response": {
            "authenticatorData": b"\xf3\n\x01h\xc8E\xb5\xe5\x97>Q\x0c\xf2/\x0e\xfa\x80\x02\x9d\x15\xd6U\\\xab\x85\x9b\x0f\xbb\xfd%@^\x01\x00\x00\x00\x01",
            "clientDataJSON": b'{"type": "webauthn.get", "challenge": "gI1UrlojFPlgh8M4xV2A25XXJT7yF5oXirSRKagkOyQ", "origin": "https://www.ubank.com.au"}',
            "signature": b"0E\x02!\x00\xe0\x12>f\xe3\x11\xac\x02n\x1e\x05\xc80\x97\x99L\x89\xf6H0\x0e7qo\xb0\xafft\xf6C=\xac\x02 \x0cT\x0b @Q\xf3*\xe9-.#\x88EE\r\x16\xa7S\xbd\xd0\xbd\xb7f\xcc\xd2t\x0f \xa2/\xc8",
            "userHandle": b"9\x12\x1f\xbe\xd6\xd5\x89Z",
        },
        "type": "public-key",
    }

    assert prepare_assertion(assertion) == {
        "id": "AI71FKYn9UU0GlDFWF03d7LKJu_cHdo3gJUJRao39bQ=",
        "rawId": "AI71FKYn9UU0GlDFWF03d7LKJu/cHdo3gJUJRao39bQ=",
        "response": {
            "authenticatorData": "8woBaMhFteWXPlEM8i8O+oACnRXWVVyrhZsPu/0lQF4BAAAAAQ==",
            "clientDataJSON": "eyJ0eXBlIjogIndlYmF1dGhuLmdldCIsICJjaGFsbGVuZ2UiOiAiZ0kxVXJsb2pGUGxnaDhNNHhWMkEyNVhYSlQ3eUY1b1hpclNSS2Fna095USIsICJvcmlnaW4iOiAiaHR0cHM6Ly93d3cudWJhbmsuY29tLmF1In0=",
            "signature": "MEUCIQDgEj5m4xGsAm4eBcgwl5lMifZIMA43cW+wr2Z09kM9rAIgDFQLIEBR8yrpLS4jiEVFDRanU73QvbdmzNJ0DyCiL8g=",
            "userHandle": "ORIfvtbViVo=",
        },
        "type": "public-key",
    }


def test_passkey_serialization(tmp_path):
    """Tests passkey de/serialization."""
    passkey = Passkey(passkey_name="test")

    # Throw away attestation.
    passkey.create(
        {
            "publicKey": {
                "rp": {"name": "example org", "id": "example.org"},
                "user": {
                    "id": b"randomhandle",
                    "name": "username",
                    "displayName": "user name",
                },
                "challenge": b"arandomchallenge",
                "pubKeyCredParams": [{"alg": -7, "type": "public-key"}],
                "attestation": "none",
            }
        },
        "https://example.org",
    )
    assert passkey.sign_count == 0

    # Throw away assertion.
    passkey.get(
        {
            "publicKey": {
                "challenge": b"arandomchallenge",
                "rpId": "example.org",
            }
        },
        "https://example.org",
    )
    assert passkey.sign_count == 1

    # Set some ubank style attributes.
    passkey.device_id = "abc"
    passkey.username = "123"

    # Serialize and deserialize passkey.
    with (tmp_path / "passkey.cbor").open("wb") as f:
        passkey.dump(f)
    with (tmp_path / "passkey.cbor").open("rb") as f:
        deserialized_passkey = Passkey.load(f)

    assert deserialized_passkey.passkey_name == passkey.passkey_name
    assert deserialized_passkey.hardware_id == passkey.hardware_id
    assert deserialized_passkey.device_meta == passkey.device_meta
    assert deserialized_passkey.device_id == passkey.device_id
    assert deserialized_passkey.username == passkey.username

    assert deserialized_passkey.credential_id == passkey.credential_id
    assert deserialized_passkey.private_key != passkey.private_key
    assert deserialized_passkey.private_key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    ) == passkey.private_key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )
    assert deserialized_passkey.aaguid == passkey.aaguid
    assert deserialized_passkey.rp_id == passkey.rp_id
    assert deserialized_passkey.user_handle == passkey.user_handle
    assert deserialized_passkey.sign_count == passkey.sign_count


def test_ubank_client():
    """Tests Client using passkey loaded from file."""
    # Load passkey from file.
    with open("passkey.cbor", "rb") as f:
        passkey = Passkey.load(f)

    # Authenticate to ubank with passkey.
    with Client(passkey) as client:
        assert (
            client.get("/app/v1/accounts").json()["linkedBanks"][0]["shortBankName"]
            == "ubank"
        )
