import urllib.parse

import requests


class UBankSession(requests.Session):
    """UBank API session."""

    def __init__(
        self, username, password, url_base="https://www.ubank.com.au/"
    ) -> None:
        """Returns instance of authenticated UBank API session.

        Authenticates to UBank `username` and `password`.

        Session request URLs are prepended with `url_base`.

        Example:

            ubank_session = UBankSession("user@domain.com", "password")
            ubank_session.get("/v1/ubank/accounts")
        """
        super().__init__()
        self.url_base = url_base

        # Set x-nab-key header for all session requests.
        self.headers.update({"x-nab-key": "73189799-4b8e-4215-b6aa-5e39e89bf490"})

        # GET this URL to initialise session cookies.
        self.get(url="/content/dam/ubank/mobile/")

        # Authenticate to UBank OAuth endpoint.
        response = self.post(
            "/v1/ubank/oauth/token",
            json={
                "client_id": "6937C7F1-F101-BCF1-9370-3FF02D27689E",
                "scope": "openid ubank:ekyc:manage ubank:statements:manage ubank:letters:manage ubank:payees:manage ubank:payment:manage ubank:account:eligibility cards:pin:create ubank:fraud:events",
                "username": username,
                "password": password,
                "grant_type": "password",
            },
        )

        # Set headers for subsequent requests.
        self.headers.update(
            {
                "Authorization": response.json()["access_token"],
                "x-nab-id": response.json()["x-nab-id"],
                "x-nab-csid": response.headers["csid"],
            }
        )

    def request(self, method, url, **kwargs):
        """Makes request() with `url` joined to `self.url_base`."""
        return super().request(
            method, urllib.parse.urljoin(self.url_base, url), **kwargs
        )
