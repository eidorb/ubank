import argparse

from playwright._impl._api_structures import Cookie
from playwright.sync_api import sync_playwright


class UbankClient:
    def __init__(self, headless=True) -> None:
        """Initialises Playwright browser, context and page objects.

        The Playwright browser is launched in headless mode by default.
        """
        self.playwright = sync_playwright().start()
        # ubank doesn't play nice with Chromium: use Firefox.
        self.browser = self.playwright.firefox.launch(headless=headless)
        self.context = self.browser.new_context()
        self.page = self.context.new_page()

    def stop(self):
        """Stops Playwright gracefully."""
        self.context.close()
        self.browser.close()
        self.playwright.stop()

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.stop()

    def _log_in(self, username: str, password: str) -> None:
        """Performs username and password steps of log in flow."""
        self.page.goto("https://www.ubank.com.au/welcome/login/username")
        self.page.get_by_label("What's your username?").click()
        self.page.get_by_label("What's your username?").fill(username)
        self.page.get_by_label("What's your username?").press("Enter")
        self.page.get_by_label("What's your password?").click()
        self.page.get_by_label("What's your password?").fill(password)
        self.page.get_by_label("What's your password?").press("Enter")

    def log_in_with_security_code(self, username: str, password: str) -> None:
        """Logs in with username, password and security code (interactive prompt)."""
        self._log_in(username, password)
        # Trust browser and prompt for security code interactively.
        self.page.locator("label").filter(has_text="Yes").click()
        self.page.get_by_role("button", name="Next").click()
        self.page.get_by_label("Enter security code").click()
        self.page.get_by_label("Enter security code").fill(
            input("Enter security code: ")
        )
        self.page.get_by_label("Enter security code").press("Enter")
        self.page.wait_for_url("https://www.ubank.com.au/welcome/my/accounts")

    def log_in_with_trusted_cookie(
        self, username: str, password: str, cookie: Cookie
    ) -> None:
        """Logs in with username, password and trusted browser cookie."""
        # Add trusted browser cookie into browser context.
        self.context.add_cookies([cookie])  # type: ignore
        self._log_in(username, password)
        self.page.wait_for_url("https://www.ubank.com.au/welcome/my/accounts")

    def get_trusted_cookie(self) -> Cookie:
        """Returns trusted cookie from authenticated session.

        When you log in to ubank you can optionally trust the browser. This sets a cookie
        so that you don't need to perform security code verification each time you log
        in.
        """
        # Extract trusted cookie by name from browser context. It's possible the
        # cookie name differs across accounts. If so, the cookie could be identified
        # by matching its name to a pattern.
        trusted_cookie = [
            cookie
            for cookie in self.context.cookies()
            if cookie["name"] == "70484507-60ac-4c04-afac-b84c9c85e504"  # type: ignore
        ][0]
        return trusted_cookie

    def get_accounts(self) -> dict:
        """Returns response from /app/v1/accounts.

        Calls to the ubank API use heavily obfuscated Javascript. It's not clear
        how to construct the required request headers.

        Simply navigating to some pages kicks off API requests in the background.
        This method navigates to the account overview page, waits for an API request
        to the /accounts endpoint, and then returns the JSON response object.
        """
        with self.page.expect_request_finished(
            lambda request: request.method == "GET"
            and request.url.startswith("https://www.ubank.com.au/app/v1/accounts")
        ) as event:
            self.page.goto("https://www.ubank.com.au/welcome/my/accounts")
        return event.value.response().json()


if __name__ == "__main__":
    # Prints trusted cookie if run as module.
    parser = argparse.ArgumentParser(
        description="Retrieves ubank trusted browser cookie"
    )
    parser.add_argument("username")
    parser.add_argument("password")
    args = parser.parse_args()
    with UbankClient() as ubank_client:
        ubank_client.log_in_with_security_code(args.username, args.password)
        print(ubank_client.get_trusted_cookie())
