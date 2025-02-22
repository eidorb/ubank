"""
ubank marimo notebook

Run:
    uv run marimo run notebook.py

Edit:
    uv run marimo edit notebook.py
"""

import marimo

__generated_with = "0.11.7"
app = marimo.App(width="medium")


@app.cell
def _():
    import marimo as mo
    return (mo,)


@app.cell
def _(mo):
    mo.md("""# ubank API Explo ~~it~~ rer""")
    return


@app.cell
def _(mo):
    uploaded_passkey = mo.ui.file(kind="area")
    username = mo.ui.text(placeholder="ubank username")
    password = mo.ui.text(placeholder="ubank password", kind="password")
    register = mo.ui.run_button(kind="success", label="Register")
    mo.md(
        f"""
        ## Authentication

        Access to ubank's API requires a passkey.
        """
    )
    return password, register, uploaded_passkey, username


@app.cell
def _(mo, password, register, uploaded_passkey, username):
    import io

    from cryptography.fernet import InvalidToken
    from httpx import HTTPStatusError

    from ubank import Passkey, add_passkey

    # stub out for testing
    # def add_passkey(username: str, password: str, passkey_name: str) -> Passkey:
    #     assert username
    #     assert passkey_name
    #     password = input("Enter security code ")
    #     return Passkey(passkey_name)

    new_passkey_file = io.BytesIO()
    if register.value:
        try:
            add_passkey(username.value, password.value, passkey_name="notebook.py").dump(
                new_passkey_file, password=password.value
            )
        except HTTPStatusError as e:
            print(f"Passkey registration failed: {e.__notes__[0]}")
    new_passkey = mo.download(
        new_passkey_file.getvalue(),
        filename="passkey.txt",
        label="passkey",
    )

    load_status = "⚪️"
    if uploaded_passkey.contents():
        try:
            Passkey.load(io.BytesIO(uploaded_passkey.contents()), password.value)
            load_status = "🟢"
        except InvalidToken:
            load_status = "🔴"

    mo.hstack(
        [
            mo.md(
                f"""
                ### Create passkey

                {register} a new {new_passkey} with ubank:

                {username} {password}


                You will be prompted for your security code.
                """
            ),
            mo.md(
                f"""
                ### Load passkey {load_status}

                Decrypt an existing passkey file with your {password}:

                {uploaded_passkey}
                """
            ),
        ],
        justify="start",
        gap=2.5,
    )
    return (
        HTTPStatusError,
        InvalidToken,
        Passkey,
        add_passkey,
        io,
        load_status,
        new_passkey,
        new_passkey_file,
    )


@app.cell
def _(mo):
    create_client = mo.ui.run_button(label="Create")

    mo.md(
        f"""
        ## API

        {create_client} an API client with your passkey.
        """
    )
    return (create_client,)


@app.cell
def _(
    InvalidToken,
    Passkey,
    create_client,
    io,
    mo,
    new_passkey_file,
    password,
    uploaded_passkey,
):
    from ubank import Client

    if create_client.value:
        try:
            with mo.status.spinner():
                passkey = Passkey.load(
                    # Coalesce bytes from uploaded or new passkey.
                    io.BytesIO(uploaded_passkey.contents() or new_passkey_file.getvalue()),
                    password.value,
                )
                client = Client(passkey)
                devices = client.get_devices(deviceUuid=passkey.device_id)
            mo.output.append(
                mo.md(
                    f"""
                    ### Devices

                    You've authenticated using passkey *{passkey.name}*.

                    The following security devices are registered with ubank:

                    {mo.ui.table([device.model_dump() for device in devices])}
                    """
                )
            )
        except InvalidToken:
            pass
    return Client, client, devices, passkey


@app.cell
def _(mo):
    get_balances = mo.ui.run_button(label="Get")

    mo.md(
        f"""
        ### Accounts

        {get_balances} account balances.
        """
    )
    return (get_balances,)


@app.cell
def _(client, get_balances, mo):
    if get_balances.value:
        with mo.status.spinner():
            bank = client.get_linked_banks().linkedBanks[0]
        mo.output.append(
            mo.tree(
                [
                    account.model_dump(include={"number", "label", "type", "balance"})
                    for account in bank.accounts
                ]
            )
        )
    return (bank,)


@app.cell
def _(mo):
    from ubank import Filter

    search_transactions = mo.ui.run_button(label="Search")
    from_date = mo.ui.date()
    to_date = mo.ui.date()
    limit = mo.ui.number(value=5)

    mo.md(
        f"""
        ### Transactions

        {search_transactions} for transactions between {from_date} and {to_date}.

        Limit the number of results to {limit}.
        """
    )
    return Filter, from_date, limit, search_transactions, to_date


@app.cell
def _(Filter, client, from_date, mo, search_transactions, to_date):
    if search_transactions.value:
        with mo.status.spinner():
            search_response = client.summarise_transactions(
                body=Filter(fromDate=from_date.value, toDate=to_date.value)
            )
        mo.output.append(
            mo.ui.table(
                search_response.model_dump(mode="json", exclude_none=True)["transactions"]
            )
        )
    return (search_response,)


if __name__ == "__main__":
    app.run()
