from datetime import date, datetime
from decimal import Decimal
from typing import Annotated, Literal, Optional

from pydantic import BaseModel, ConfigDict, Field


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
    fromDate: date
    toDate: date
    limit: Annotated[int, Field(ge=1, le=200)]
    accountId: Optional[list[str]] = None  # list of account ids
    direction: Optional[Literal["CR", "DR"]] = None  # CR: money in or DR: money out
    excludeTransactionType: Optional[list[Literal["Pending"]]] = None
    fromAmount: Optional[float] = None
    paginationToken: Optional[str] = None  # set to nextPageId from previous response
    query: Optional[str] = None
    timezone: str = "Australia/Sydney"  # IANA time zone database identifier
    toAmount: Optional[float] = None
    spendingFootprintSubCategory: Optional[
        list[
            Literal[
                "Shopping",
                "Drink & Dine",
                "Entertainment",
                "Holiday",
                "Car & Transport",
                "Home & Bills",
                "Groceries",
                "Health & Fitness",
                "Pets",
                "Insurance",
                "Education",
                "Other",
                "Uncategorised",
                "Finance",
                "Loans & Repayments",
            ]
        ]
    ] = None


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
