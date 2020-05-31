CREATE TABLE IF NOT EXISTS Limitations (
    Limitation_ID INTEGER PRIMARY KEY,
    LimitationSummary NVARCHAR (100) NOT NULL,
    LimitationBackground NVARCHAR (500) NOT NULL,
    LimitationDetails NVARCHAR (500) NOT NULL,
    IsTestException NVARCHAR (5) NOT NULL
);