CREATE TABLE IF NOT EXISTS WindowsDomainUserSettings (
    WindowsDomainUserSettings_ID INTEGER PRIMARY KEY,
    WindowsDomainUserIsDisabled NVARCHAR (5) NOT NULL,
    WindowsDomainUserIsDisabledAutomatically NVARCHAR (5) NOT NULL,
    WindowsDomainUserCantChangePW NVARCHAR (5) NOT NULL,
    WindowsDomainUserNeverChangedPW NVARCHAR (5) NOT NULL,
    WindowsDomainUserNeverLoggedOn NVARCHAR (5) NOT NULL,
    WindowsDomainUserPW_NeverExpires NVARCHAR (5) NOT NULL
);