CREATE TABLE IF NOT EXISTS WindowsLocalUserSettings (
    WindowsLocalUserSettings_ID INTEGER PRIMARY KEY,
    WindowsLocalUserIsDisabled NVARCHAR (5) NOT NULL,
    WindowsLocalUserIsDisabledAutomatically NVARCHAR (5) NOT NULL,
    WindowsLocalUserCantChangePW NVARCHAR (5) NOT NULL,
    WindowsLocalUserNeverChangedPW NVARCHAR (5) NOT NULL,
    WindowsLocalUserNeverLoggedOn NVARCHAR (5) NOT NULL,
    WindowsLocalUserPW_NeverExpires NVARCHAR (5) NOT NULL
);