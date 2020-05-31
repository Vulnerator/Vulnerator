CREATE TABLE IF NOT EXISTS TestScheduleItems (
    TestScheduleItem_ID INTEGER PRIMARY KEY,
    TestEvent NVARCHAR (200) NOT NULL,
    TestScheduleCategory NVARCHAR (25) NOT NULL,
    DurationInDays INTEGER NOT NULL
);