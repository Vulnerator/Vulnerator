CREATE TABLE IF NOT EXISTS CustomTestCases (
    CustomTestCase_ID INTEGER PRIMARY KEY,
    TestCaseName NVARCHAR (25) NOT NULL,
    TestCaseDescription NVARCHAR (500) NOT NULL,
    TestCaseBackground NVARCHAR (500) NOT NULL,
    TestCaseClassification NVARCHAR (25) NOT NULL,
    TestCaseSeverity NVARCHAR (25) NOT NULL,
    TestCaseAssessmentProcedure NVARCHAR (500) NOT NULL,
    TestCase_CCI_ID INTEGER NOT NULL,
    FOREIGN KEY (TestCase_CCI_ID) REFERENCES CCIs(CCI_ID)
);