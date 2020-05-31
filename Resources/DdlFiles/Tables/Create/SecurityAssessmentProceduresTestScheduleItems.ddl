CREATE TABLE IF NOT EXISTS SecurityAssessmentProceduresTestScheduleItems (
    SecurityAssessmentProcedureTestScheduleItem_ID INTEGER PRIMARY KEY,
    SecurityAssessmentProcedure_ID INTEGER NOT NULL,
    TestScheduleItem_ID INTEGER NOT NULL,
    UNIQUE (SecurityAssessmentProcedure_ID, TestScheduleItem_ID) ON CONFLICT IGNORE,
    FOREIGN KEY (SecurityAssessmentProcedure_ID) REFERENCES SecurityAssessmentProcedures(SecurityAssessmentProcedure_ID),
    FOREIGN KEY (TestScheduleItem_ID) REFERENCES TestScheduleItems(TestScheduleItem_ID)
);