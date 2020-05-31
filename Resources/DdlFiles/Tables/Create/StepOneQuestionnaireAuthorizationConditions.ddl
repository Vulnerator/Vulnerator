CREATE TABLE IF NOT EXISTS StepOneQuestionnaireAuthorizationConditions (
    StepOneQuestionnaireAuthorizationCondition_ID INTEGER PRIMARY KEY ,
    StepOneQuestionnaire_ID INTEGER NOT NULL ,
    AuthorizationCondition_ID INTEGER NOT NULL ,
    UNIQUE (StepOneQuestionnaire_ID, AuthorizationCondition_ID) ON CONFLICT IGNORE ,
    FOREIGN KEY (StepOneQuestionnaire_ID) REFERENCES StepOneQuestionnaire(StepOneQuestionnaire_ID),
    FOREIGN KEY (AuthorizationCondition_ID) REFERENCES AuthorizationConditions(AuthorizationCondition_ID)
);