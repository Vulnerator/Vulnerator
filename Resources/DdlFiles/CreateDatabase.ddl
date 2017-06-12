PRAGMA user_version = '1';

CREATE TABLE Accessibility 
	(
	 Accessibility_ID INTEGER PRIMARY KEY , 
	 LogicalAccess NVARCHAR (25) NOT NULL , 
	 PhysicalAccess NVARCHAR (25) NOT NULL , 
	 AvScan NVARCHAR (25) NOT NULL , 
	 DodinConnectionPeriodicity NVARCHAR (25) NOT NULL,
	 FOREIGN KEY (Accessibility_ID) REFERENCES StepOneQuestionnaire(Accessibility_ID)
	);
CREATE TABLE Accreditations 
	(
	 Accreditation_ID INTEGER PRIMARY KEY , 
	 Accreditation_Name NVARCHAR (100) NOT NULL , 
	 Accreditation_Acronym NVARCHAR (25) NOT NULL , 
	 Accreditation_eMASS_ID NVARCHAR (25) NOT NULL , 
	 IsPlatform NVARCHAR (5) , 
	 Confidentiality_ID INTEGER NOT NULL , 
	 Integrity_ID INTEGER NOT NULL , 
	 Availability_ID INTEGER NOT NULL , 
	 SystemCategorization_ID INTEGER NOT NULL , 
	 AccreditationVersion NVARCHAR (25) ,  
	 CybersafeGrade CHAR (1) , 
	 FISCAM_Applies NVARCHAR (5) , 
	 ControlSelection_ID INTEGER , 
	 HasForeignNationals NVARCHAR (5) , 
	 SystemType NVARCHAR (25) , 
	 RDTE_Zone CHAR (1) , 
	 StepOneQuestionnaire_ID INTEGER NOT NULL , 
	 SAP_ID INTEGER , 
	 PIT_Determination_ID INTEGER,
	 FOREIGN KEY (Confidentiality_ID) REFERENCES ConfidentialityLevels(Confidentiality_ID),
	 FOREIGN KEY (Integrity_ID) REFERENCES IntegrityLevels(Integrity_ID),
	 FOREIGN KEY (Availability_ID) REFERENCES AvailabilityLevels(Availability_ID),
	 FOREIGN KEY (SystemCategorization_ID) REFERENCES SystemCategorization(SystemCategorization_ID),
	 FOREIGN KEY (ControlSelection_ID) REFERENCES ControlSelection(ControlSelection_ID) ,
	 FOREIGN KEY (StepOneQuestionnaire_ID) REFERENCES StepOneQuestionnaire(StepOneQuestionnaire_ID),
	 FOREIGN KEY (SAP_ID) REFERENCES SAPs(SAP_ID),
	 FOREIGN KEY (PIT_Determination_ID) REFERENCES PIT_Determination(PIT_Determination_ID)
	);
CREATE TABLE Accreditations_IATA_Standards 
	(
	 Accreditation_ID INTEGER NOT NULL , 
	 IATA_Standard_ID INTEGER NOT NULL,
	 FOREIGN KEY (Accreditation_ID) REFERENCES Accreditations(Accreditation_ID),
	 FOREIGN KEY (IATA_Standard_ID) REFERENCES IATA_Standards(IATA_Standard_ID) 
	);
CREATE TABLE AccreditationsConnectedSystems 
	(
	 Accreditation_ID INTEGER NOT NULL , 
	 ConnectedSystem_ID INTEGER NOT NULL,
	 FOREIGN KEY (Accreditation_ID) REFERENCES Accreditations(Accreditation_ID),
	 FOREIGN KEY (ConnectedSystem_ID) REFERENCES ConnectedSystems(ConnectedSystem_ID) 
	);
CREATE TABLE AccreditationsConnections 
	(
	 Accreditation_ID INTEGER NOT NULL , 
	 Connection_ID INTEGER NOT NULL,
	 FOREIGN KEY (Accreditation_ID) REFERENCES Accreditations(Accreditation_ID),
	 FOREIGN KEY (Connection_ID) REFERENCES Connections(Connection_ID)
	);
CREATE TABLE AccreditationsContacts 
	(
	 Accreditation_ID INTEGER NOT NULL , 
	 Contact_ID INTEGER NOT NULL,
	 FOREIGN KEY (Accreditation_ID) REFERENCES Accreditations(Accreditation_ID),
	 FOREIGN KEY (Contact_ID) REFERENCES Contacts(Contact_ID) 
	);
CREATE TABLE AccreditationsNistControls 
	(
	 AccreditationsNistControls_ID INTEGER PRIMARY KEY, 
	 Accreditation_ID INTEGER NOT NULL , 
	 NIST_Control_ID INTEGER NOT NULL , 
	 IsInherited NVARCHAR (5) , 
	 InheritedFrom NVARCHAR (50) , 
	 Inheritable NVARCHAR (5) , 
	 ImplementationStatus NVARCHAR (25) , 
	 ImplementationNotes NVARCHAR (500) ,
	 FOREIGN KEY (Accreditation_ID) REFERENCES Accreditations(Accreditation_ID),
	 FOREIGN KEY (NIST_Control_ID) REFERENCES NistControls(NIST_Control_ID)
	);
CREATE TABLE AccreditationsOverlays 
	(
	 Accreditation_ID INTEGER NOT NULL , 
	 Overlay_ID INTEGER NOT NULL ,
	 FOREIGN KEY (Accreditation_ID) REFERENCES Accreditations(Accreditation_ID),
	 FOREIGN KEY (Overlay_ID) REFERENCES Overlays(Overlay_ID)
	);
CREATE TABLE AccreditationsWaivers 
	(
	 Accreditation_ID INTEGER NOT NULL , 
	 Waiver_ID INTEGER NOT NULL , 
	 WaiverGrantedDate DATE NOT NULL , 
	 WaiverExpirationDate DATE NOT NULL ,
	 FOREIGN KEY (Accreditation_ID) REFERENCES Accreditations(Accreditation_ID),
	 FOREIGN KEY (Waiver_ID) REFERENCES Waivers(Waiver_ID)
	);
CREATE TABLE AdditionalTestConsiderations 
	(
	 Consideration_ID INTEGER PRIMARY KEY, 
	 ConsiderationTitle NVARCHAR (25) , 
	 ConsiderationDetails NVARCHAR (1000) 
	);
CREATE TABLE ATC_IATC 
	(
	 ATC_ID INTEGER PRIMARY KEY , 
	 ATC_GrantedDate DATE NOT NULL , 
	 ATC_ExpirationDate DATE NOT NULL , 
	 CND_ServiceProvider NVARCHAR (25) 
	);
CREATE TABLE ATC_IATC_ATC_IATC_PendingItems 
	(
	 ATC_ID INTEGER NOT NULL , 
	 ATC_IATC_PendingItem_ID INTEGER NOT NULL ,
	 FOREIGN KEY (ATC_ID) REFERENCES ATC_IATC(ATC_ID),
	 FOREIGN KEY (ATC_IATC_PendingItem_ID) REFERENCES ATC_IATC_PendingItems(ATC_IATC_PendingItem_ID)
	);
CREATE TABLE ATC_IATC_PendingItems 
	(
	 ATC_IATC_PendingItem_ID INTEGER PRIMARY KEY , 
	 PendingItem NVARCHAR (50) NOT NULL , 
	 PendingItemDueDate DATE NOT NULL 
	);
CREATE TABLE AuthorizationConditions 
	(
	 AuthorizationCondition_ID INTEGER PRIMARY KEY , 
	 Condition NVARCHAR (500) NOT NULL , 
	 CompletionDate DATE NOT NULL , 
	 IsCompleted NVARCHAR (5) NOT NULL 
	);
CREATE TABLE AuthorizationInformation 
	(
	 AuthorizationInformation_ID INTEGER PRIMARY KEY , 
	 SecurityPlanApprovalStatus NVARCHAR (25) NOT NULL , 
	 SecurityPlanApprovalDate DATE , 
	 AuthorizationStatus NVARCHAR (25) NOT NULL , 
	 HasAuthorizationDocumentation NVARCHAR (5) NOT NULL , 
	 AssessmentCompletionDate DATE , 
	 AuthorizationDate DATE , 
	 AuthorizationTerminationDate DATE ,
	 FOREIGN KEY (AuthorizationInformation_ID) REFERENCES StepOneQuestionnaire(AuthorizationInformation_ID)
	);
CREATE TABLE AuthorizationInformation_AuthorizationConditions 
	(
	 AuthorizationInformation_ID INTEGER NOT NULL , 
	 AuthorizationCondition_ID INTEGER NOT NULL ,
	 FOREIGN KEY (AuthorizationInformation_ID) REFERENCES AuthorizationInformation(AuthorizationInformation_ID),
	 FOREIGN KEY (AuthorizationCondition_ID) REFERENCES AuthorizationConditions(AuthorizationCondition_ID)
	);
CREATE TABLE AvailabilityLevels 
	(
	 Availability_ID INTEGER PRIMARY KEY , 
	 Availability_Level NVARCHAR (25) NOT NULL 
	);
CREATE TABLE Buildings 
	(
	 Building_ID INTEGER PRIMARY KEY , 
	 RealTimeAccessControl NVARCHAR (5) NOT NULL , 
	 HVAC NVARCHAR (5) NOT NULL , 
	 RealTimeSecurityMonitoring NVARCHAR (5) NOT NULL ,
	 FOREIGN KEY (Building_ID) REFERENCES PIT_Determination(Building_ID)
	);
CREATE TABLE Business 
	(
	 Business_ID INTEGER PRIMARY KEY , 
	 MissionCriticality NVARCHAR (25) NOT NULL , 
	 GoverningMissionArea NVARCHAR (25) NOT NULL , 
	 DOD_Component NVARCHAR (25) NOT NULL , 
	 ACQ_Category NVARCHAR (25) NOT NULL , 
	 ACQ_Phase NVARCHAR (25) NOT NULL , 
	 SoftwareCategory NVARCHAR (25) NOT NULL , 
	 SystemOwnershipAndControl NVARCHAR (50) NOT NULL , 
	 OtherInformation NVARCHAR (2000) ,
	 FOREIGN KEY (Business_ID) REFERENCES StepOneQuestionnaire(Business_ID)
	);
CREATE TABLE CalibrationSystems 
	(
	 Calibration_ID INTEGER PRIMARY KEY , 
	 BuiltInCalibration NVARCHAR (5) NOT NULL , 
	 PortableCalibration NVARCHAR (5) NOT NULL ,
	 FOREIGN KEY (Calibration_ID) REFERENCES PIT_Determination(Calibration_ID)
	);
CREATE TABLE Categories 
	(
	 Category_ID INTEGER PRIMARY KEY , 
	 Category NVARCHAR (25) NOT NULL 
	);
CREATE TABLE CCIs 
	(
	 CCI_ID INTEGER PRIMARY KEY , 
	 CCI NVARCHAR (25) NOT NULL , 
	 Definition NVARCHAR (500) NOT NULL , 
	 Type NVARCHAR (25) NOT NULL,
	 CCI_Status NVARCHAR (25) NOT NULL 
	);
CREATE TABLE Certifications 
	(
	 Certification_ID INTEGER PRIMARY KEY , 
	 Certification NVARCHAR (50) NOT NULL 
	);
CREATE TABLE CombatSystems 
	(
	 CombatSystem_ID INTEGER PRIMARY KEY , 
	 CommandAndControl NVARCHAR (5) NOT NULL , 
	 CombatIdentification NVARCHAR (5) NOT NULL , 
	 RealTimeTrackManagement NVARCHAR (5) NOT NULL , 
	 ForceOrders NVARCHAR (5) NOT NULL , 
	 TroopMovement NVARCHAR (5) NOT NULL , 
	 EngagementCoordination NVARCHAR (5) NOT NULL ,
	 FOREIGN KEY (CombatSystem_ID) REFERENCES PIT_Determination(CombatSystem_ID)
	);
CREATE TABLE CommonControlPackages
	(
	 CCP_ID INTEGER PRIMARY KEY ,
	 CCAP_Name NVARCHAR (100) NOT NULL
	);
CREATE TABLE CommunicationSystems 
	(
	 CommunicationSystem_ID INTEGER PRIMARY KEY , 
	 VoiceCommunication NVARCHAR (5) NOT NULL , 
	 SatelliteCommunication NVARCHAR (5) NOT NULL , 
	 TacticalCommunication NVARCHAR (5) NOT NULL , 
	 ISDN_VTC_Systems NVARCHAR (5) NOT NULL , 
	 InterrogatorsTransponders NVARCHAR (5) NOT NULL ,
	 FOREIGN KEY (CommunicationSystem_ID) REFERENCES PIT_Determination(CommunicationSystem_ID)
	);
CREATE TABLE ConfidentialityLevels 
	(
	 Confidentiality_ID INTEGER PRIMARY KEY , 
	 Confidentiality_Level NVARCHAR (25) NOT NULL 
	);
CREATE TABLE ConnectedSystems 
	(
	 ConnectedSystem_ID INTEGER PRIMARY KEY , 
	 ConnectedSystemName NVARCHAR (100) NOT NULL , 
	 IsAuthorized NVARCHAR (5) NOT NULL 
	);
CREATE TABLE Connections 
	(
	 Connection_ID INTEGER PRIMARY KEY , 
	 Internet NVARCHAR (5) , 
	 DODIN NVARCHAR (5) , 
	 DMZ NVARCHAR (5) , 
	 VPN NVARCHAR (5) , 
	 CNSDP NVARCHAR (5) , 
	 EnterpriseServicesProvider NVARCHAR (5) 
	);
CREATE TABLE Connectivity 
	(
	 Connectivity_ID INTEGER PRIMARY KEY , 
	 Connectivity NVARCHAR (25) NOT NULL , 
	 OwnCircuit NVARCHAR (5) NOT NULL , 
	 CCSD_Number NVARCHAR (25) NOT NULL , 
	 CCSD_Location NVARCHAR (50) NOT NULL , 
	 CCSD_Support NVARCHAR (100) NOT NULL 
	);
CREATE TABLE Contacts 
	(
	 Contact_ID INTEGER PRIMARY KEY , 
	 First_Name NVARCHAR (25) NOT NULL , 
	 Last_Name NVARCHAR (50) NOT NULL , 
	 Email NVARCHAR (50) NOT NULL , 
	 Title_ID INTEGER NOT NULL , 
	 Organization_ID INTEGER NOT NULL ,
	 FOREIGN KEY (Title_ID) REFERENCES Titles(Title_ID),
	 FOREIGN KEY (Organization_ID) REFERENCES Organizations(Organization_ID)
	);
CREATE TABLE ContactsCertifications 
	(
	 Contact_ID INTEGER PRIMARY KEY , 
	 Certification_ID INTEGER NOT NULL ,
	 FOREIGN KEY (Contact_ID) REFERENCES Contacts(Contact_ID),
	 FOREIGN KEY (Certification_ID) REFERENCES Certifications(Certification_ID)
	);
CREATE TABLE ControlApplicabilityAssessment
	(
	 CAA_ID INTEGER PRIMARY KEY ,
	 CAA_Name NVARCHAR (50) NOT NULL
	);
CREATE TABLE ControlSelection 
	(
	 ControlSelection_ID INTEGER PRIMARY KEY , 
	 TierOneApplied NVARCHAR (5) NOT NULL , 
	 TierOneJustification NVARCHAR (50) NOT NULL , 
	 TierTwoApplied NVARCHAR (5) NOT NULL , 
	 TierTwoJustification NVARCHAR (50) NOT NULL , 
	 TierThreeApplied NVARCHAR (5) NOT NULL , 
	 TierThreeJustification NVARCHAR (50) NOT NULL , 
	 CNSS_1253_Applied NVARCHAR (5) NOT NULL , 
	 CNSS_1253_Justification NVARCHAR (50) NOT NULL , 
	 SpaceApplied NVARCHAR (5) NOT NULL , 
	 SpaceJustification NVARCHAR (50) NOT NULL , 
	 CDS_Applied NVARCHAR (5) NOT NULL , 
	 CDS_Justification NVARCHAR (50) , 
	 IntelligenceApplied NVARCHAR (5) NOT NULL , 
	 IntelligenceJustification NVARCHAR (50) NOT NULL , 
	 ClassifiedApplied NVARCHAR (5) NOT NULL , 
	 ClassifiedJustification NVARCHAR (50) NOT NULL , 
	 OtherApplied NVARCHAR (5) NOT NULL , 
	 OtherJustification NVARCHAR (50) NOT NULL , 
	 CompensatingControlsApplied NVARCHAR (5) NOT NULL , 
	 CompensatingControlsJustification NVARCHAR (50) NOT NULL , 
	 NA_BaselineControls NVARCHAR (5) NOT NULL , 
	 NA_BaselineControlsJustification NVARCHAR (100) NOT NULL , 
	 BaselineControlsModified NVARCHAR (5) NOT NULL , 
	 ModifiedBaselineJustification NVARCHAR (100) NOT NULL , 
	 BaselineRiskModified NVARCHAR (5) NOT NULL , 
	 BaselineRiskModificationJustification NVARCHAR (100) NOT NULL , 
	 BaselineScopeApproved NVARCHAR (5) NOT NULL , 
	 BaselineScopeJustification NVARCHAR (100) NOT NULL , 
	 InheritableControlsDefined NVARCHAR (5) NOT NULL , 
	 InheritableControlsJustification NVARCHAR (100) NOT NULL 
	);
CREATE TABLE ControlSets 
	(
	 ControlSet_ID INTEGER PRIMARY KEY , 
	 ControlSet NVARCHAR (50) NOT NULL 
	);
CREATE TABLE CustomTestCases 
	(
	 CustomTestCase_ID INTEGER PRIMARY KEY , 
	 TestCaseName NVARCHAR (25) NOT NULL , 
	 TestCaseDescription NVARCHAR (500) NOT NULL , 
	 TestCaseBackground NVARCHAR (500) NOT NULL , 
	 TestCaseClassification NVARCHAR (25) NOT NULL , 
	 TestCaseSeverity NVARCHAR (25) NOT NULL , 
	 TestCaseAssessmentProcedure NVARCHAR (500) NOT NULL , 
	 TestCase_CCI NVARCHAR (25) NOT NULL , 
	 TestCase_NIST_Control NVARCHAR (25) NOT NULL 
	);
CREATE TABLE DADMS_Networks 
	(
	 DADMS_Network_ID INTEGER PRIMARY KEY , 
	 DADMS_Network_Name NVARCHAR (50) NOT NULL 
	);
CREATE TABLE DiagnosticTestingSystems 
	(
	 DiagnosticTesting_ID INTEGER PRIMARY KEY , 
	 BuiltInTestingEquipment NVARCHAR (5) NOT NULL , 
	 PortableTestingEquipment NVARCHAR (5) NOT NULL 
	);
CREATE TABLE DitprDonNumbers 
	(
	 DITPR_DON_Number_ID INTEGER PRIMARY KEY , 
	 DITPR_DON_Number INTEGER NOT NULL 
	);
CREATE TABLE EncryptionTechniques 
	(
	 EncryptionTechnique_ID INTEGER PRIMARY KEY , 
	 EncryptionTechnique NVARCHAR (100) NOT NULL , 
	 KeyManagement NVARCHAR (500) NOT NULL 
	);
CREATE TABLE EntranceCriteria 
	(
	 EntranceCriteria_ID INTEGER PRIMARY KEY , 
	 EntranceCriteria NVARCHAR (100) NOT NULL 
	);
CREATE TABLE EnumeratedDomainUsersSettings 
	(
	 User_ID INTEGER NOT NULL , 
	 Domain_Settings_ID INTEGER NOT NULL ,
	 FOREIGN KEY (User_ID) REFERENCES EnumeratedWindowsUsers(User_ID),
	 FOREIGN KEY (Domain_Settings_ID) REFERENCES WindowsDomainUserSettings(Domain_Settings_ID)
	);
CREATE TABLE EnumeratedLocalWindowsUsersSettings 
	(
	 User_ID INTEGER NOT NULL , 
	 Local_Settings_ID INTEGER NOT NULL ,
	 FOREIGN KEY (User_ID) REFERENCES EnumeratedWindowsUsers(User_ID),
	 FOREIGN KEY (Local_Settings_ID) REFERENCES WindowsLocalUserSettings(Local_Settings_ID)
	);
CREATE TABLE EnumeratedWindowsGroups 
	(
	 Group_ID INTEGER PRIMARY KEY , 
	 Group_Name NVARCHAR (50) NOT NULL 
	);
CREATE TABLE EnumeratedWindowsGroupsUsers 
	(
	 Group_ID INTEGER NOT NULL , 
	 User_ID INTEGER NOT NULL ,
	 FOREIGN KEY (Group_ID) REFERENCES EnumeratedWindowsGroups(Group_ID),
	 FOREIGN KEY (User_ID) REFERENCES EnumeratedWindowsUsers(User_ID)
	);
CREATE TABLE EnumeratedWindowsUsers 
	(
	 User_ID INTEGER PRIMARY KEY , 
	 User_Name NVARCHAR (25) NOT NULL , 
	 Is_Guest_Account NVARCHAR (5) NOT NULL , 
	 Is_Domain_Account NVARCHAR (5) NOT NULL , 
	 Is_Local_Acount NVARCHAR (5) NOT NULL 
	);
CREATE TABLE ExitCriteria 
	(
	 ExitCriteria_ID INTEGER PRIMARY KEY , 
	 ExitCriteria NVARCHAR (100) NOT NULL 
	);
CREATE TABLE ExternalSecurityServices 
	(
	 ExternalSecurityServices_ID INTEGER PRIMARY KEY , 
	 ExternalSecurityService NVARCHAR (50) NOT NULL , 
	 ServiceDescription NVARCHAR (500) NOT NULL , 
	 SecurityRequirementsDescription NVARCHAR (500) NOT NULL , 
	 RiskDetermination NVARCHAR (100) NOT NULL 
	);
CREATE TABLE FindingTypes 
	(
	 Finding_Type_ID INTEGER PRIMARY KEY , 
	 Finding_Type NVARCHAR (25) NOT NULL 
	);
CREATE TABLE FISMA 
	(
	 FISMA_ID INTEGER PRIMARY KEY , 
	 SecurityReviewCompleted NVARCHAR (5) NOT NULL , 
	 SecurityReviewDate DATE , 
	 ContingencyPlanRequired NVARCHAR (5) NOT NULL , 
	 ContingencyPlanTested NVARCHAR (5) , 
	 ContingencyPlanTestDate DATE , 
	 PIA_Required NVARCHAR (5) NOT NULL , 
	 PIA_Date DATE , 
	 PrivacyActNoticeRequired NVARCHAR (5) NOT NULL , 
	 eAuthenticationRiskAssessmentRequired NVARCHAR (5) NOT NULL , 
	 eAuthenticationRiskAssessmentDate DATE , 
	 ReportableTo_FISMA NVARCHAR (5) NOT NULL , 
	 ReportableTo_ERS NVARCHAR (5) NOT NULL ,
	 FOREIGN KEY (FISMA_ID) REFERENCES StepOneQuestionnaire(FISMA_ID)
	);
CREATE TABLE GoverningPolicies 
	(
	 GoverningPolicy_ID INTEGER PRIMARY KEY , 
	 GoverningPolicy_Name NVARCHAR (50) 
	);
CREATE TABLE Groups 
	(
	 Group_ID INTEGER PRIMARY KEY , 
	 Group_Name NVARCHAR (50) NOT NULL UNIQUE ON CONFLICT IGNORE, 
	 Is_Accreditation NVARCHAR (5) NOT NULL , 
	 Accreditation_ID INTEGER , 
	 Organization_ID INTEGER 
	);
CREATE TABLE Groups_MitigationsOrConditions 
	(
	 MitigationOrCondition_ID INTEGER NOT NULL , 
	 Group_ID INTEGER NOT NULL ,
	 FOREIGN KEY (MitigationOrCondition_ID) REFERENCES MitigationsOrConditions(MitigationOrCondition_ID),
	 FOREIGN KEY (Group_ID) REFERENCES Groups(Group_ID)
	);
CREATE TABLE GroupsContacts 
	(
	 Group_ID INTEGER NOT NULL , 
	 Contact_ID INTEGER NOT NULL ,
	 FOREIGN KEY (Group_ID) REFERENCES Groups(Group_ID),
	 FOREIGN KEY (Contact_ID) REFERENCES Contacts(Contact_ID)
	);
CREATE TABLE Hardware 
	(
	 Hardware_ID INTEGER PRIMARY KEY , 
	 Host_Name NVARCHAR (50) UNIQUE ON CONFLICT IGNORE, 
	 FQDN NVARCHAR (100),
	 Is_Virtual_Server NVARCHAR (5) , 
	 NIAP_Level NVARCHAR (25) , 
	 Manufacturer NVARCHAR (25) , 
	 ModelNumber NVARCHAR (50) , 
	 Is_IA_Enabled NVARCHAR (5) ,  
	 SerialNumber NVARCHAR (50) ,
	 Role NVARCHAR (25),
	 LifecycleStatus_ID INTEGER ,
	 FOREIGN KEY (LifecycleStatus_ID) REFERENCES LifecycleStatuses(LifecycleStatus_ID)
	);
CREATE TABLE Hardware_MitigationsOrConditions 
	(
	 Hardware_ID INTEGER NOT NULL , 
	 MitigationOrCondition_ID INTEGER NOT NULL ,
	 FOREIGN KEY (Hardware_ID) REFERENCES Hardware(Hardware_ID),
	 FOREIGN KEY (MitigationOrCondition_ID) REFERENCES MitigationsOrConditions(MitigationOrCondition_ID)
	);
CREATE TABLE Hardware_PPS 
	(
	 Hardware_ID INTEGER NOT NULL , 
	 PPS_ID INTEGER NOT NULL , 
	 ReportInAccreditation NVARCHAR (5) , 
	 AssociatedService NVARCHAR (25) , 
	 Direction NVARCHAR (25) , 
	 BoundaryCrossed NVARCHAR (25) , 
	 DoD_Compliant NVARCHAR (5) , 
	 Classification NVARCHAR (25) ,
	 FOREIGN KEY (Hardware_ID) REFERENCES Hardware(Hardware_ID),
	 FOREIGN KEY (PPS_ID) REFERENCES PPS(PPS_ID)
	);
CREATE TABLE HardwareContacts 
	(
	 Hardware_ID INTEGER NOT NULL , 
	 Contact_ID INTEGER NOT NULL ,
	 FOREIGN KEY (Hardware_ID) REFERENCES Hardware(Hardware_ID),
	 FOREIGN KEY (Contact_ID) REFERENCES Contacts(Contact_ID)
	);
CREATE TABLE HardwareEnumeratedWindowsGroups 
	(
	 Hardware_ID INTEGER NOT NULL , 
	 Group_ID INTEGER NOT NULL ,
	 FOREIGN KEY (Hardware_ID) REFERENCES Hardware(Hardware_ID),
	 FOREIGN KEY (Group_ID) REFERENCES EnumeratedWindowsGroups(Group_ID)
	);
CREATE TABLE HardwareGroups 
	(
	 Hardware_ID INTEGER NOT NULL , 
	 Group_ID INTEGER NOT NULL ,
	 FOREIGN KEY (Hardware_ID) REFERENCES Hardware(Hardware_ID),
	 FOREIGN KEY (Group_ID) REFERENCES Groups(Group_ID)
	);
CREATE TABLE HardwareIpAddresses 
	(
	 Hardware_ID INTEGER NOT NULL , 
	 IP_Address_ID INTEGER NOT NULL ,
	 FOREIGN KEY (Hardware_ID) REFERENCES Hardware(Hardware_ID),
	 FOREIGN KEY (IP_Address_ID) REFERENCES IpAddresses(IP_Address_ID)
	);
CREATE TABLE HardwareMacAddresses 
	(
	 Hardware_ID INTEGER NOT NULL , 
	 MAC_Address_ID INTEGER NOT NULL ,
	 FOREIGN KEY (Hardware_ID) REFERENCES Hardware(Hardware_ID),
	 FOREIGN KEY (MAC_Address_ID) REFERENCES MAC_Addresses(MAC_Address_ID)
	);
CREATE TABLE HardwareLocation 
	(
	 Hardware_ID INTEGER NOT NULL , 
	 Location_ID INTEGER NOT NULL , 
	 IsBaselineLocation NVARCHAR (5) NOT NULL , 
	 IsDeploymentLocation NVARCHAR (5) NOT NULL , 
	 IsTestLocation NVARCHAR (5) NOT NULL ,
	 FOREIGN KEY (Hardware_ID) REFERENCES Hardware(Hardware_ID),
	 FOREIGN KEY (Location_ID) REFERENCES Locations(Location_ID)
	);
CREATE TABLE IA_Controls
	(
	  IA_Control_ID INTEGER PRIMARY KEY ,
	  IA_Control_Number NVARCHAR (10) NOT NULL,
	  Impact NVARCHAR (10) NOT NULL ,
	  Subject_Area NVARCHAR (50) NOT NULL ,
	  Name NVARCHAR (100) NOT NULL ,
	  Description NVARCHAR (250) NOT NULL ,
	  Threat_Vuln_Countermeasures NVARCHAR (2000) NOT NULL ,
	  General_Implementation_Guidance NVARCHAR (2000) NOT NULL ,
	  System_Specific_Guidance_Resources NVARCHAR (2000) NOT NULL
	);
CREATE TABLE IATA_Standards 
	(
	 IATA_Standard_ID INTEGER PRIMARY KEY , 
	 Standard_Title NVARCHAR (50) NOT NULL , 
	 Standard_Description NVARCHAR (1000) NOT NULL 
	);
CREATE TABLE ImpactAdjustments 
	(
	 ImpactAdjustment_ID INTEGER PRIMARY KEY , 
	 AdjustedConfidentiality NVARCHAR (25) NOT NULL , 
	 AdjustedIntegrity NVARCHAR (25) NOT NULL , 
	 AdjustedAvailability NVARCHAR (25) NOT NULL ,
	 FOREIGN KEY (ImpactAdjustment_ID) REFERENCES SystemCategorizationInformationTypes(ImpactAdjustment_ID)
	);
CREATE TABLE InformationSystemOwners 
	(
	 InformationSystemOwner_ID INTEGER NOT NULL , 
	 Contact_ID INTEGER NOT NULL ,
	 FOREIGN KEY (InformationSystemOwner_ID) REFERENCES Overview(InformationSystemOwner_ID),
	 FOREIGN KEY (Contact_ID) REFERENCES Contacts(Contact_ID)
	);
CREATE TABLE InformationTypes 
	(
	 InformationType_ID INTEGER PRIMARY KEY , 
	 InfoTypeId NVARCHAR (25) NOT NULL , 
	 InfoTypeName NVARCHAR (50) NOT NULL , 
	 BaselineConfidentiality NVARCHAR , 
	 BaselineIntegrity NVARCHAR , 
	 BaselineAvailability NVARCHAR , 
	 EnhancedConfidentiality NVARCHAR , 
	 EnhancedIntegrity NVARCHAR , 
	 EnhancedAvailability NVARCHAR 
	);
CREATE TABLE InformationTypesMissionAreas 
	(
	 InformationType_ID INTEGER NOT NULL , 
	 MissionArea_ID INTEGER NOT NULL ,
	 FOREIGN KEY (InformationType_ID) REFERENCES InformationTypes(InformationType_ID),
	 FOREIGN KEY (MissionArea_ID) REFERENCES MissionAreas(MissionArea_ID)
	);
CREATE TABLE IntegrityLevels 
	(
	 Integrity_ID INTEGER PRIMARY KEY , 
	 Integrity_Level NVARCHAR (25) NOT NULL 
	);
CREATE TABLE InterconnectedSystems 
	(
	 InterconnectedSystem_ID INTEGER PRIMARY KEY , 
	 InterconnectedSystem_Name NVARCHAR (50) NOT NULL 
	);
CREATE TABLE IP_Addresses 
	(
	 IP_Address_ID INTEGER PRIMARY KEY , 
	 IP_Address NVARCHAR (25) NOT NULL UNIQUE ON CONFLICT IGNORE 
	);
CREATE TABLE JointAuthorizationOrganizations 
	(
	 JointOrganization_ID INTEGER PRIMARY KEY , 
	 JointOrganization_Name NVARCHAR (50) NOT NULL 
	);
CREATE TABLE LifecycleStatuses 
	(
	 LifecycleStatus_ID INTEGER NOT NULL , 
	 LifecycleStatus NVARCHAR (25) NOT NULL 
	);
CREATE TABLE Limitations 
	(
	 Limitation_ID INTEGER PRIMARY KEY , 
	 LimitationSummary NVARCHAR (100) NOT NULL , 
	 LimitationBackground NVARCHAR (500) NOT NULL , 
	 LimitationDetails NVARCHAR (500) NOT NULL , 
	 IsTestException NVARCHAR (5) NOT NULL 
	);
CREATE TABLE Locations 
	(
	 Location_ID INTEGER PRIMARY KEY , 
	 Location_Name NVARCHAR (50) NOT NULL , 
	 StreetAddressOne NVARCHAR (50) NOT NULL , 
	 StreeAddressTwo NVARCHAR (50) NOT NULL , 
	 BuildingNumber NVARCHAR (25) , 
	 FloorNumber INTEGER , 
	 RoomNumber INTEGER , 
	 City NVARCHAR (25) , 
	 State NVARCHAR (25) , 
	 Country NVARCHAR (25) NOT NULL , 
	 ZipCode INTEGER , 
	 APO_FPO NVARCHAR (50) , 
	 OSS_AccreditationDate DATE , 
	 IsBaselineLocation_Global NVARCHAR (5) , 
	 IsDeploymentLocation_Global NVARCHAR (5) , 
	 IsTestLocation_Global NVARCHAR (5) 
	);
CREATE TABLE MAC_Addresses
	(
	  MAC_Address_ID INTEGER PRIMARY KEY ,
	  MAC_Address NVARCHAR (50) NOT NULL UNIQUE ON CONFLICT IGNORE
	);
CREATE TABLE MedicalTechnologies 
	(
	 MedicalTechnology_ID INTEGER PRIMARY KEY , 
	 MedicalImaging NVARCHAR (5) NOT NULL , 
	 MedicalMonitoring NVARCHAR (5) NOT NULL 
	);
CREATE TABLE MissionAreas 
	(
	 MissionArea_ID INTEGER PRIMARY KEY , 
	 MissionArea NVARCHAR (25) NOT NULL 
	);
CREATE TABLE MitigationsOrConditions 
	(
	 MitigationOrCondition_ID INTEGER PRIMARY KEY , 
	 ApplicableVulnerability NVARCHAR (25) NOT NULL,
	 MitigationText NVARCHAR (2000) NOT NULL , 
	 MitigationType NVARCHAR (25) NOT NULL , 
	 IsGlobal NVARCHAR (5) NOT NULL 
	);
CREATE TABLE NavigationTransportationSystems 
	(
	 NavigationSystem_ID INTEGER PRIMARY KEY , 
	 ShipAircraftControl NVARCHAR (5) NOT NULL , 
	 IntegratedBridge NVARCHAR (5) NOT NULL , 
	 ElectronicCharts NVARCHAR (5) NOT NULL , 
	 GPS NVARCHAR (5) NOT NULL , 
	 WSN NVARCHAR (5) NOT NULL , 
	 InertialNavigation NVARCHAR (5) NOT NULL , 
	 DeadReckoningDevice NVARCHAR (5) NOT NULL 
	);
CREATE TABLE NetworkConnectionRules 
	(
	 NetworkConnectionRule_ID INTEGER PRIMARY KEY , 
	 NewtorkConnectionName NVARCHAR (25) NOT NULL , 
	 ConnectionRule NVARCHAR (100) NOT NULL 
	);
CREATE TABLE NistControls 
	(
	 NIST_Control_ID INTEGER PRIMARY KEY , 
	 Control_Family NVARCHAR (25) NOT NULL , 
	 Control_Number INTEGER NOT NULL , 
	 Enhancement INTEGER , 
	 Control_Title NVARCHAR (50) NOT NULL , 
	 Control_Text NVARCHAR (500) NOT NULL , 
	 Supplemental_Guidance NVARCHAR (500) NOT NULL ,
	 Monitoring_Frequency NVARCHAR (10)
	);
CREATE TABLE NistControls_IATA_Standards 
	(
	 NIST_Control_ID INTEGER NOT NULL , 
	 IATA_Standard_ID INTEGER NOT NULL ,
	 FOREIGN KEY (NIST_Control_ID) REFERENCES NistControls(NIST_Control_ID),
	 FOREIGN KEY (IATA_Standard_ID) REFERENCES IATA_Standards(IATA_Standard_ID)
	);
CREATE TABLE NistControlsAvailabilityLevels 
	(
	 NIST_Control_ID INTEGER NOT NULL , 
	 Availability_ID INTEGER NOT NULL ,
	 NSS_Systems_Only NVARCHAR (10) NOT NULL,
	 FOREIGN KEY (NIST_Control_ID) REFERENCES NistControls(NIST_Control_ID),
	 FOREIGN KEY (Availability_ID) REFERENCES AvailabilityLevels(Availability_ID)
	);
CREATE TABLE NistControlsCCIs 
	(
	 NIST_Control_ID INTEGER NOT NULL , 
	 CCI_ID INTEGER NOT NULL ,
	 DOD_AssessmentProcedureMapping NVARCHAR (10),
	 ControlIndicator NVARCHAR (25) NOT NULL,
	 ImplementationGuidance NVARCHAR(1000) NOT NULL,
	 AssessmentProcedureText NVARCHAR(1000) NOT NULL,
	 FOREIGN KEY (NIST_Control_ID) REFERENCES NistControls(NIST_Control_ID),
	 FOREIGN KEY (CCI_ID) REFERENCES CCIs(CCI_ID)
	);
CREATE TABLE NistControlsCAAs
	(
	 NIST_Control_ID INTEGER NOT NULL ,
	 CAA_ID INTEGER NOT NULL ,
	 LegacyDifficulty NVARCHAR (10) NOT NULL,
	 Applicability NVARCHAR (25) NOT NULL,
	 FOREIGN KEY (NIST_Control_ID) REFERENCES NistControls(NIST_Control_ID) ,
	 FOREIGN KEY (CAA_ID) REFERENCES ControlApplicabilityAssessment(CAA_ID)
	);
CREATE TABLE NistControlsConfidentialityLevels 
	(
	 NIST_Control_ID INTEGER NOT NULL , 
	 Confidentiality_ID INTEGER NOT NULL ,
	 NSS_Systems_Only NVARCHAR (10) NOT NULL,
	 FOREIGN KEY (NIST_Control_ID) REFERENCES NistControls(NIST_Control_ID),
	 FOREIGN KEY (Confidentiality_ID) REFERENCES ConfidentialityLevels(Confidentiality_ID)
	);
CREATE TABLE NistControlsControlSets 
	(
	 NIST_Control_ID INTEGER NOT NULL , 
	 ControlSet_ID INTEGER NOT NULL ,
	 FOREIGN KEY (NIST_Control_ID) REFERENCES NistControls(NIST_Control_ID),
	 FOREIGN KEY (ControlSet_ID) REFERENCES ControlSets(ControlSet_ID)
	);
CREATE TABLE NistControlsCCPs
	(
	 NIST_Control_ID INTEGER NOT NULL ,
	 CCP_ID INTEGER NOT NULL ,
	 FOREIGN KEY (NIST_Control_ID) REFERENCES NistControls(NIST_Control_ID),
	 FOREIGN KEY (CCP_ID) REFERENCES CommonControlPackages(CCP_ID)
	);
CREATE TABLE NistControlsIntegrityLevels 
	(
	 NIST_Control_ID INTEGER NOT NULL , 
	 Integrity_ID INTEGER NOT NULL ,
	 NSS_Systems_Only NVARCHAR (10) NOT NULL,
	 FOREIGN KEY (NIST_Control_ID) REFERENCES NistControls(NIST_Control_ID),
	 FOREIGN KEY (Integrity_ID) REFERENCES IntegrityLevels(Integrity_ID)
	);
CREATE TABLE NistControlsOverlays 
	(
	 NIST_Control_ID INTEGER NOT NULL , 
	 Overlay_ID INTEGER NOT NULL ,
	 FOREIGN KEY (NIST_Control_ID) REFERENCES NistControls(NIST_Control_ID),
	 FOREIGN KEY (Overlay_ID) REFERENCES Overlays(Overlay_ID)
	);
CREATE TABLE NssQuestionnaire 
	(
	 NssQuestionnaire_ID INTEGER PRIMARY KEY , 
	 InvolvesIntelligenceActivities NVARCHAR (5) NOT NULL , 
	 InvolvesCryptoActivities NVARCHAR (5) NOT NULL , 
	 InvolvesCommandAndControl NVARCHAR (5) NOT NULL , 
	 IsMilitaryCritical NVARCHAR (5) NOT NULL , 
	 IsBusinessInfo NVARCHAR (5) NOT NULL , 
	 HasExecutiveOrderProtections NVARCHAR (5) NOT NULL , 
	 IsNss NVARCHAR (5) NOT NULL 
	);
CREATE TABLE Organizations 
	(
	 Organization_ID INTEGER PRIMARY KEY , 
	 Organization NVARCHAR (50) NOT NULL 
	);
CREATE TABLE Overlays 
	(
	 Overlay_ID INTEGER PRIMARY KEY , 
	 Overlay NVARCHAR (25) NOT NULL 
	);
CREATE TABLE Overview 
	(
	 Overview_ID INTEGER PRIMARY KEY , 
	 RegistrationType NVARCHAR (25) NOT NULL , 
	 InformationSystemOwner_ID INTEGER NOT NULL , 
	 SystemType_ID INTEGER NOT NULL , 
	 DVS_Site NVARCHAR (100) ,
	 FOREIGN KEY (Overview_ID) REFERENCES StepOneQuestionnaire(Overview_ID),
	 FOREIGN KEY (SystemType_ID) REFERENCES SystemTypes(SystemType_ID)
	);
CREATE TABLE PIT_Determination 
	(
	 PIT_Determination_ID INTEGER PRIMARY KEY , 
	 RecievesInfo NVARCHAR (5) NOT NULL , 
	 TransmitsInfo NVARCHAR (5) NOT NULL , 
	 ProcessesInfo NVARCHAR (5) NOT NULL , 
	 StoresInfo NVARCHAR (5) NOT NULL , 
	 DisplaysInfo NVARCHAR (5) NOT NULL , 
	 EmbeddedInSpecialPurpose NVARCHAR (5) NOT NULL , 
	 IsDedicatedSpecialPurposeSystem NVARCHAR (5) NOT NULL , 
	 IsEssentialSpecialPurposeSystem NVARCHAR (5) NOT NULL , 
	 PerformsGeneralServices NVARCHAR (5) NOT NULL , 
	 WeaponsSystem_ID INTEGER , 
	 TrainingSimulation_ID INTEGER , 
	 DiagnosticTesting_ID INTEGER , 
	 Calibration_ID INTEGER , 
	 ResearchWeaponsSystem_ID INTEGER , 
	 MedicalTechnology_ID INTEGER , 
	 NavigationSystem_ID INTEGER , 
	 Building_ID INTEGER , 
	 UtilityDistribution_ID INTEGER , 
	 CommunicationSystem_ID INTEGER , 
	 CombatSystem_ID INTEGER , 
	 SpecialPurposeConsole_ID INTEGER , 
	 Sensor_ID INTEGER , 
	 TacticalSupportDatabase_ID INTEGER , 
	 IsTacticalDecisionAid NVARCHAR (5) , 
	 OtherSystemTypeDescription NVARCHAR (100) ,
	 FOREIGN KEY (PIT_Determination_ID) REFERENCES Accreditations(PIT_Determination_ID)
	);
CREATE TABLE PPS 
	(
	 PPS_ID INTEGER PRIMARY KEY , 
	 Port INTEGER NOT NULL , 
	 Protocol NVARCHAR (25) NOT NULL 
	);
CREATE TABLE RelatedDocuments 
	(
	 RelatedDocument_ID INTEGER PRIMARY KEY , 
	 RelatedDocumentName NVARCHAR (50) NOT NULL , 
	 RelationshipDescription NVARCHAR (100) NOT NULL 
	);
CREATE TABLE RelatedTesting 
	(
	 RelatedTesting_ID INTEGER PRIMARY KEY , 
	 TestTitle NVARCHAR (50) NOT NULL , 
	 DateConducted DATE NOT NULL , 
	 RelatedSystemTested NVARCHAR (50) NOT NULL , 
	 ResponsibleOrganization NVARCHAR (100) NOT NULL , 
	 TestingImpact NVARCHAR (500) NOT NULL 
	);
CREATE TABLE ResearchWeaponsSystems 
	(
	 ResearchWeaponsSystem_ID INTEGER PRIMARY KEY , 
	 RDTE_Network NVARCHAR (5) NOT NULL , 
	 RDTE_ConnectedSystem NVARCHAR (5) NOT NULL ,
	 FOREIGN KEY (ResearchWeaponsSystem_ID) REFERENCES PIT_Determination(ResearchWeaponsSystem_ID)
	);
CREATE TABLE ResponsibilityRoles
	(
	  Role_ID INTEGER PRIMARY KEY ,
	  Role_Title NVARCHAR (25) NOT NULL
	);
CREATE TABLE SAP_AdditionalTestConsiderations 
	(
	 SAP_ID INTEGER NOT NULL , 
	 Consideration_ID INTEGER NOT NULL ,
	 FOREIGN KEY (SAP_ID) REFERENCES SAPs(SAP_ID),
	 FOREIGN KEY (Consideration_ID) REFERENCES AdditionalTestConsiderations(Consideration_ID)
	);
CREATE TABLE SAP_CustomTestCases 
	(
	 SAP_ID INTEGER NOT NULL , 
	 CustomTestCase_ID INTEGER NOT NULL ,
	 FOREIGN KEY (SAP_ID) REFERENCES SAPs(SAP_ID),
	 FOREIGN KEY (CustomTestCase_ID) REFERENCES CustomTestCases(CustomTestCase_ID)
	);
CREATE TABLE SAP_EntranceCriteria 
	(
	 SAP_ID INTEGER NOT NULL , 
	 EntranceCriteria_ID INTEGER NOT NULL ,
	 FOREIGN KEY (SAP_ID) REFERENCES SAPs(SAP_ID),
	 FOREIGN KEY (EntranceCriteria_ID) REFERENCES EntranceCriteria(EntranceCriteria_ID)
	);
CREATE TABLE SAP_ExitCriteria 
	(
	 SAP_ID INTEGER NOT NULL , 
	 ExitCriteria_ID INTEGER NOT NULL ,
	 FOREIGN KEY (SAP_ID) REFERENCES SAPs(SAP_ID),
	 FOREIGN KEY (ExitCriteria_ID) REFERENCES ExitCriteria(ExitCriteria_ID)
	);
CREATE TABLE SAP_Limitiations 
	(
	 SAP_ID INTEGER NOT NULL , 
	 Limitation_ID INTEGER NOT NULL ,
	 FOREIGN KEY (SAP_ID) REFERENCES SAPs(SAP_ID),
	 FOREIGN KEY (Limitation_ID) REFERENCES Limitations(Limitation_ID)
	);
CREATE TABLE SAP_RelatedDocuments 
	(
	 SAP_ID INTEGER NOT NULL , 
	 RelatedDocument_ID INTEGER NOT NULL ,
	 FOREIGN KEY (SAP_ID) REFERENCES SAPs(SAP_ID),
	 FOREIGN KEY (RelatedDocument_ID) REFERENCES RelatedDocuments(RelatedDocument_ID)
	);
CREATE TABLE SAP_RelatedTesting 
	(
	 SAP_ID INTEGER NOT NULL , 
	 RelatedTesting_ID INTEGER NOT NULL,
	 FOREIGN KEY (SAP_ID) REFERENCES SAPs(SAP_ID),
	 FOREIGN KEY (RelatedTesting_ID) REFERENCES RelatedTesting(RelatedTesting_ID) 
	);
CREATE TABLE SAP_TestReferences 
	(
	 SAP_ID INTEGER NOT NULL , 
	 TestReference_ID INTEGER NOT NULL ,
	 FOREIGN KEY (SAP_ID) REFERENCES SAPs(SAP_ID),
	 FOREIGN KEY (TestReference_ID) REFERENCES TestReferences(TestReference_ID)
	);
CREATE TABLE SAP_TestScheduleItems 
	(
	 SAP_ID INTEGER NOT NULL , 
	 TestScheduleItem_ID INTEGER NOT NULL ,
	 FOREIGN KEY (SAP_ID) REFERENCES SAPs(SAP_ID),
	 FOREIGN KEY (TestScheduleItem_ID) REFERENCES TestScheduleItems(TestScheduleItem_ID)
	);
CREATE TABLE SAPs 
	(
	 SAP_ID INTEGER PRIMARY KEY , 
	 Scope NVARCHAR (50) NOT NULL , 
	 Limitations NVARCHAR (500) NOT NULL , 
	 TestConfiguration NVARCHAR (2000) NOT NULL , 
	 LogisiticsSupport NVARCHAR (1000) NOT NULL , 
	 Security NVARCHAR (1000) NOT NULL ,
	 FOREIGN KEY (SAP_ID) REFERENCES Accreditations(SAP_ID)
	);
CREATE TABLE ScapScores 
	(
	 SCAP_Score_ID INTEGER PRIMARY KEY , 
	 Score INTEGER NOT NULL , 
	 Hardware_ID INTEGER NOT NULL , 
	 Source_ID INTEGER NOT NULL ,
	 FOREIGN KEY (Hardware_ID) REFERENCES Hardware(Hardware_ID),
	 FOREIGN KEY (Source_ID) REFERENCES VulnerabilitySources(Source_ID)
	);
CREATE TABLE Sensors 
	(
	 Sensor_ID INTEGER PRIMARY KEY , 
	 RADAR NVARCHAR (5) NOT NULL , 
	 Acoustic NVARCHAR (5) NOT NULL , 
	 VisualAndImaging NVARCHAR (5) NOT NULL , 
	 RemoteVehicle NVARCHAR (5) NOT NULL , 
	 PassiveElectronicWarfare NVARCHAR (5) NOT NULL , 
	 ISR NVARCHAR (5) NOT NULL , 
	 National NVARCHAR (5) NOT NULL , 
	 NavigationAndControl NVARCHAR (5) NOT NULL ,
	 FOREIGN KEY (Sensor_ID) REFERENCES PIT_Determination(Sensor_ID)
	);
CREATE TABLE Software 
	(
	 Software_ID INTEGER PRIMARY KEY , 
	 Software_Name NVARCHAR (50) NOT NULL , 
	 Software_Acronym NVARCHAR (25) , 
	 Software_Version NVARCHAR (25) , 
	 Function NVARCHAR (500) , 
	 Install_Date DATE , 
	 DADMS_ID INTEGER , 
	 DADMS_Disposition NVARCHAR (25) , 
	 DADMS_LDA DATE , 
	 Has_Custom_Code NVARCHAR (5) , 
	 IaOrIa_Enabled NVARCHAR (5) , 
	 Is_OS_Or_Firmware NVARCHAR (5) , 
	 FAM_Accepted NVARCHAR (5) , 
	 Externally_Authorized NVARCHAR (5) , 
	 ReportInAccreditation_Global NVARCHAR (5) , 
	 ApprovedForBaseline_Global NVARCHAR (5) , 
	 BaselineApprover_Global NVARCHAR (50) , 
	 Instance NVARCHAR (25)
	);
CREATE TABLE Software_DADMS_Networks 
	(
	 Software_ID INTEGER NOT NULL , 
	 DADMS_Network_ID INTEGER NOT NULL ,
	 FOREIGN KEY (Software_ID) REFERENCES Software(Software_ID),
	 FOREIGN KEY (DADMS_Network_ID) REFERENCES DADMS_Networks(DADMS_Network_ID)
	);
CREATE TABLE SoftwareContacts 
	(
	 Software_ID INTEGER NOT NULL , 
	 Contact_ID INTEGER NOT NULL ,
	 FOREIGN KEY (Software_ID) REFERENCES Software(Software_ID),
	 FOREIGN KEY (Contact_ID) REFERENCES Contacts(Contact_ID)
	);
CREATE TABLE SoftwareHardware 
	(
	 Software_ID INTEGER NOT NULL , 
	 Hardware_ID INTEGER NOT NULL , 
	 ReportInAccreditation NVARCHAR (5) , 
	 ApprovedForBaseline NVARCHAR (5) , 
	 BaselineApprover NVARCHAR (50) ,
	 FOREIGN KEY (Software_ID) REFERENCES Software(Software_ID),
	 FOREIGN KEY (Hardware_ID) REFERENCES Hardware(Hardware_ID)
	);
CREATE TABLE SpecialPurposeConsoles 
	(
	 SpecialPurposeConsole_ID INTEGER PRIMARY KEY , 
	 WarFighting NVARCHAR (5) NOT NULL , 
	 InputOutputConsole NVARCHAR (5) NOT NULL ,
	 FOREIGN KEY (SpecialPurposeConsole_ID) REFERENCES PIT_Determination(SpecialPurposeConsole_ID)
	);
CREATE TABLE StepOneQuestionnaire 
	(
	 StepOneQuestionnaire_ID INTEGER PRIMARY KEY , 
	 SystemDescription NVARCHAR (2000) NOT NULL , 
	 MissionDescription NVARCHAR (2000) NOT NULL , 
	 CONOPS_Statement NVARCHAR (2000) NOT NULL , 
	 IsTypeAuthorization NVARCHAR (5) NOT NULL , 
	 RMF_Activity NVARCHAR (25) NOT NULL , 
	 Accessibility_ID INTEGER NOT NULL , 
	 Overview_ID INTEGER NOT NULL , 
	 PPSM_RegistrationNumber NVARCHAR (25) NOT NULL , 
	 AuthorizationInformation_ID INTEGER NOT NULL , 
	 FISMA_ID INTEGER NOT NULL , 
	 Business_ID INTEGER NOT NULL , 
	 SystemEnterpriseArchitecture NVARCHAR (2000) NOT NULL , 
	 ATC_ID INTEGER , 
	 NistControlSet NVARCHAR (50) NOT NULL ,
	 FOREIGN KEY (StepOneQuestionnaire_ID) REFERENCES Accreditations(StepOneQuestionnaire_ID)
	);
CREATE TABLE StepOneQuestionnaire_Connectivity 
	(
	 StepOneQuestionnaire_ID INTEGER NOT NULL , 
	 Connectivity_ID INTEGER NOT NULL ,
	 FOREIGN KEY (StepOneQuestionnaire_ID) REFERENCES StepOneQuestionnaire(StepOneQuestionnaire_ID),
	 FOREIGN KEY (Connectivity_ID) REFERENCES Connectivity(Connectivity_ID)
	);
CREATE TABLE StepOneQuestionnaire_DitprDonNumbers 
	(
	 StepOneQuestionnaire_ID INTEGER NOT NULL , 
	 DITPR_DON_Number_ID INTEGER NOT NULL ,
	 FOREIGN KEY (StepOneQuestionnaire_ID) REFERENCES StepOneQuestionnaire(StepOneQuestionnaire_ID),
	 FOREIGN KEY (DITPR_DON_Number_ID) REFERENCES DitprDonNumbers(DITPR_DON_Number_ID)
	);
CREATE TABLE StepOneQuestionnaire_ExternalSecurityServices 
	(
	 StepOneQuestionnaire_ID INTEGER NOT NULL , 
	 ExternalSecurityServices_ID INTEGER NOT NULL ,
	 FOREIGN KEY (StepOneQuestionnaire_ID) REFERENCES StepOneQuestionnaire(StepOneQuestionnaire_ID),
	 FOREIGN KEY (ExternalSecurityServices_ID) REFERENCES ExternalSecurityServices(ExternalSecurityServices_ID)
	);
CREATE TABLE StepOneQuestionnaireEncryptionTechniques 
	(
	 StepOneQuestionnaire_ID INTEGER NOT NULL , 
	 EncryptionTechnique_ID INTEGER NOT NULL ,
	 FOREIGN KEY (StepOneQuestionnaire_ID) REFERENCES StepOneQuestionnaire(StepOneQuestionnaire_ID),
	 FOREIGN KEY (EncryptionTechnique_ID) REFERENCES EncryptionTechnique(EncryptionTechnique_ID)
	);
CREATE TABLE StepOneQuestionnaireNetworkConnectionRules 
	(
	 StepOneQuestionnaire_ID INTEGER NOT NULL , 
	 NetworkConnectionRule_ID INTEGER NOT NULL ,
	 FOREIGN KEY (StepOneQuestionnaire_ID) REFERENCES StepOneQuestionnaire(StepOneQuestionnaire_ID),
	 FOREIGN KEY (NetworkConnectionRule_ID) REFERENCES NetworkConnectionRules(NetworkConnectionRule_ID)
	);
CREATE TABLE StepOneQuestionnaireUserCategories 
	(
	 StepOneQuestionnaire_ID INTEGER NOT NULL , 
	 UserCategory_ID INTEGER NOT NULL ,
	 FOREIGN KEY (StepOneQuestionnaire_ID) REFERENCES StepOneQuestionnaire(StepOneQuestionnaire_ID),
	 FOREIGN KEY (UserCategory_ID) REFERENCES UserCategories(UserCategory_ID)
	);
CREATE TABLE SystemCategorization 
	(
	 SystemCategorization_ID INTEGER PRIMARY KEY , 
	 SystemClassification NVARCHAR (25) NOT NULL , 
	 InformationClassification NVARCHAR (25) NOT NULL , 
	 InformationReleasability NVARCHAR (25) NOT NULL , 
	 HasGoverningPolicy NVARCHAR (5) NOT NULL , 
	 VaryingClearanceRequirements NVARCHAR (5) NOT NULL , 
	 ClearanceRequirementDescription NVARCHAR (500) , 
	 HasAggergationImpact NVARCHAR (5) NOT NULL , 
	 IsJointAuthorization NVARCHAR (5) NOT NULL , 
	 NssQuestionnaire_ID INTEGER NOT NULL , 
	 CategorizationIsApproved NVARCHAR (5) NOT NULL ,
	 FOREIGN KEY (SystemCategorization_ID) REFERENCES Accreditations(SystemCategorization_ID)
	);
CREATE TABLE SystemCategorizationGoverningPolicies 
	(
	 SystemCategorization_ID INTEGER NOT NULL , 
	 GoverningPolicy_ID INTEGER NOT NULL ,
	 FOREIGN KEY (SystemCategorization_ID) REFERENCES SystemCategorization(SystemCategorization_ID),
	 FOREIGN KEY (GoverningPolicy_ID) REFERENCES GoverningPolicies(GoverningPolicy_ID)
	);
CREATE TABLE SystemCategorizationInformationTypes 
	(
	 SystemCategorizationInformationTypes_ID INTEGER NOT NULL , 
	 SystemCategorization_ID INTEGER NOT NULL , 
	 Description NVARCHAR (500) NOT NULL , 
	 InformationType_ID INTEGER NOT NULL , 
	 ImpactAdjustment_ID INTEGER NOT NULL ,
	 FOREIGN KEY (SystemCategorization_ID) REFERENCES SystemCategorization(SystemCategorization_ID),
	 FOREIGN KEY (InformationType_ID) REFERENCES InformationTypes(InformationType_ID)
	);
CREATE TABLE SystemCategorizationInterconnectedSystems 
	(
	 SystemCategorization_ID INTEGER NOT NULL , 
	 InterconnectedSystem_ID INTEGER NOT NULL ,
	 FOREIGN KEY (SystemCategorization_ID) REFERENCES SystemCategorization(SystemCategorization_ID),
	 FOREIGN KEY (InterconnectedSystem_ID) REFERENCES InterconnectedSystems(InterconnectedSystem_ID)
	);
CREATE TABLE SystemCategorizationJointOrganizations 
	(
	 SystemCategorization_ID INTEGER NOT NULL , 
	 JointOrganization_ID INTEGER NOT NULL ,
	 FOREIGN KEY (SystemCategorization_ID) REFERENCES SystemCategorization(SystemCategorization_ID),
	 FOREIGN KEY (JointOrganization_ID) REFERENCES JointAuthorizationOrganizations(JointOrganization_ID)
	);
CREATE TABLE SystemTypes 
	(
	 SystemType_ID INTEGER PRIMARY KEY , 
	 SystemType NVARCHAR (100) NOT NULL 
	);
CREATE TABLE TacticalSupportDatabases 
	(
	 TacticalSupportDatabase_ID INTEGER PRIMARY KEY , 
	 ElectronicWarfare NVARCHAR (5) NOT NULL , 
	 Intelligence NVARCHAR (5) NOT NULL , 
	 Environmental NVARCHAR (5) NOT NULL , 
	 Acoustic NVARCHAR (5) NOT NULL , 
	 Geographic NVARCHAR (5) NOT NULL ,
	 FOREIGN KEY (TacticalSupportDatabase_ID) REFERENCES PIT_Determination(TacticalSupportDatabase_ID)
	);
CREATE TABLE TestReferences 
	(
	 TestReference_ID INTEGER PRIMARY KEY , 
	 TestReferenceName NVARCHAR (100) 
	);
CREATE TABLE TestScheduleItems 
	(
	 TestScheduleItem_ID INTEGER PRIMARY KEY , 
	 TestEvent NVARCHAR (100) , 
	 Category_ID INTEGER NOT NULL , 
	 DurationInDays INTEGER NOT NULL 
	);
CREATE TABLE Titles 
	(
	 Title_ID INTEGER PRIMARY KEY , 
	 Title NVARCHAR (25) NOT NULL 
	);
CREATE TABLE TrainingSimulationSystems 
	(
	 TrainingSimulation_ID INTEGER PRIMARY KEY , 
	 FlightSimulator NVARCHAR (5) NOT NULL , 
	 BridgeSimulator NVARCHAR (5) NOT NULL , 
	 ClassroomNetworkOther NVARCHAR (5) NOT NULL , 
	 EmbeddedTactical NVARCHAR (5) NOT NULL ,
	 FOREIGN KEY (TrainingSimulation_ID) REFERENCES PIT_Determination(TrainingSimulation_ID)
	);
CREATE TABLE UniqueFindings 
	(
	 Unique_Finding_ID INTEGER PRIMARY KEY , 
	 Tool_Generated_Output NVARCHAR , 
	 Comments NVARCHAR , 
	 Finding_Details NVARCHAR , 
	 Technical_Mitigation NVARCHAR (2000) , 
	 Proposed_Mitigation NVARCHAR (2000) , 
	 Predisposing_Conditions NVARCHAR (2000) , 
	 Impact NVARCHAR (25) , 
	 Likelihood NVARCHAR (25) , 
	 Severity NVARCHAR (25) , 
	 Risk NVARCHAR (25) , 
	 Residual_Risk NVARCHAR (25) , 
	 First_Discovered DATE NOT NULL, 
	 Last_Observed DATE NOT NULL, 
	 Approval_Status NVARCHAR (5) NOT NULL, 
	 Data_Entry_Date DATE , 
	 Data_Expiration_Date DATE , 
	 Delta_Analysis_Required NVARCHAR (5) NOT NULL , 
	 Finding_Type_ID INTEGER NOT NULL , 
	 Finding_Source_File_ID INTEGER NOT NULL , 
	 Status NVARCHAR (25) NOT NULL , 
	 Vulnerability_ID INTEGER NOT NULL , 
	 Hardware_ID INTEGER NOT NULL ,
	 Severity_Override NVARCHAR (25),
	 Severity_Override_Justification NVARCHAR (2000),
	 Technology_Area NVARCHAR (100),
	 Web_DB_Site NVARCHAR(500),
	 Web_DB_Instance NVARCHAR(100),
	 Classification NVARCHAR (25),
	 FOREIGN KEY (Finding_Type_ID) REFERENCES FindingTypes(Finding_Type_ID),
	 FOREIGN KEY (Vulnerability_ID) REFERENCES Vulnerabilities(Vulnerability_ID),
	 FOREIGN KEY (Hardware_ID) REFERENCES Hardware(Hardware_ID),
	 FOREIGN KEY (Finding_Source_File_ID) REFERENCES UniqueFindingsSourceFiles(Finding_Source_File_ID)
	);
CREATE INDEX Unique_Finding_Index ON UniqueFindings(Unique_Finding_ID);
CREATE TABLE UniqueFindings_UniqueFindingsSourceFiles 
	(
	  Unique_Finding_ID INTEGER NOT NULL ,
	  Finding_Source_File_ID INTEGER NOT NULL ,
	  FOREIGN KEY (Unique_Finding_ID) REFERENCES UniqueFindings(Unique_Finding_ID),
	  FOREIGN KEY (Finding_Source_File_ID) REFERENCES UniqueFindingsSourceFiles(Finding_Source_File_ID)
	);
CREATE TABLE UniqueFindingsSourceFiles 
	(
	 Finding_Source_File_ID INTEGER PRIMARY KEY , 
	 Finding_Source_File_Name NVARCHAR (500) NOT NULL UNIQUE ON CONFLICT IGNORE 
	);
CREATE TABLE UserCategories 
	(
	 UserCategory_ID INTEGER PRIMARY KEY , 
	 UserCategory NVARCHAR (25) 
	);
CREATE TABLE UtilityDistribution 
	(
	 UtilityDistribution_ID INTEGER PRIMARY KEY , 
	 SCADA NVARCHAR (5) NOT NULL , 
	 UtilitiesEngineering NVARCHAR (5) NOT NULL , 
	 MeteringAndControl NVARCHAR (5) NOT NULL , 
	 MechanicalMonitoring NVARCHAR (5) NOT NULL , 
	 DamageControlMonitoring NVARCHAR (5) NOT NULL ,
	 FOREIGN KEY (UtilityDistribution_ID) REFERENCES PIT_Determination(UtilityDistribution_ID)
	);
CREATE TABLE VulnerabilitesCCIs 
	(
	 Vulnerability_ID INTEGER NOT NULL , 
	 CCI_ID INTEGER NOT NULL ,
	 PRIMARY KEY (Vulnerability_ID, CCI_ID) ,
	 FOREIGN KEY (Vulnerability_ID) REFERENCES Vulnerabilities(Vulnerability_ID),
	 FOREIGN KEY (CCI_ID) REFERENCES CCIs(CCI_ID)
	);
CREATE TABLE Vulnerabilites_IA_Controls 
	(
	 Vulnerability_ID INTEGER NOT NULL , 
	 IA_Control_ID INTEGER NOT NULL ,
	 FOREIGN KEY (Vulnerability_ID) REFERENCES Vulnerabilities(Vulnerability_ID),
	 FOREIGN KEY (IA_Control_ID) REFERENCES IA_Controls(IA_Control_ID)
	);
CREATE TABLE Vulnerabilities 
	(
	 Vulnerability_ID INTEGER PRIMARY KEY , 
	 Unique_Vulnerability_Identifier NVARCHAR (50) UNIQUE ON CONFLICT IGNORE NOT NULL,
	 Vulnerability_Group_ID NVARCHAR (25) , 
	 Vulnerability_Group_Title NVARCHAR (100) ,
	 Secondary_Vulnerability_Identifier NVARCHAR (25),
	 VulnerabilityFamilyOrClass NVARCHAR (100) , 
	 Version NVARCHAR (25) , 
	 Release NVARCHAR (25) , 
	 Vulnerability_Title NVARCHAR (100) NOT NULL , 
	 Description NVARCHAR , 
	 Risk_Statement NVARCHAR , 
	 Fix_Text NVARCHAR , 
	 Published_Date DATE , 
	 Modified_Date DATE , 
	 Fix_Published_Date DATE , 
	 Raw_Risk NVARCHAR (25) NOT NULL , 
	 Check_Content NVARCHAR (2000),
	 False_Positives NVARCHAR (2000),
	 False_Negatives NVARCHAR (2000),
	 Documentable NVARCHAR (5),
	 Mitigations NVARCHAR (2000),
	 Mitigation_Control NVARCHAR (2000),
	 Potential_Impacts NVARCHAR (2000),
	 Third_Party_Tools NVARCHAR (500),
	 Security_Override_Guidance NVARCHAR (2000) ,
	 Overflow NVARCHAR (2000)
	);
CREATE INDEX Vulnerability_Index ON Vulnerabilities(Vulnerability_ID);
CREATE TABLE Vulnerbailities_RoleResponsibilities
	(
	  Vulnerability_ID INTEGER NOT NULL ,
	  Role_ID INTEGER NOT NULL ,
	  PRIMARY KEY (Vulnerability_ID, Role_ID) ,
	  FOREIGN KEY (Vulnerability_ID) REFERENCES Vulnerabilities(Vulnerability_ID),
	  FOREIGN KEY (Role_ID) REFERENCES ResponsibilityRoles(Role_ID)
	);
CREATE TABLE Vulnerabilities_VulnerabilitySources 
	(
	  Vulnerability_ID INTEGER NOT NULL , 
	  Vulnerability_Source_ID INTEGER NOT NULL ,
	  PRIMARY KEY (Vulnerability_ID, Vulnerability_Source_ID) ,
	  FOREIGN KEY (Vulnerability_ID) REFERENCES Vulnerabilities(Vulnerability_ID),
	  FOREIGN KEY (Vulnerability_Source_ID) REFERENCES VulnerabilitySources(Vulnerability_Source_ID)
	);
CREATE TABLE Vulnerabilities_VulnerabilityReferences
	(
		Vulnerability_ID INTEGER NOT NULL,
		Reference_ID INTEGER NOT NULL,
		FOREIGN KEY (Vulnerability_ID) REFERENCES Vulnerabilities(Vulnerability_ID),
		FOREIGN KEY (Reference_ID) REFERENCES VulnerabilityReferences(Reference_ID)
	);
CREATE TABLE VulnerabilityReferences
	(
		Reference_ID INTEGER PRIMARY KEY,
		Reference NVARCHAR (50) UNIQUE ON CONFLICT IGNORE,
		Reference_Type NVARCHAR (25)
	);
CREATE TABLE VulnerabilitySources 
	(
	 Vulnerability_Source_ID INTEGER PRIMARY KEY , 
	 Source_Name NVARCHAR (100) UNIQUE ON CONFLICT IGNORE NOT NULL, 
	 Source_Secondary_Identifier NVARCHAR (100) UNIQUE ON CONFLICT IGNORE,
	 Vulnerability_Source_File_Name NVARCHAR (500) ,
	 Source_Description NVARCHAR (2000) ,
	 Source_Version NVARCHAR (25) NOT NULL, 
	 Source_Release NVARCHAR (25) NOT NULL
	);
CREATE INDEX Vulnerability_Source_Index ON VulnerabilitySources(Vulnerability_Source_ID);
CREATE TABLE VulnerabilitySourcesSoftware 
	(
	 Source_ID INTEGER NOT NULL , 
	 Software_ID INTEGER NOT NULL ,
	 FOREIGN KEY (Source_ID) REFERENCES VulnerabilitySources(Source_ID),
	 FOREIGN KEY (Software_ID) REFERENCES Software(Software_ID)
	);
CREATE TABLE Waivers 
	(
	 Waiver_ID INTEGER PRIMARY KEY , 
	 Waiver_Name NVARCHAR (100) NOT NULL 
	);
CREATE TABLE WeaponsSystems 
	(
	 WeaponsSystem_ID INTEGER PRIMARY KEY , 
	 FireControlAndTargeting NVARCHAR (5) NOT NULL , 
	 Missile NVARCHAR (5) NOT NULL , 
	 Gun NVARCHAR (5) NOT NULL , 
	 Torpedoes NVARCHAR (5) NOT NULL , 
	 ActiveElectronicWarfare NVARCHAR (5) NOT NULL , 
	 Launchers NVARCHAR (5) NOT NULL , 
	 Decoy NVARCHAR (5) NOT NULL , 
	 Vehicles NVARCHAR (5) NOT NULL , 
	 Tanks NVARCHAR (5) NOT NULL , 
	 Artillery NVARCHAR (5) NOT NULL , 
	 ManDeployableWeapons NVARCHAR (5) NOT NULL ,
	 FOREIGN KEY (WeaponsSystem_ID) REFERENCES PIT_Determination(WeaponsSystem_ID)
	);
CREATE TABLE WindowsDomainUserSettings 
	(
	 Domain_Settings_ID INTEGER PRIMARY KEY , 
	 Domain_Is_Disabled NVARCHAR (5) NOT NULL , 
	 Domain_Is_Disabled_Automatically NVARCHAR (5) NOT NULL , 
	 Domain_Cant_Change_PW NVARCHAR (5) NOT NULL , 
	 Domain_Never_Changed_PW NVARCHAR (5) NOT NULL , 
	 Domain_Never_Logged_On NVARCHAR (5) NOT NULL , 
	 Domain_PW_Never_Expires NVARCHAR (5) NOT NULL 
	);
CREATE TABLE WindowsLocalUserSettings 
	(
	 Local_Settings_ID INTEGER PRIMARY KEY , 
	 Local_Is_Disabled NVARCHAR (5) NOT NULL , 
	 Local_Is_Disabled_Automatically NVARCHAR (5) NOT NULL , 
	 Local_Cant_Change_PW NVARCHAR (5) NOT NULL , 
	 Local_Never_Changed_PW NVARCHAR (5) NOT NULL , 
	 Local_Never_Logged_On NVARCHAR (5) NOT NULL , 
	 Local_PW_Never_Expires NVARCHAR (5) NOT NULL 
	);
INSERT INTO Groups VALUES (NULL, '', 0, NULL, NULL);
INSERT INTO FindingTypes VALUES (NULL, 'ACAS');
INSERT INTO FindingTypes VALUES (NULL, 'CKL');
INSERT INTO FindingTypes VALUES (NULL, 'Fortify');
INSERT INTO FindingTypes VALUES (NULL, 'XCCDF');
INSERT INTO FindingTypes VALUES (NULL, 'WASSP');
INSERT INTO AvailabilityLevels VALUES (NULL, 'High');
INSERT INTO AvailabilityLevels VALUES (NULL, 'Moderate');
INSERT INTO AvailabilityLevels VALUES (NULL, 'Low');
INSERT INTO ConfidentialityLevels VALUES (NULL, 'High');
INSERT INTO ConfidentialityLevels VALUES (NULL, 'Moderate');
INSERT INTO ConfidentialityLevels VALUES (NULL, 'Low');
INSERT INTO IntegrityLevels VALUES (NULL, 'High');
INSERT INTO IntegrityLevels VALUES (NULL, 'Moderate');
INSERT INTO IntegrityLevels VALUES (NULL, 'Low');
INSERT INTO Overlays VALUES (NULL, "Classified");
INSERT INTO Overlays VALUES (NULL, "CDS Access");
INSERT INTO Overlays VALUES (NULL, "CDS Multilevel");
INSERT INTO Overlays VALUES (NULL, "CDS Transfer");
INSERT INTO Overlays VALUES (NULL, "Intelligence A");
INSERT INTO Overlays VALUES (NULL, "Intelligence B");
INSERT INTO Overlays VALUES (NULL, "Intelligence C");
INSERT INTO Overlays VALUES (NULL, "NC3");
INSERT INTO Overlays VALUES (NULL, "Privacy Low");
INSERT INTO Overlays VALUES (NULL, "Privacy High");
INSERT INTO Overlays VALUES (NULL, "Privacy Moderate");
INSERT INTO Overlays VALUES (NULL, "Privacy PHI");
INSERT INTO Overlays VALUES (NULL, "Space");