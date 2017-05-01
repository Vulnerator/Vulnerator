PRAGMA user_version = '1';

CREATE TABLE Accessibility 
	(
	 Accessibility_ID INTEGER NOT NULL PRIMARY KEY , 
	 LogicalAccess NVARCHAR (25) NOT NULL , 
	 PhysicalAccess NVARCHAR (25) NOT NULL , 
	 AvScan NVARCHAR (25) NOT NULL , 
	 DodinConnectionPeriodicity NVARCHAR (25) NOT NULL,
	 FOREIGN KEY (Accessibility_ID) REFERENCES StepOneQuestionnaire(Accessibility_ID)
	);
CREATE TABLE Accreditations 
	(
	 Accreditation_ID INTEGER NOT NULL PRIMARY KEY , 
	 Accreditation_Name NVARCHAR (100) NOT NULL , 
	 Accreditation_Acronym NVARCHAR (25) NOT NULL , 
	 Accreditation_eMASS_ID NVARCHAR (25) NOT NULL , 
	 IsPlatform BIT , 
	 Confidentiality_ID INTEGER NOT NULL , 
	 Integrity_ID INTEGER NOT NULL , 
	 Availability_ID INTEGER NOT NULL , 
	 SystemCategorization_ID INTEGER NOT NULL , 
	 AccreditationVersion NVARCHAR (25) ,  
	 CybersafeGrade CHAR (1) , 
	 FISCAM_Applies BIT , 
	 ControlSelection_ID INTEGER , 
	 HasForeignNationals BIT , 
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
	 AccreditationsNistControls_ID INTEGER NOT NULL PRIMARY KEY, 
	 Accreditation_ID INTEGER NOT NULL , 
	 NIST_Control_ID INTEGER NOT NULL , 
	 IsInherited BIT , 
	 InheritedFrom NVARCHAR (50) , 
	 Inheritable BIT , 
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
	 Consideration_ID INTEGER NOT NULL PRIMARY KEY, 
	 ConsiderationTitle NVARCHAR (25) , 
	 ConsiderationDetails NVARCHAR (1000) 
	);
CREATE TABLE ATC_IATC 
	(
	 ATC_ID INTEGER NOT NULL PRIMARY KEY , 
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
	 ATC_IATC_PendingItem_ID INTEGER NOT NULL PRIMARY KEY , 
	 PendingItem NVARCHAR (50) NOT NULL , 
	 PendingItemDueDate DATE NOT NULL 
	);
CREATE TABLE AuthorizationConditions 
	(
	 AuthorizationCondition_ID INTEGER NOT NULL PRIMARY KEY , 
	 Condition NVARCHAR (500) NOT NULL , 
	 CompletionDate DATE NOT NULL , 
	 IsCompleted BIT NOT NULL 
	);
CREATE TABLE AuthorizationInformation 
	(
	 AuthorizationInformation_ID INTEGER NOT NULL PRIMARY KEY , 
	 SecurityPlanApprovalStatus NVARCHAR (25) NOT NULL , 
	 SecurityPlanApprovalDate DATE , 
	 AuthorizationStatus NVARCHAR (25) NOT NULL , 
	 HasAuthorizationDocumentation BIT NOT NULL , 
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
	 Availability_ID INTEGER NOT NULL PRIMARY KEY , 
	 Availability_Level NVARCHAR (25) NOT NULL 
	);
CREATE TABLE Buildings 
	(
	 Building_ID INTEGER NOT NULL PRIMARY KEY , 
	 RealTimeAccessControl BIT NOT NULL , 
	 HVAC BIT NOT NULL , 
	 RealTimeSecurityMonitoring BIT NOT NULL ,
	 FOREIGN KEY (Building_ID) REFERENCES PIT_Determination(Building_ID)
	);
CREATE TABLE Business 
	(
	 Business_ID INTEGER NOT NULL PRIMARY KEY , 
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
	 Calibration_ID INTEGER NOT NULL PRIMARY KEY , 
	 BuiltInCalibration BIT NOT NULL , 
	 PortableCalibration BIT NOT NULL ,
	 FOREIGN KEY (Calibration_ID) REFERENCES PIT_Determination(Calibration_ID)
	);
CREATE TABLE Categories 
	(
	 Category_ID INTEGER NOT NULL PRIMARY KEY , 
	 Category NVARCHAR (25) NOT NULL 
	);
CREATE TABLE CCIs 
	(
	 CCI_ID INTEGER NOT NULL PRIMARY KEY , 
	 CCI NVARCHAR (25) NOT NULL , 
	 Definition NVARCHAR (500) NOT NULL , 
	 CCI_Status NVARCHAR (25) NOT NULL 
	);
CREATE TABLE Certifications 
	(
	 Certification_ID INTEGER NOT NULL PRIMARY KEY , 
	 Certification NVARCHAR (50) NOT NULL 
	);
CREATE TABLE CombatSystems 
	(
	 CombatSystem_ID INTEGER NOT NULL PRIMARY KEY , 
	 CommandAndControl BIT NOT NULL , 
	 CombatIdentification BIT NOT NULL , 
	 RealTimeTrackManagement BIT NOT NULL , 
	 ForceOrders BIT NOT NULL , 
	 TroopMovement BIT NOT NULL , 
	 EngagementCoordination BIT NOT NULL ,
	 FOREIGN KEY (CombatSystem_ID) REFERENCES PIT_Determination(CombatSystem_ID)
	);
CREATE TABLE CommunicationSystems 
	(
	 CommunicationSystem_ID INTEGER NOT NULL PRIMARY KEY , 
	 VoiceCommunication BIT NOT NULL , 
	 SatelliteCommunication BIT NOT NULL , 
	 TacticalCommunication BIT NOT NULL , 
	 ISDN_VTC_Systems BIT NOT NULL , 
	 InterrogatorsTransponders BIT NOT NULL ,
	 FOREIGN KEY (CommunicationSystem_ID) REFERENCES PIT_Determination(CommunicationSystem_ID)
	);
CREATE TABLE ConfidentialityLevels 
	(
	 Confidentiality_ID INTEGER NOT NULL PRIMARY KEY , 
	 Confidentiality_Level NVARCHAR (25) NOT NULL 
	);
CREATE TABLE ConnectedSystems 
	(
	 ConnectedSystem_ID INTEGER NOT NULL PRIMARY KEY , 
	 ConnectedSystemName NVARCHAR (100) NOT NULL , 
	 IsAuthorized BIT NOT NULL 
	);
CREATE TABLE Connections 
	(
	 Connection_ID INTEGER NOT NULL PRIMARY KEY , 
	 Internet BIT , 
	 DODIN BIT , 
	 DMZ BIT , 
	 VPN BIT , 
	 CNSDP BIT , 
	 EnterpriseServicesProvider BIT 
	);
CREATE TABLE Connectivity 
	(
	 Connectivity_ID INTEGER NOT NULL PRIMARY KEY , 
	 Connectivity NVARCHAR (25) NOT NULL , 
	 OwnCircuit BIT NOT NULL , 
	 CCSD_Number NVARCHAR (25) NOT NULL , 
	 CCSD_Location NVARCHAR (50) NOT NULL , 
	 CCSD_Support NVARCHAR (100) NOT NULL 
	);
CREATE TABLE Contacts 
	(
	 Contact_ID INTEGER NOT NULL PRIMARY KEY , 
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
	 Contact_ID INTEGER NOT NULL , 
	 Certification_ID INTEGER NOT NULL ,
	 FOREIGN KEY (Contact_ID) REFERENCES Contacts(Contact_ID),
	 FOREIGN KEY (Certification_ID) REFERENCES Certifications(Certification_ID)
	);
CREATE TABLE ControlSelection 
	(
	 ControlSelection_ID INTEGER NOT NULL PRIMARY KEY , 
	 TierOneApplied BIT NOT NULL , 
	 TierOneJustification NVARCHAR (50) NOT NULL , 
	 TierTwoApplied BIT NOT NULL , 
	 TierTwoJustification NVARCHAR (50) NOT NULL , 
	 TierThreeApplied BIT NOT NULL , 
	 TierThreeJustification NVARCHAR (50) NOT NULL , 
	 CNSS_1253_Applied BIT NOT NULL , 
	 CNSS_1253_Justification NVARCHAR (50) NOT NULL , 
	 SpaceApplied BIT NOT NULL , 
	 SpaceJustification NVARCHAR (50) NOT NULL , 
	 CDS_Applied BIT NOT NULL , 
	 CDS_Justification NVARCHAR (50) , 
	 IntelligenceApplied BIT NOT NULL , 
	 IntelligenceJustification NVARCHAR (50) NOT NULL , 
	 ClassifiedApplied BIT NOT NULL , 
	 ClassifiedJustification NVARCHAR (50) NOT NULL , 
	 OtherApplied BIT NOT NULL , 
	 OtherJustification NVARCHAR (50) NOT NULL , 
	 CompensatingControlsApplied BIT NOT NULL , 
	 CompensatingControlsJustification NVARCHAR (50) NOT NULL , 
	 NA_BaselineControls BIT NOT NULL , 
	 NA_BaselineControlsJustification NVARCHAR (100) NOT NULL , 
	 BaselineControlsModified BIT NOT NULL , 
	 ModifiedBaselineJustification NVARCHAR (100) NOT NULL , 
	 BaselineRiskModified BIT NOT NULL , 
	 BaselineRiskModificationJustification NVARCHAR (100) NOT NULL , 
	 BaselineScopeApproved BIT NOT NULL , 
	 BaselineScopeJustification NVARCHAR (100) NOT NULL , 
	 InheritableControlsDefined BIT NOT NULL , 
	 InheritableControlsJustification NVARCHAR (100) NOT NULL 
	);
CREATE TABLE ControlSets 
	(
	 ControlSet_ID INTEGER NOT NULL PRIMARY KEY , 
	 ControlSet NVARCHAR (50) NOT NULL 
	);
CREATE TABLE CustomTestCases 
	(
	 CustomTestCase_ID INTEGER NOT NULL PRIMARY KEY , 
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
	 DADMS_Network_ID INTEGER NOT NULL PRIMARY KEY , 
	 DADMS_Network_Name NVARCHAR (50) NOT NULL 
	);
CREATE TABLE DiagnosticTestingSystems 
	(
	 DiagnosticTesting_ID INTEGER NOT NULL PRIMARY KEY , 
	 BuiltInTestingEquipment BIT NOT NULL , 
	 PortableTestingEquipment BIT NOT NULL 
	);
CREATE TABLE DitprDonNumbers 
	(
	 DITPR_DON_Number_ID INTEGER NOT NULL PRIMARY KEY , 
	 DITPR_DON_Number INTEGER NOT NULL 
	);
CREATE TABLE EncryptionTechniques 
	(
	 EncryptionTechnique_ID INTEGER NOT NULL PRIMARY KEY , 
	 EncryptionTechnique NVARCHAR (100) NOT NULL , 
	 KeyManagement NVARCHAR (500) NOT NULL 
	);
CREATE TABLE EntranceCriteria 
	(
	 EntranceCriteria_ID INTEGER NOT NULL PRIMARY KEY , 
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
	 Group_ID INTEGER NOT NULL PRIMARY KEY , 
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
	 User_ID INTEGER NOT NULL PRIMARY KEY , 
	 User_Name NVARCHAR (25) NOT NULL , 
	 Is_Guest_Account BIT NOT NULL , 
	 Is_Domain_Account BIT NOT NULL , 
	 Is_Local_Acount BIT NOT NULL 
	);
CREATE TABLE ExitCriteria 
	(
	 ExitCriteria_ID INTEGER NOT NULL PRIMARY KEY , 
	 ExitCriteria NVARCHAR (100) NOT NULL 
	);
CREATE TABLE ExternalSecurityServices 
	(
	 ExternalSecurityServices_ID INTEGER NOT NULL PRIMARY KEY , 
	 ExternalSecurityService NVARCHAR (50) NOT NULL , 
	 ServiceDescription NVARCHAR (500) NOT NULL , 
	 SecurityRequirementsDescription NVARCHAR (500) NOT NULL , 
	 RiskDetermination NVARCHAR (100) NOT NULL 
	);
CREATE TABLE FindingStatuses 
	(
	 Status_ID INTEGER NOT NULL PRIMARY KEY , 
	 Status NVARCHAR (25) NOT NULL 
	);
CREATE TABLE FindingTypes 
	(
	 Finding_Type_ID INTEGER NOT NULL PRIMARY KEY , 
	 Finding_Type NVARCHAR (25) NOT NULL 
	);
CREATE TABLE FISMA 
	(
	 FISMA_ID INTEGER NOT NULL PRIMARY KEY , 
	 SecurityReviewCompleted BIT NOT NULL , 
	 SecurityReviewDate DATE , 
	 ContingencyPlanRequired BIT NOT NULL , 
	 ContingencyPlanTested BIT , 
	 ContingencyPlanTestDate DATE , 
	 PIA_Required BIT NOT NULL , 
	 PIA_Date DATE , 
	 PrivacyActNoticeRequired BIT NOT NULL , 
	 eAuthenticationRiskAssessmentRequired BIT NOT NULL , 
	 eAuthenticationRiskAssessmentDate DATE , 
	 ReportableTo_FISMA BIT NOT NULL , 
	 ReportableTo_ERS BIT NOT NULL ,
	 FOREIGN KEY (FISMA_ID) REFERENCES StepOneQuestionnaire(FISMA_ID)
	);
CREATE TABLE GoverningPolicies 
	(
	 GoverningPolicy_ID INTEGER NOT NULL PRIMARY KEY , 
	 GoverningPolicy_Name NVARCHAR (50) 
	);
CREATE TABLE Groups 
	(
	 Group_ID INTEGER NOT NULL PRIMARY KEY , 
	 Group_Name NVARCHAR (50) NOT NULL , 
	 Is_Accreditation BIT NOT NULL , 
	 Accreditation_ID INTEGER NOT NULL , 
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
	 Hardware_ID INTEGER NOT NULL PRIMARY KEY , 
	 Host_Name NVARCHAR (50) , 
	 Is_Virtual_Server BIT , 
	 NIAP_Level NVARCHAR (25) , 
	 Manufacturer NVARCHAR (25) , 
	 ModelNumber NVARCHAR (50) , 
	 Is_IA_Enabled BIT , 
	 Purpose NVARCHAR (50) , 
	 SerialNumber NVARCHAR (50) 
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
	 ReportInAccreditation BIT , 
	 AssociatedService NVARCHAR (25) , 
	 Direction NVARCHAR (25) , 
	 BoundaryCrossed NVARCHAR (25) , 
	 DoD_Compliant BIT , 
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
CREATE TABLE HardwareLocation 
	(
	 Hardware_ID INTEGER NOT NULL , 
	 Location_ID INTEGER NOT NULL , 
	 IsBaselineLocation BIT NOT NULL , 
	 IsDeploymentLocation BIT NOT NULL , 
	 IsTestLocation BIT NOT NULL ,
	 FOREIGN KEY (Hardware_ID) REFERENCES Hardware(Hardware_ID),
	 FOREIGN KEY (Location_ID) REFERENCES Locations(Location_ID)
	);
CREATE TABLE IATA_Standards 
	(
	 IATA_Standard_ID INTEGER NOT NULL PRIMARY KEY , 
	 Standard_Title NVARCHAR (50) NOT NULL , 
	 Standard_Description NVARCHAR (1000) NOT NULL 
	);
CREATE TABLE ImpactAdjustments 
	(
	 ImpactAdjustment_ID INTEGER NOT NULL PRIMARY KEY , 
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
	 InformationType_ID INTEGER NOT NULL PRIMARY KEY , 
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
	 Integrity_ID INTEGER NOT NULL PRIMARY KEY , 
	 Integrity_Level NVARCHAR (25) NOT NULL 
	);
CREATE TABLE InterconnectedSystems 
	(
	 InterconnectedSystem_ID INTEGER NOT NULL PRIMARY KEY , 
	 InterconnectedSystem_Name NVARCHAR (50) NOT NULL 
	);
CREATE TABLE IpAddresses 
	(
	 IP_Address_ID INTEGER NOT NULL PRIMARY KEY , 
	 Ip_Address NVARCHAR (25) NOT NULL 
	);
CREATE TABLE JointAuthorizationOrganizations 
	(
	 JointOrganization_ID INTEGER NOT NULL PRIMARY KEY , 
	 JointOrganization_Name NVARCHAR (50) NOT NULL 
	);
CREATE TABLE LifecycleStatuses 
	(
	 LifecycleStatus_ID INTEGER NOT NULL , 
	 LifecycleStatus NVARCHAR (25) NOT NULL 
	);
CREATE TABLE Limitations 
	(
	 Limitation_ID INTEGER NOT NULL PRIMARY KEY , 
	 LimitationSummary NVARCHAR (100) NOT NULL , 
	 LimitationBackground NVARCHAR (500) NOT NULL , 
	 LimitationDetails NVARCHAR (500) NOT NULL , 
	 IsTestException BIT NOT NULL 
	);
CREATE TABLE Locations 
	(
	 Location_ID INTEGER NOT NULL PRIMARY KEY , 
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
	 IsBaselineLocation_Global BIT , 
	 IsDeploymentLocation_Global BIT , 
	 IsTestLocation_Global BIT 
	);
CREATE TABLE MedicalTechnologies 
	(
	 MedicalTechnology_ID INTEGER NOT NULL PRIMARY KEY , 
	 MedicalImaging BIT NOT NULL , 
	 MedicalMonitoring BIT NOT NULL 
	);
CREATE TABLE MissionAreas 
	(
	 MissionArea_ID INTEGER NOT NULL PRIMARY KEY , 
	 MissionArea NVARCHAR (25) NOT NULL 
	);
CREATE TABLE MitigationsOrConditions 
	(
	 MitigationOrCondition_ID INTEGER NOT NULL PRIMARY KEY , 
	 ApplicableVulnerability NVARCHAR (25) NOT NULL,
	 MitigationText NVARCHAR (2000) NOT NULL , 
	 MitigationType NVARCHAR (25) NOT NULL , 
	 IsGlobal BIT NOT NULL 
	);
CREATE TABLE NavigationTransportationSystems 
	(
	 NavigationSystem_ID INTEGER NOT NULL PRIMARY KEY , 
	 ShipAircraftControl BIT NOT NULL , 
	 IntegratedBridge BIT NOT NULL , 
	 ElectronicCharts BIT NOT NULL , 
	 GPS BIT NOT NULL , 
	 WSN BIT NOT NULL , 
	 InertialNavigation BIT NOT NULL , 
	 DeadReckoningDevice BIT NOT NULL 
	);
CREATE TABLE NetworkConnectionRules 
	(
	 NetworkConnectionRule_ID INTEGER NOT NULL PRIMARY KEY , 
	 NewtorkConnectionName NVARCHAR (25) NOT NULL , 
	 ConnectionRule NVARCHAR (100) NOT NULL 
	);
CREATE TABLE NistControls 
	(
	 NIST_Control_ID INTEGER NOT NULL PRIMARY KEY , 
	 Control_Family NVARCHAR (25) NOT NULL , 
	 Control_Number INTEGER NOT NULL , 
	 Enhancement NVARCHAR (25) NOT NULL , 
	 Control_Title NVARCHAR (50) NOT NULL , 
	 Control_Text NVARCHAR (500) NOT NULL , 
	 Supplemental_Guidance NVARCHAR (500) NOT NULL 
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
	 FOREIGN KEY (NIST_Control_ID) REFERENCES NistControls(NIST_Control_ID),
	 FOREIGN KEY (Availability_ID) REFERENCES AvailabilityLevels(Availability_ID)
	);
CREATE TABLE NistControlsCCIs 
	(
	 NIST_Control_ID INTEGER NOT NULL , 
	 CCI_ID INTEGER NOT NULL ,
	 FOREIGN KEY (NIST_Control_ID) REFERENCES NistControls(NIST_Control_ID),
	 FOREIGN KEY (CCI_ID) REFERENCES CCIs(CCI_ID)
	);
CREATE TABLE NistControlsConfidentialityLevels 
	(
	 NIST_Control_ID INTEGER NOT NULL , 
	 Confidentiality_ID INTEGER NOT NULL ,
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
CREATE TABLE NistControlsIntegrityLevels 
	(
	 NIST_Control_ID INTEGER NOT NULL , 
	 Integrity_ID INTEGER NOT NULL ,
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
	 NssQuestionnaire_ID INTEGER NOT NULL PRIMARY KEY , 
	 InvolvesIntelligenceActivities BIT NOT NULL , 
	 InvolvesCryptoActivities BIT NOT NULL , 
	 InvolvesCommandAndControl BIT NOT NULL , 
	 IsMilitaryCritical BIT NOT NULL , 
	 IsBusinessInfo BIT NOT NULL , 
	 HasExecutiveOrderProtections BIT NOT NULL , 
	 IsNss BIT NOT NULL 
	);
CREATE TABLE Organizations 
	(
	 Organization_ID INTEGER NOT NULL PRIMARY KEY , 
	 Organization NVARCHAR (50) NOT NULL 
	);
CREATE TABLE Overlays 
	(
	 Overlay_ID INTEGER NOT NULL PRIMARY KEY , 
	 Overlay NVARCHAR (25) NOT NULL 
	);
CREATE TABLE Overview 
	(
	 Overview_ID INTEGER NOT NULL PRIMARY KEY , 
	 RegistrationType NVARCHAR (25) NOT NULL , 
	 InformationSystemOwner_ID INTEGER NOT NULL , 
	 SystemType_ID INTEGER NOT NULL , 
	 DVS_Site NVARCHAR (100) ,
	 FOREIGN KEY (Overview_ID) REFERENCES StepOneQuestionnaire(Overview_ID),
	 FOREIGN KEY (SystemType_ID) REFERENCES SystemTypes(SystemType_ID)
	);
CREATE TABLE PIT_Determination 
	(
	 PIT_Determination_ID INTEGER NOT NULL PRIMARY KEY , 
	 RecievesInfo BIT NOT NULL , 
	 TransmitsInfo BIT NOT NULL , 
	 ProcessesInfo BIT NOT NULL , 
	 StoresInfo BIT NOT NULL , 
	 DisplaysInfo BIT NOT NULL , 
	 EmbeddedInSpecialPurpose BIT NOT NULL , 
	 IsDedicatedSpecialPurposeSystem BIT NOT NULL , 
	 IsEssentialSpecialPurposeSystem BIT NOT NULL , 
	 PerformsGeneralServices BIT NOT NULL , 
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
	 IsTacticalDecisionAid BIT , 
	 OtherSystemTypeDescription NVARCHAR (100) ,
	 FOREIGN KEY (PIT_Determination_ID) REFERENCES Accreditations(PIT_Determination_ID)
	);
CREATE TABLE PPS 
	(
	 PPS_ID INTEGER NOT NULL PRIMARY KEY , 
	 Port INTEGER NOT NULL , 
	 Protocol NVARCHAR (25) NOT NULL 
	);
CREATE TABLE RelatedDocuments 
	(
	 RelatedDocument_ID INTEGER NOT NULL PRIMARY KEY , 
	 RelatedDocumentName NVARCHAR (50) NOT NULL , 
	 RelationshipDescription NVARCHAR (100) NOT NULL 
	);
CREATE TABLE RelatedTesting 
	(
	 RelatedTesting_ID INTEGER NOT NULL PRIMARY KEY , 
	 TestTitle NVARCHAR (50) NOT NULL , 
	 DateConducted DATE NOT NULL , 
	 RelatedSystemTested NVARCHAR (50) NOT NULL , 
	 ResponsibleOrganization NVARCHAR (100) NOT NULL , 
	 TestingImpact NVARCHAR (500) NOT NULL 
	);
CREATE TABLE ResearchWeaponsSystems 
	(
	 ResearchWeaponsSystem_ID INTEGER NOT NULL PRIMARY KEY , 
	 RDTE_Network BIT NOT NULL , 
	 RDTE_ConnectedSystem BIT NOT NULL ,
	 FOREIGN KEY (ResearchWeaponsSystem_ID) REFERENCES PIT_Determination(ResearchWeaponsSystem_ID)
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
	 SAP_ID INTEGER NOT NULL PRIMARY KEY , 
	 Scope NVARCHAR (50) NOT NULL , 
	 Limitations NVARCHAR (500) NOT NULL , 
	 TestConfiguration NVARCHAR (2000) NOT NULL , 
	 LogisiticsSupport NVARCHAR (1000) NOT NULL , 
	 Security NVARCHAR (1000) NOT NULL ,
	 FOREIGN KEY (SAP_ID) REFERENCES Accreditations(SAP_ID)
	);
CREATE TABLE ScapScores 
	(
	 SCAP_Score_ID INTEGER NOT NULL PRIMARY KEY , 
	 Score INTEGER NOT NULL , 
	 Hardware_ID INTEGER NOT NULL , 
	 Source_ID INTEGER NOT NULL ,
	 FOREIGN KEY (Hardware_ID) REFERENCES Hardware(Hardware_ID),
	 FOREIGN KEY (Source_ID) REFERENCES VulnerabilitySources(Source_ID)
	);
CREATE TABLE Sensors 
	(
	 Sensor_ID INTEGER NOT NULL PRIMARY KEY , 
	 RADAR BIT NOT NULL , 
	 Acoustic BIT NOT NULL , 
	 VisualAndImaging BIT NOT NULL , 
	 RemoteVehicle BIT NOT NULL , 
	 PassiveElectronicWarfare BIT NOT NULL , 
	 ISR BIT NOT NULL , 
	 National BIT NOT NULL , 
	 NavigationAndControl BIT NOT NULL ,
	 FOREIGN KEY (Sensor_ID) REFERENCES PIT_Determination(Sensor_ID)
	);
CREATE TABLE Software 
	(
	 Software_ID INTEGER NOT NULL PRIMARY KEY , 
	 Software_Name NVARCHAR (50) NOT NULL , 
	 Software_Acronym NVARCHAR (25) , 
	 Software_Version NVARCHAR (25) , 
	 Function NVARCHAR (500) NOT NULL , 
	 Install_Date DATE , 
	 DADMS_ID INTEGER , 
	 DADMS_Disposition NVARCHAR (25) , 
	 DADMS_LDA DATE , 
	 Has_Custom_Code BIT , 
	 IaOrIa_Enabled BIT , 
	 Is_OS_Or_Firmware BIT , 
	 FAM_Accepted BIT , 
	 Externally_Authorized BIT , 
	 ReportInAccreditation_Global BIT , 
	 ApprovedForBaseline_Global BIT , 
	 BaselineApprover_Global NVARCHAR (50) , 
	 LifecycleStatus_ID INTEGER NOT NULL ,
	 FOREIGN KEY (LifecycleStatus_ID) REFERENCES LifecycleStatuses(LifecycleStatus_ID)
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
	 ReportInAccreditation BIT , 
	 ApprovedForBaseline BIT , 
	 BaselineApprover NVARCHAR (50) ,
	 FOREIGN KEY (Software_ID) REFERENCES Software(Software_ID),
	 FOREIGN KEY (Hardware_ID) REFERENCES Hardware(Hardware_ID)
	);
CREATE TABLE SourceFiles 
	(
	 Source_File_ID INTEGER NOT NULL PRIMARY KEY , 
	 Source_File_Name NVARCHAR (500) NOT NULL 
	);
CREATE TABLE SpecialPurposeConsoles 
	(
	 SpecialPurposeConsole_ID INTEGER NOT NULL PRIMARY KEY , 
	 WarFighting BIT NOT NULL , 
	 InputOutputConsole BIT NOT NULL ,
	 FOREIGN KEY (SpecialPurposeConsole_ID) REFERENCES PIT_Determination(SpecialPurposeConsole_ID)
	);
CREATE TABLE StepOneQuestionnaire 
	(
	 StepOneQuestionnaire_ID INTEGER NOT NULL PRIMARY KEY , 
	 SystemDescription NVARCHAR (2000) NOT NULL , 
	 MissionDescription NVARCHAR (2000) NOT NULL , 
	 CONOPS_Statement NVARCHAR (2000) NOT NULL , 
	 IsTypeAuthorization BIT NOT NULL , 
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
	 SystemCategorization_ID INTEGER NOT NULL PRIMARY KEY , 
	 SystemClassification NVARCHAR (25) NOT NULL , 
	 InformationClassification NVARCHAR (25) NOT NULL , 
	 InformationReleasability NVARCHAR (25) NOT NULL , 
	 HasGoverningPolicy BIT NOT NULL , 
	 VaryingClearanceRequirements BIT NOT NULL , 
	 ClearanceRequirementDescription NVARCHAR (500) , 
	 HasAggergationImpact BIT NOT NULL , 
	 IsJointAuthorization BIT NOT NULL , 
	 NssQuestionnaire_ID INTEGER NOT NULL , 
	 CategorizationIsApproved BIT NOT NULL ,
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
	 SystemType_ID INTEGER NOT NULL PRIMARY KEY , 
	 SystemType NVARCHAR (100) NOT NULL 
	);
CREATE TABLE TacticalSupportDatabases 
	(
	 TacticalSupportDatabase_ID INTEGER NOT NULL PRIMARY KEY , 
	 ElectronicWarfare BIT NOT NULL , 
	 Intelligence BIT NOT NULL , 
	 Environmental BIT NOT NULL , 
	 Acoustic BIT NOT NULL , 
	 Geographic BIT NOT NULL ,
	 FOREIGN KEY (TacticalSupportDatabase_ID) REFERENCES PIT_Determination(TacticalSupportDatabase_ID)
	);
CREATE TABLE TestReferences 
	(
	 TestReference_ID INTEGER NOT NULL PRIMARY KEY , 
	 TestReferenceName NVARCHAR (100) 
	);
CREATE TABLE TestScheduleItems 
	(
	 TestScheduleItem_ID INTEGER NOT NULL PRIMARY KEY , 
	 TestEvent NVARCHAR (100) , 
	 Category_ID INTEGER NOT NULL , 
	 DurationInDays INTEGER NOT NULL 
	);
CREATE TABLE Titles 
	(
	 Title_ID INTEGER NOT NULL PRIMARY KEY , 
	 Title NVARCHAR (25) NOT NULL 
	);
CREATE TABLE TrainingSimulationSystems 
	(
	 TrainingSimulation_ID INTEGER NOT NULL PRIMARY KEY , 
	 FlightSimulator BIT NOT NULL , 
	 BridgeSimulator BIT NOT NULL , 
	 ClassroomNetworkOther BIT NOT NULL , 
	 EmbeddedTactical BIT NOT NULL ,
	 FOREIGN KEY (TrainingSimulation_ID) REFERENCES PIT_Determination(TrainingSimulation_ID)
	);
CREATE TABLE UniqueFindings 
	(
	 Unique_Finding_ID INTEGER NOT NULL PRIMARY KEY , 
	 AutomatedFindingOutput NVARCHAR , 
	 Comments NVARCHAR (2000) , 
	 Finding_Details NVARCHAR (2000) , 
	 Technical_Mitigation NVARCHAR (2000) , 
	 Proposed_Mitigation NVARCHAR (2000) , 
	 Predisposing_Conditions NVARCHAR (2000) , 
	 Impact NVARCHAR (25) , 
	 Likelihood NVARCHAR (25) , 
	 Severity NVARCHAR (25) , 
	 Risk NVARCHAR (25) , 
	 Residual_Risk NVARCHAR (25) , 
	 First_Discovered DATE NOT NULL , 
	 Last_Observed DATE NOT NULL , 
	 Approval_Status NVARCHAR NOT NULL , 
	 Data_Entry_Date DATE , 
	 Data_Expiration_Date DATE , 
	 Delta_Analysis_Required BIT NOT NULL , 
	 Finding_Type_ID INTEGER NOT NULL , 
	 Source_ID INTEGER NOT NULL , 
	 Source_File_ID INTEGER NOT NULL , 
	 Status_ID INTEGER NOT NULL , 
	 Vulnerability_ID INTEGER NOT NULL , 
	 Hardware_ID INTEGER NOT NULL ,
	 FOREIGN KEY (Finding_Type_ID) REFERENCES FindingTypes(Finding_Type_ID),
	 FOREIGN KEY (Source_ID) REFERENCES VulnerabilitySources(Source_ID),
	 FOREIGN KEY (Source_File_ID) REFERENCES SourceFiles(Source_File_ID),
	 FOREIGN KEY (Status_ID) REFERENCES FindingStatuses(Status_ID),
	 FOREIGN KEY (Vulnerability_ID) REFERENCES Vulnerabilities(Vulnerability_ID),
	 FOREIGN KEY (Hardware_ID) REFERENCES Hardware(Hardware_ID)
	);
CREATE TABLE UserCategories 
	(
	 UserCategory_ID INTEGER NOT NULL PRIMARY KEY , 
	 UserCategory NVARCHAR (25) 
	);
CREATE TABLE UtilityDistribution 
	(
	 UtilityDistribution_ID INTEGER NOT NULL PRIMARY KEY , 
	 SCADA BIT NOT NULL , 
	 UtilitiesEngineering BIT NOT NULL , 
	 MeteringAndControl BIT NOT NULL , 
	 MechanicalMonitoring BIT NOT NULL , 
	 DamageControlMonitoring BIT NOT NULL ,
	 FOREIGN KEY (UtilityDistribution_ID) REFERENCES PIT_Determination(UtilityDistribution_ID)
	);
CREATE TABLE VulnerabilitesCCIs 
	(
	 Vulnerability_ID INTEGER NOT NULL , 
	 CCI_ID INTEGER NOT NULL ,
	 FOREIGN KEY (Vulnerability_ID) REFERENCES Vulnerabilities(Vulnerability_ID),
	 FOREIGN KEY (CCI_ID) REFERENCES CCIs(CCI_ID)
	);
CREATE TABLE Vulnerabilities 
	(
	 Vulnerability_ID INTEGER NOT NULL PRIMARY KEY , 
	 UniqueVulnerabilityIdentifier NVARCHAR (50) , 
	 VulnerabilityFamilyOrClass NVARCHAR (100) , 
	 Version NVARCHAR (25) , 
	 Release NVARCHAR (25) , 
	 Title NVARCHAR (100) NOT NULL , 
	 Description NVARCHAR NOT NULL , 
	 Risk_Statement NVARCHAR , 
	 Fix_Text NVARCHAR , 
	 Published_Date DATE NOT NULL , 
	 Modified_Date DATE NOT NULL , 
	 Fix_Published_Date DATE NOT NULL , 
	 Raw_Risk NVARCHAR (25) NOT NULL , 
	 V_ID NVARCHAR (25) , 
	 STIG_ID NVARCHAR (25) , 
	 Check_Content NVARCHAR 
	);
CREATE TABLE VulnerabilitySources 
	(
	 Source_ID INTEGER NOT NULL PRIMARY KEY , 
	 Source_Name NVARCHAR (100) NOT NULL , 
	 Source_Version NVARCHAR (25) NOT NULL , 
	 Source_Release NVARCHAR (25) NOT NULL 
	);
CREATE TABLE VulnerabilitySourcesSoftware 
	(
	 Source_ID INTEGER NOT NULL , 
	 Software_ID INTEGER NOT NULL ,
	 FOREIGN KEY (Source_ID) REFERENCES VulnerabilitySources(Source_ID),
	 FOREIGN KEY (Software_ID) REFERENCES Software(Software_ID)
	);
CREATE TABLE Waivers 
	(
	 Waiver_ID INTEGER NOT NULL PRIMARY KEY , 
	 Waiver_Name NVARCHAR (100) NOT NULL 
	);
CREATE TABLE WeaponsSystems 
	(
	 WeaponsSystem_ID INTEGER NOT NULL PRIMARY KEY , 
	 FireControlAndTargeting BIT NOT NULL , 
	 Missile BIT NOT NULL , 
	 Gun BIT NOT NULL , 
	 Torpedoes BIT NOT NULL , 
	 ActiveElectronicWarfare BIT NOT NULL , 
	 Launchers BIT NOT NULL , 
	 Decoy BIT NOT NULL , 
	 Vehicles BIT NOT NULL , 
	 Tanks BIT NOT NULL , 
	 Artillery BIT NOT NULL , 
	 ManDeployableWeapons BIT NOT NULL ,
	 FOREIGN KEY (WeaponsSystem_ID) REFERENCES PIT_Determination(WeaponsSystem_ID)
	);
CREATE TABLE WindowsDomainUserSettings 
	(
	 Domain_Settings_ID INTEGER NOT NULL PRIMARY KEY , 
	 Domain_Is_Disabled BIT NOT NULL , 
	 Domain_Is_Disabled_Automatically BIT NOT NULL , 
	 Domain_Cant_Change_PW BIT NOT NULL , 
	 Domain_Never_Changed_PW BIT NOT NULL , 
	 Domain_Never_Logged_On BIT NOT NULL , 
	 Domain_PW_Never_Expires BIT NOT NULL 
	);
CREATE TABLE WindowsLocalUserSettings 
	(
	 Local_Settings_ID INTEGER NOT NULL PRIMARY KEY , 
	 Local_Is_Disabled BIT NOT NULL , 
	 Local_Is_Disabled_Automatically BIT NOT NULL , 
	 Local_Cant_Change_PW BIT NOT NULL , 
	 Local_Never_Changed_PW BIT NOT NULL , 
	 Local_Never_Logged_On BIT NOT NULL , 
	 Local_PW_Never_Expires BIT NOT NULL 
	);