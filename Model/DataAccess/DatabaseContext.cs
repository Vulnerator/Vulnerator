using System.Data.Entity;
using System.Data.SQLite;
using Vulnerator.Model.Entity;
using Vulnerator.Properties;

namespace Vulnerator.Model.DataAccess
{
    public class DatabaseContext : DbContext
    {
        public DatabaseContext() : base(DatabaseBuilder.sqliteConnection, false)
        {
        }

        public virtual DbSet<AdditionalTestConsideration> AdditionalTestConsiderations { get; set; }
        public virtual DbSet<AuthorizationCondition> AuthorizationConditions { get; set; }
        public virtual DbSet<AuthorizationToConnectOrInterim_ATC_PendingItem> AuthorizationToConnectOrInterim_ATC_PendingItems { get; set; }
        
        
        public virtual DbSet<AvailabilityLevel> AvailabilityLevels { get; set; }
        public virtual DbSet<CCI> CCIs { get; set; }
        public virtual DbSet<Certification> Certifications { get; set; }
        public virtual DbSet<CommonControlPackage> CommonControlPackages { get; set; }
        public virtual DbSet<ConfidentialityLevel> ConfidentialityLevels { get; set; }
        public virtual DbSet<ConnectedSystem> ConnectedSystems { get; set; }
        public virtual DbSet<Connection> Connections { get; set; }
        public virtual DbSet<Connectivity> Connectivities { get; set; }
        public virtual DbSet<Contact> Contacts { get; set; }
        public virtual DbSet<ControlApplicabilityAssessment> ControlApplicabilityAssessments { get; set; }
        public virtual DbSet<ControlSelection> ControlSelections { get; set; }
        public virtual DbSet<ControlSet> ControlSets { get; set; }
        public virtual DbSet<CustomTestCase> CustomTestCases { get; set; }
        public virtual DbSet<DADMS_Networks> DADMS_Networks { get; set; }
        public virtual DbSet<EncryptionTechnique> EncryptionTechniques { get; set; }
        public virtual DbSet<EntranceCriteria> EntranceCriterias { get; set; }
        public virtual DbSet<EnumeratedWindowsGroup> EnumeratedWindowsGroups { get; set; }
        public virtual DbSet<EnumeratedWindowsUser> EnumeratedWindowsUsers { get; set; }
        public virtual DbSet<ExitCriteria> ExitCriterias { get; set; }
        public virtual DbSet<ExternalSecurityService> ExternalSecurityServices { get; set; }
        public virtual DbSet<FindingType> FindingTypes { get; set; }
        public virtual DbSet<GoverningPolicy> GoverningPolicies { get; set; }
        public virtual DbSet<Group> Groups { get; set; }
        public virtual DbSet<Hardware> Hardwares { get; set; }
        public virtual DbSet<IA_Control> IA_Controls { get; set; }
        public virtual DbSet<IATA_Standards> IATA_Standards { get; set; }
        public virtual DbSet<ImpactAdjustment> ImpactAdjustments { get; set; }
        public virtual DbSet<InformationType> InformationTypes { get; set; }
        public virtual DbSet<IntegrityLevel> IntegrityLevels { get; set; }
        public virtual DbSet<InterconnectedSystem> InterconnectedSystems { get; set; }
        public virtual DbSet<IP_Address> IP_Addresses { get; set; }
        public virtual DbSet<JointAuthorizationOrganization> JointAuthorizationOrganizations { get; set; }
        public virtual DbSet<LifecycleStatus> LifecycleStatuses { get; set; }
        public virtual DbSet<Limitation> Limitations { get; set; }
        public virtual DbSet<Location> Locations { get; set; }
        public virtual DbSet<MAC_Address> MAC_Addresses { get; set; }
        public virtual DbSet<MissionArea> MissionAreas { get; set; }
        public virtual DbSet<MitigationOrCondition> MitigationsOrConditions { get; set; }
        public virtual DbSet<NetworkConnectionRule> NetworkConnectionRules { get; set; }
        public virtual DbSet<NIST_Control> NIST_Controls { get; set; }
        public virtual DbSet<Organization> Organizations { get; set; }
        public virtual DbSet<Overlay> Overlays { get; set; }
        public virtual DbSet<PIT_Determination> PIT_Determinations { get; set; }
        public virtual DbSet<PortProtocol> PortsProtocols { get; set; }
        public virtual DbSet<PortService> PortsServices { get; set; }
        public virtual DbSet<RelatedDocument> RelatedDocuments { get; set; }
        public virtual DbSet<RelatedTesting> RelatedTestings { get; set; }
        public virtual DbSet<ReportSeverity> ReportSeverities { get; set; }
        public virtual DbSet<RequiredReport> RequiredReports { get; set; }
        public virtual DbSet<ResponsibilityRole> ResponsibilityRoles { get; set; }
        public virtual DbSet<SecurityAssessmentProcedure> SecurityAssessmentProcedures { get; set; }
        public virtual DbSet<SCAP_Score> SCAP_Scores { get; set; }
        public virtual DbSet<Software> Softwares { get; set; }
        public virtual DbSet<StepOneQuestionnaire> StepOneQuestionnaires { get; set; }
        public virtual DbSet<SystemCategorization> SystemCategorizations { get; set; }
        public virtual DbSet<SystemType> SystemTypes { get; set; }
        public virtual DbSet<TestReference> TestReferences { get; set; }
        public virtual DbSet<TestScheduleItem> TestScheduleItems { get; set; }
        public virtual DbSet<Title> Titles { get; set; }
        public virtual DbSet<UniqueFinding> UniqueFindings { get; set; }
        public virtual DbSet<UniqueFindingSourceFile> UniqueFindingsSourceFiles { get; set; }
        public virtual DbSet<UserCategory> UserCategories { get; set; }
        public virtual DbSet<Vulnerability> Vulnerabilities { get; set; }
        public virtual DbSet<VulnerabilityReference> VulnerabilityReferences { get; set; }
        public virtual DbSet<VulnerabilitySource> VulnerabilitySources { get; set; }
        public virtual DbSet<Waiver> Waivers { get; set; }
        public virtual DbSet<WindowsDomainUserSetting> WindowsDomainUserSettings { get; set; }
        public virtual DbSet<WindowsLocalUserSetting> WindowsLocalUserSettings { get; set; }

        private static string ConnectionString()
        {
            SQLiteConnectionStringBuilder sqliteConnectionStringBuilder = new SQLiteConnectionStringBuilder
            { DataSource = Settings.Default.Database.Split(';')[0] };
            return sqliteConnectionStringBuilder.ToString();
        }

        protected override void OnModelCreating(DbModelBuilder modelBuilder)
        {
            // * Verified
            modelBuilder.Entity<Contact>()
                .HasMany(e => e.Certifications)
                .WithMany(e => e.Contacts)
                .Map(e => e.ToTable("ContactsCertifications")
                    .MapLeftKey("Contact_ID")
                    .MapRightKey("Certification_ID"));
            
            modelBuilder.Entity<Certification>()
                .HasMany(e => e.Contacts)
                .WithMany(e => e.Certifications)
                .Map(e => e.ToTable("ContactsCertifications")
                    .MapLeftKey("Certification_ID")
                    .MapRightKey("Contact_ID"));

            modelBuilder.Entity<Contact>().HasOptional(e => e.Organization).WithMany(e => e.Contacts);
            
            modelBuilder.Entity<Organization>()
                .HasMany(e => e.Contacts)
                .WithOptional(e => e.Organization)
                .WillCascadeOnDelete(false);

            modelBuilder.Entity<EnumeratedWindowsUser>().HasMany(e => e.WindowsDomainUserSettings)
                .WithMany(e => e.EnumeratedWindowsUsers)
                .Map(e => e.ToTable("EnumeratedDomainWindowsUsersSettings")
                    .MapLeftKey("EnumeratedWindowsUser_ID")
                    .MapRightKey("WindowsDomainUserSettings_ID"));

            modelBuilder.Entity<WindowsDomainUserSetting>().HasMany(e => e.EnumeratedWindowsUsers)
                .WithMany(e => e.WindowsDomainUserSettings)
                .Map(e => e.ToTable("EnumeratedDomainWindowsUsersSettings")
                    .MapLeftKey("WindowsDomainUserSettings_ID")
                    .MapRightKey("EnumeratedWindowsUser_ID"));
            
            modelBuilder.Entity<EnumeratedWindowsUser>().HasMany(e => e.WindowsLocalUserSettings)
                .WithMany(e => e.EnumeratedWindowsUsers)
                .Map(e => e.ToTable("EnumeratedLocalWindowsUsersSettings")
                    .MapLeftKey("EnumeratedWindowsUser_ID")
                    .MapRightKey("WindowsLocalUserSettings_ID"));
            
            modelBuilder.Entity<WindowsLocalUserSetting>().HasMany(e => e.EnumeratedWindowsUsers)
                .WithMany(e => e.WindowsLocalUserSettings)
                .Map(e => e.ToTable("EnumeratedLocalWindowsUsersSettings")
                    .MapLeftKey("WindowsLocalUserSettings_ID")
                    .MapRightKey("EnumeratedWindowsUser_ID"));
            
            modelBuilder.Entity<EnumeratedWindowsUser>().HasMany(e => e.EnumeratedWindowsGroups)
                .WithMany(e => e.EnumeratedWindowsUsers)
                .Map(e => e.ToTable("EnumeratedWindowsGroupsUsers")
                    .MapLeftKey("EnumeratedWindowsUser_ID")
                    .MapRightKey("EnumeratedWindowsGroup_ID"));
            
            modelBuilder.Entity<EnumeratedWindowsGroup>().HasMany(e => e.EnumeratedWindowsUsers)
                .WithMany(e => e.EnumeratedWindowsGroups)
                .Map(e => e.ToTable("EnumeratedWindowsGroupsUsers")
                    .MapLeftKey("EnumeratedWindowsGroup_ID")
                    .MapRightKey("EnumeratedWindowsUser_ID"));

            modelBuilder.Entity<Group>().HasOptional(e => e.ConfidentialityLevel).WithMany(e => e.Groups);

            modelBuilder.Entity<ConfidentialityLevel>().HasMany(e => e.Groups)
                .WithOptional(e => e.ConfidentialityLevel);
            
            modelBuilder.Entity<Group>().HasOptional(e => e.IntegrityLevel).WithMany(e => e.Groups);

            modelBuilder.Entity<IntegrityLevel>().HasMany(e => e.Groups)
                .WithOptional(e => e.IntegrityLevel);
            
            modelBuilder.Entity<Group>().HasOptional(e => e.AvailabilityLevel).WithMany(e => e.Groups);

            modelBuilder.Entity<AvailabilityLevel>().HasMany(e => e.Groups)
                .WithOptional(e => e.AvailabilityLevel);
            
            modelBuilder.Entity<Group>().HasOptional(e => e.SystemCategorization).WithRequired(e => e.Group);

            modelBuilder.Entity<SystemCategorization>().HasRequired(e => e.Group)
                .WithOptional(e => e.SystemCategorization);
            
            modelBuilder.Entity<Group>().HasOptional(e => e.ControlSelection).WithRequired(e => e.Group);

            modelBuilder.Entity<ControlSelection>().HasRequired(e => e.Group)
                .WithOptional(e => e.ControlSelection);
            
            modelBuilder.Entity<Group>().HasOptional(e => e.StepOneQuestionnaire).WithRequired(e => e.Group);

            modelBuilder.Entity<StepOneQuestionnaire>().HasRequired(e => e.Group)
                .WithOptional(e => e.StepOneQuestionnaire);
            
            modelBuilder.Entity<Group>().HasOptional(e => e.SecurityAssessmentProcedure).WithRequired(e => e.Group);

            modelBuilder.Entity<SecurityAssessmentProcedure>().HasRequired(e => e.Group)
                .WithOptional(e => e.SecurityAssessmentProcedure);
            
            modelBuilder.Entity<Group>().HasOptional(e => e.PIT_Determination).WithRequired(e => e.Group);

            modelBuilder.Entity<PIT_Determination>().HasRequired(e => e.Group)
                .WithOptional(e => e.PIT_Determination);
            
            modelBuilder.Entity<Group>().HasOptional(e => e.Organization).WithRequired(e => e.Group);

            modelBuilder.Entity<Organization>().HasRequired(e => e.Group)
                .WithOptional(e => e.Organization);

            modelBuilder.Entity<Group>().HasMany(e => e.CCIs).WithMany(e => e.Groups)
                .Map(e => e.ToTable("GroupsCCIs")
                    .MapLeftKey("Group_ID")
                    .MapRightKey("CCI_ID"));

            modelBuilder.Entity<CCI>().HasMany(e => e.Groups).WithMany(e => e.CCIs)
                .Map(e => e.ToTable("GroupsCCIs")
                    .MapLeftKey("CCI_ID")
                    .MapRightKey("Group_ID"));
            
            modelBuilder.Entity<Group>().HasMany(e => e.ConnectedSystems).WithMany(e => e.Groups)
                .Map(e => e.ToTable("GroupsConnectedSystems")
                    .MapLeftKey("Group_ID")
                    .MapRightKey("ConnectedSystem_ID"));

            modelBuilder.Entity<ConnectedSystem>().HasMany(e => e.Groups).WithMany(e => e.ConnectedSystems)
                .Map(e => e.ToTable("GroupsConnectedSystems")
                    .MapLeftKey("ConnectedSystem_ID")
                    .MapRightKey("Group_ID"));
            
            modelBuilder.Entity<Group>().HasMany(e => e.Connections).WithMany(e => e.Groups)
                .Map(e => e.ToTable("GroupsConnections")
                    .MapLeftKey("Group_ID")
                    .MapRightKey("Connection_ID"));

            modelBuilder.Entity<Connection>().HasMany(e => e.Groups).WithMany(e => e.Connections)
                .Map(e => e.ToTable("GroupsConnections")
                    .MapLeftKey("Connection_ID")
                    .MapRightKey("Group_ID"));
            
            // TODO: GroupsContactsTitles
            
            modelBuilder.Entity<Group>().HasMany(e => e.IATA_Standards).WithMany(e => e.Groups)
                .Map(e => e.ToTable("GroupsIATA_Standards")
                    .MapLeftKey("Group_ID")
                    .MapRightKey("IATA_Standard_ID"));

            modelBuilder.Entity<IATA_Standards>().HasMany(e => e.Groups).WithMany(e => e.IATA_Standards)
                .Map(e => e.ToTable("GroupsIATA_Standards")
                    .MapLeftKey("IATA_Standard_ID")
                    .MapRightKey("Group_ID"));
            
            // TODO: GroupsMitigationsOrConditionsVulnerabilities
            
            modelBuilder.Entity<Group>().HasMany(e => e.Overlays).WithMany(e => e.Groups)
                .Map(e => e.ToTable("GroupsOverlays")
                    .MapLeftKey("Group_ID")
                    .MapRightKey("Overlay_ID"));

            modelBuilder.Entity<Overlay>().HasMany(e => e.Groups).WithMany(e => e.Overlays)
                .Map(e => e.ToTable("GroupsOverlays")
                    .MapLeftKey("Overlay_ID")
                    .MapRightKey("Group_ID"));
            
            modelBuilder.Entity<Group>().HasMany(e => e.Waivers).WithMany(e => e.Groups)
                .Map(e => e.ToTable("GroupsWaivers")
                    .MapLeftKey("Group_ID")
                    .MapRightKey("Waiver_ID"));

            modelBuilder.Entity<Waiver>().HasMany(e => e.Groups).WithMany(e => e.Waivers)
                .Map(e => e.ToTable("GroupsWaivers")
                    .MapLeftKey("Overlay_ID")
                    .MapRightKey("Waiver_ID"));

            modelBuilder.Entity<Hardware>().HasOptional(e => e.LifecycleStatus).WithMany(e => e.Hardwares);
            
            modelBuilder.Entity<LifecycleStatus>().HasMany(e => e.Hardwares).WithOptional(e => e.LifecycleStatus);

            modelBuilder.Entity<Hardware>().HasMany(e => e.Contacts).WithMany(e => e.Hardwares)
                .Map(e => e.ToTable("HardwareContacts")
                    .MapLeftKey("Hardware_ID")
                    .MapRightKey("Contact_ID"));

            modelBuilder.Entity<Contact>().HasMany(e => e.Hardwares).WithMany(e => e.Contacts)
                .Map(e => e.ToTable("HardwareContacts")
                    .MapLeftKey("Contact_ID")
                    .MapRightKey("Hardware_ID"));
            
            modelBuilder.Entity<Hardware>().HasMany(e => e.EnumeratedWindowsGroups).WithMany(e => e.Hardwares)
                .Map(e => e.ToTable("HardwareEnumeratedWindowsGroups")
                    .MapLeftKey("Hardware_ID")
                    .MapRightKey("EnumeratedWindowsGroup_ID"));

            modelBuilder.Entity<EnumeratedWindowsGroup>().HasMany(e => e.Hardwares).WithMany(e => e.EnumeratedWindowsGroups)
                .Map(e => e.ToTable("HardwareEnumeratedWindowsGroups")
                    .MapLeftKey("EnumeratedWindowsGroup_ID")
                    .MapRightKey("Hardware_ID"));
            
            modelBuilder.Entity<Hardware>().HasMany(e => e.Groups).WithMany(e => e.Hardwares)
                .Map(e => e.ToTable("HardwareGroups")
                    .MapLeftKey("Hardware_ID")
                    .MapRightKey("Group_ID"));

            modelBuilder.Entity<Group>().HasMany(e => e.Hardwares).WithMany(e => e.Groups)
                .Map(e => e.ToTable("HardwareGroups")
                    .MapLeftKey("Group_ID")
                    .MapRightKey("Hardware_ID"));
            
            modelBuilder.Entity<Hardware>().HasMany(e => e.IP_Addresses).WithMany(e => e.Hardwares)
                .Map(e => e.ToTable("Hardware_IP_Addresses")
                    .MapLeftKey("Hardware_ID")
                    .MapRightKey("IP_Address_ID"));

            modelBuilder.Entity<IP_Address>().HasMany(e => e.Hardwares).WithMany(e => e.IP_Addresses)
                .Map(e => e.ToTable("Hardware_IP_Addresses")
                    .MapLeftKey("IP_Address_ID")
                    .MapRightKey("Hardware_ID"));
            
            modelBuilder.Entity<Hardware>().HasMany(e => e.Locations).WithMany(e => e.Hardwares)
                .Map(e => e.ToTable("HardwareLocation")
                    .MapLeftKey("Hardware_ID")
                    .MapRightKey("Location_ID"));

            modelBuilder.Entity<Location>().HasMany(e => e.Hardwares).WithMany(e => e.Locations)
                .Map(e => e.ToTable("HardwareLocation")
                    .MapLeftKey("Location_ID")
                    .MapRightKey("Hardware_ID"));
            
            modelBuilder.Entity<Hardware>().HasMany(e => e.PortsProtocols).WithMany(e => e.Hardwares)
                .Map(e => e.ToTable("HardwarePortsProtocols")
                    .MapLeftKey("Hardware_ID")
                    .MapRightKey("PortsProtocols_ID"));

            modelBuilder.Entity<PortProtocol>().HasMany(e => e.Hardwares).WithMany(e => e.PortsProtocols)
                .Map(e => e.ToTable("HardwarePortsProtocols")
                    .MapLeftKey("PortsProtocols_ID")
                    .MapRightKey("Hardware_ID"));
            
            modelBuilder.Entity<InformationType>().HasMany(e => e.MissionAreas).WithMany(e => e.InformationTypes)
                .Map(e => e.ToTable("InformationTypesMissionAreas")
                    .MapLeftKey("InformationType_ID")
                    .MapRightKey("MissionArea_ID"));

            modelBuilder.Entity<MissionArea>().HasMany(e => e.InformationTypes).WithMany(e => e.MissionAreas)
                .Map(e => e.ToTable("InformationTypesMissionAreas")
                    .MapLeftKey("MissionArea_ID")
                    .MapRightKey("InformationType_ID"));
            
            modelBuilder.Entity<NIST_Control>().HasMany(e => e.IATA_Standards).WithMany(e => e.NIST_Controls)
                .Map(e => e.ToTable("NIST_Controls_IATA_Standards")
                    .MapLeftKey("NIST_Control_ID")
                    .MapRightKey("IATA_Standard_ID"));

            modelBuilder.Entity<IATA_Standards>().HasMany(e => e.NIST_Controls).WithMany(e => e.IATA_Standards)
                .Map(e => e.ToTable("NIST_Controls_IATA_Standards")
                    .MapLeftKey("IATA_Standard_ID")
                    .MapRightKey("NIST_Control_ID"));
            
            modelBuilder.Entity<NIST_Control>().HasMany(e => e.AvailabilityLevels).WithMany(e => e.NIST_Controls)
                .Map(e => e.ToTable("NIST_ControlsAvailabilityLevels")
                    .MapLeftKey("NIST_Control_ID")
                    .MapRightKey("AvailabilityLevel_ID"));

            modelBuilder.Entity<AvailabilityLevel>().HasMany(e => e.NIST_Controls).WithMany(e => e.AvailabilityLevels)
                .Map(e => e.ToTable("NIST_ControlsAvailabilityLevels")
                    .MapLeftKey("AvailabilityLevel_ID")
                    .MapRightKey("NIST_Control_ID"));
            
            modelBuilder.Entity<NIST_Control>().HasMany(e => e.CCIs).WithMany(e => e.NIST_Controls)
                .Map(e => e.ToTable("NIST_ControlsCCIs")
                    .MapLeftKey("NIST_Control_ID")
                    .MapRightKey("CCI_ID"));

            modelBuilder.Entity<CCI>().HasMany(e => e.NIST_Controls).WithMany(e => e.CCIs)
                .Map(e => e.ToTable("NIST_ControlsCCIs")
                    .MapLeftKey("CCI_ID")
                    .MapRightKey("NIST_Control_ID"));
            
            modelBuilder.Entity<NIST_Control>().HasMany(e => e.ControlApplicabilityAssessments).WithMany(e => e.NIST_Controls)
                .Map(e => e.ToTable("NIST_ControlsCAAs")
                    .MapLeftKey("NIST_Control_ID")
                    .MapRightKey("CAA_ID"));

            modelBuilder.Entity<ControlApplicabilityAssessment>().HasMany(e => e.NIST_Controls).WithMany(e => e.ControlApplicabilityAssessments)
                .Map(e => e.ToTable("NIST_ControlsCAAs")
                    .MapLeftKey("CAA_ID")
                    .MapRightKey("NIST_Control_ID"));
            
            modelBuilder.Entity<NIST_Control>().HasMany(e => e.ConfidentialityLevels).WithMany(e => e.NIST_Controls)
                .Map(e => e.ToTable("NIST_ControlsConfidentialityLevels")
                    .MapLeftKey("NIST_Control_ID")
                    .MapRightKey("ConfidentialityLevel_ID"));

            modelBuilder.Entity<ConfidentialityLevel>().HasMany(e => e.NIST_Controls).WithMany(e => e.ConfidentialityLevels)
                .Map(e => e.ToTable("NIST_ControlsConfidentialityLevels")
                    .MapLeftKey("ConfidentialityLevel_ID")
                    .MapRightKey("NIST_Control_ID"));
            
            modelBuilder.Entity<NIST_Control>().HasMany(e => e.ControlSets).WithMany(e => e.NIST_Controls)
                .Map(e => e.ToTable("NIST_ControlsControlSets")
                    .MapLeftKey("NIST_Control_ID")
                    .MapRightKey("ControlSet_ID"));

            modelBuilder.Entity<ControlSet>().HasMany(e => e.NIST_Controls).WithMany(e => e.ControlSets)
                .Map(e => e.ToTable("NIST_ControlsControlSets")
                    .MapLeftKey("ControlSet_ID")
                    .MapRightKey("NIST_Control_ID"));
            
            modelBuilder.Entity<NIST_Control>().HasMany(e => e.CommonControlPackages).WithMany(e => e.NIST_Controls)
                .Map(e => e.ToTable("NIST_ControlsCCPs")
                    .MapLeftKey("NIST_Control_ID")
                    .MapRightKey("CCP_ID"));

            modelBuilder.Entity<CommonControlPackage>().HasMany(e => e.NIST_Controls).WithMany(e => e.CommonControlPackages)
                .Map(e => e.ToTable("NIST_ControlsCCPs")
                    .MapLeftKey("CCP_ID")
                    .MapRightKey("NIST_Control_ID"));
            
            modelBuilder.Entity<NIST_Control>().HasMany(e => e.IntegrityLevels).WithMany(e => e.NIST_Controls)
                .Map(e => e.ToTable("NIST_ControlsIntegrityLevels")
                    .MapLeftKey("NIST_Control_ID")
                    .MapRightKey("IntegrityLevel_ID"));

            modelBuilder.Entity<IntegrityLevel>().HasMany(e => e.NIST_Controls).WithMany(e => e.IntegrityLevels)
                .Map(e => e.ToTable("NIST_ControlsIntegrityLevels")
                    .MapLeftKey("IntegrityLevel_ID")
                    .MapRightKey("NIST_Control_ID"));
            
            modelBuilder.Entity<NIST_Control>().HasMany(e => e.Overlays).WithMany(e => e.NIST_Controls)
                .Map(e => e.ToTable("NIST_ControlsOverlays")
                    .MapLeftKey("NIST_Control_ID")
                    .MapRightKey("Overlay_ID"));

            modelBuilder.Entity<Overlay>().HasMany(e => e.NIST_Controls).WithMany(e => e.Overlays)
                .Map(e => e.ToTable("NIST_ControlsOverlays")
                    .MapLeftKey("Overlay_ID")
                    .MapRightKey("NIST_Control_ID"));

            modelBuilder.Entity<PortService>().HasRequired(e => e.PortProtocol).WithMany(e => e.PortServices);
            
            modelBuilder.Entity<PortService>().HasMany(e => e.Softwares).WithMany(e => e.PortServices)
                .Map(e => e.ToTable("PortServicesSoftware")
                    .MapLeftKey("PortService_ID")
                    .MapRightKey("Software_ID"));

            modelBuilder.Entity<Software>().HasMany(e => e.PortServices).WithMany(e => e.Softwares)
                .Map(e => e.ToTable("PortServicesSoftware")
                    .MapLeftKey("Software_ID")
                    .MapRightKey("PortService_ID"));
            
            
            
            
            
            
            
            
            
            
            
            
            
            
            
            
            
            // TODO: Still needs to be verified
            modelBuilder.Entity<AdditionalTestConsideration>()
                .HasMany(e => e.SAPs)
                .WithMany(e => e.AdditionalTestConsiderations)
                .Map(e => e.ToTable("SAP_AdditionalTestConsiderations").MapLeftKey("Consideration_ID")
                    .MapRightKey("SAP_ID"));

            modelBuilder.Entity<AuthorizationCondition>()
                .HasMany(e => e.AuthorizationInformations)
                .WithMany(e => e.AuthorizationConditions)
                .Map(e => e.ToTable("AuthorizationInformation_AuthorizationConditions")
                    .MapLeftKey("AuthorizationCondition_ID").MapRightKey("AuthorizationInformation_ID"));

            modelBuilder.Entity<AvailabilityLevel>()
                .HasMany(e => e.Groups)
                .WithRequired(e => e.AvailabilityLevel)
                .WillCascadeOnDelete(false);

            modelBuilder.Entity<CCI>()
                .HasMany(e => e.Vulnerabilities)
                .WithMany(e => e.CCIs)
                .Map(e => e.ToTable("VulnerabilitiesCCIs").MapLeftKey("CCI_ID").MapRightKey("Vulnerability_ID"));

            modelBuilder.Entity<CommonControlPackage>()
                .HasMany(e => e.NIST_Controls)
                .WithMany(e => e.CommonControlPackages)
                .Map(e => e.ToTable("NistControlsCCPs").MapLeftKey("CCP_ID").MapRightKey("NIST_Control_ID"));

            modelBuilder.Entity<ConfidentialityLevel>()
                .HasMany(e => e.Groups)
                .WithRequired(e => e.ConfidentialityLevel)
                .WillCascadeOnDelete(false);

            modelBuilder.Entity<ConnectedSystem>()
                .HasMany(e => e.Groups)
                .WithMany(e => e.ConnectedSystems)
                .Map(e => e.ToTable("AccreditationsConnectedSystems").MapLeftKey("ConnectedSystem_ID")
                    .MapRightKey("Accreditation_ID"));

            modelBuilder.Entity<Connection>()
                .HasMany(e => e.Groups)
                .WithMany(e => e.Connections)
                .Map(e => e.ToTable("AccreditationsConnections").MapLeftKey("Connection_ID")
                    .MapRightKey("Accreditation_ID"));

            modelBuilder.Entity<Connectivity>()
                .HasMany(e => e.StepOneQuestionnaires)
                .WithMany(e => e.Connectivities)
                .Map(e => e.ToTable("StepOneQuestionnaire_Connectivity").MapLeftKey("Connectivity_ID")
                    .MapRightKey("StepOneQuestionnaire_ID"));

            modelBuilder.Entity<Contact>()
                .HasMany(e => e.Groups)
                .WithMany(e => e.Contacts)
                .Map(e => e.ToTable("GroupsContacts").MapLeftKey("Contact_ID").MapRightKey("Group_ID"));

            modelBuilder.Entity<Contact>()
                .HasMany(e => e.Hardwares)
                .WithMany(e => e.Contacts)
                .Map(e => e.ToTable("HardwareContacts").MapLeftKey("Contact_ID").MapRightKey("Hardware_ID"));

            

            modelBuilder.Entity<Contact>()
                .HasMany(e => e.Softwares)
                .WithMany(e => e.Contacts)
                .Map(e => e.ToTable("SoftwareContacts").MapLeftKey("Contact_ID").MapRightKey("Software_ID"));

            modelBuilder.Entity<ControlSet>()
                .HasMany(e => e.NIST_Controls)
                .WithMany(e => e.ControlSets)
                .Map(e => e.ToTable("NistControlsControlSets").MapLeftKey("ControlSet_ID")
                    .MapRightKey("NIST_Control_ID"));

            modelBuilder.Entity<CustomTestCase>()
                .HasMany(e => e.SAPs)
                .WithMany(e => e.CustomTestCases)
                .Map(e => e.ToTable("SAP_CustomTestCases").MapLeftKey("CustomTestCase_ID").MapRightKey("SAP_ID"));

            modelBuilder.Entity<DADMS_Networks>()
                .HasMany(e => e.Softwares)
                .WithMany(e => e.DADMS_Networks)
                .Map(e => e.ToTable("Software_DADMS_Networks").MapLeftKey("DADMS_Network_ID")
                    .MapRightKey("Software_ID"));

            modelBuilder.Entity<EncryptionTechnique>()
                .HasMany(e => e.StepOneQuestionnaires)
                .WithMany(e => e.EncryptionTechniques)
                .Map(e => e.ToTable("StepOneQuestionnaireEncryptionTechniques").MapLeftKey("EncryptionTechnique_ID")
                    .MapRightKey("StepOneQuestionnaire_ID"));

            modelBuilder.Entity<EntranceCriteria>()
                .HasMany(e => e.SAPs)
                .WithMany(e => e.EntranceCriterias)
                .Map(e => e.ToTable("SAP_EntranceCriteria").MapLeftKey("EntranceCriteria_ID").MapRightKey("SAP_ID"));

            modelBuilder.Entity<EnumeratedWindowsGroup>()
                .HasMany(e => e.Hardwares)
                .WithMany(e => e.EnumeratedWindowsGroups)
                .Map(e => e.ToTable("HardwareEnumeratedWindowsGroups").MapLeftKey("Group_ID")
                    .MapRightKey("Hardware_ID"));

            modelBuilder.Entity<EnumeratedWindowsUser>()
                .HasMany(e => e.EnumeratedWindowsGroups)
                .WithMany(e => e.EnumeratedWindowsUsers)
                .Map(e => e.ToTable("EnumeratedWindowsGroupsUsers").MapLeftKey("User_ID").MapRightKey("Group_ID"));

            modelBuilder.Entity<ExitCriteria>()
                .HasMany(e => e.SAPs)
                .WithMany(e => e.ExitCriterias)
                .Map(e => e.ToTable("SAP_ExitCriteria").MapLeftKey("ExitCriteria_ID").MapRightKey("SAP_ID"));

            modelBuilder.Entity<ExternalSecurityService>()
                .HasMany(e => e.StepOneQuestionnaires)
                .WithMany(e => e.ExternalSecurityServices)
                .Map(e => e.ToTable("StepOneQuestionnaire_ExternalSecurityServices")
                    .MapLeftKey("ExternalSecurityServices_ID").MapRightKey("StepOneQuestionnaire_ID"));

            modelBuilder.Entity<FindingType>()
                .HasMany(e => e.UniqueFindings)
                .WithRequired(e => e.FindingType)
                .WillCascadeOnDelete(false);

            modelBuilder.Entity<GoverningPolicy>()
                .HasMany(e => e.SystemCategorizations)
                .WithMany(e => e.GoverningPolicies)
                .Map(e => e.ToTable("SystemCategorizationGoverningPolicies").MapLeftKey("GoverningPolicy_ID")
                    .MapRightKey("SystemCategorization_ID"));

            modelBuilder.Entity<Group>()
                .HasMany(e => e.Hardwares)
                .WithMany(e => e.Groups)
                .Map(e => e.ToTable("HardwareGroups").MapLeftKey("Group_ID").MapRightKey("Hardware_ID"));
            
            modelBuilder.Entity<Group>()
                .HasMany(e => e.MitigationsOrConditions)
                .WithMany(e => e.Groups)
                .Map(e => e.ToTable("GroupsMitigationsOrConditions").MapLeftKey("Group_ID").MapRightKey("MitigationOrCondition_ID"));

            modelBuilder.Entity<Hardware>()
                .HasMany(e => e.ScapScores)
                .WithRequired(e => e.Hardware)
                .WillCascadeOnDelete(false);

            modelBuilder.Entity<Hardware>()
                .HasMany(e => e.VulnerabilitySources)
                .WithMany(e => e.Hardwares)
                .Map(e => e.ToTable("Hardware_VulnerabilitySources").MapLeftKey("Hardware_ID")
                    .MapRightKey("VulnerabilitySource_ID"));

            modelBuilder.Entity<IA_Control>()
                .HasMany(e => e.Vulnerabilities)
                .WithMany(e => e.IA_Controls)
                .Map(e => e.ToTable("Vulnerabilities_IA_Controls").MapLeftKey("IA_Control_ID")
                    .MapRightKey("VulnerabilitySource_ID"));

            modelBuilder.Entity<IATA_Standards>()
                .HasMany(e => e.Groups)
                .WithMany(e => e.IATA_Standards)
                .Map(e => e.ToTable("Accreditations_IATA_Standards").MapLeftKey("IATA_Standard_ID")
                    .MapRightKey("Accreditation_ID"));

            modelBuilder.Entity<IATA_Standards>()
                .HasMany(e => e.NIST_Controls)
                .WithMany(e => e.IATA_Standards)
                .Map(e => e.ToTable("NistControls_IATA_Standards").MapLeftKey("IATA_Standard_ID")
                    .MapRightKey("NIST_Control_ID"));

            modelBuilder.Entity<IntegrityLevel>()
                .HasMany(e => e.Groups)
                .WithRequired(e => e.IntegrityLevel)
                .WillCascadeOnDelete(false);

            modelBuilder.Entity<InterconnectedSystem>()
                .HasMany(e => e.SystemCategorizations)
                .WithMany(e => e.InterconnectedSystems)
                .Map(e => e.ToTable("SystemCategorizationInterconnectedSystems").MapLeftKey("InterconnectedSystem_ID")
                    .MapRightKey("SystemCategorization_ID"));

            modelBuilder.Entity<IP_Address>()
                .HasMany(e => e.Hardwares)
                .WithMany(e => e.IP_Addresses)
                .Map(e => e.ToTable("Hardware_IP_Addresses").MapLeftKey("IP_Address_ID").MapRightKey("Hardware_ID"));

            modelBuilder.Entity<JointAuthorizationOrganization>()
                .HasMany(e => e.SystemCategorizations)
                .WithMany(e => e.JointAuthorizationOrganizations)
                .Map(e => e.ToTable("SystemCategorizationJointOrganizations").MapLeftKey("JointOrganization_ID")
                    .MapRightKey("SystemCategorization_ID"));

            modelBuilder.Entity<MAC_Address>()
                .HasMany(e => e.Hardwares)
                .WithMany(e => e.MAC_Addresses)
                .Map(e => e.ToTable("Hardware_MAC_Addresses").MapLeftKey("MAC_Address_ID").MapRightKey("Hardware_ID"));

            modelBuilder.Entity<MissionArea>()
                .HasMany(e => e.InformationTypes)
                .WithMany(e => e.MissionAreas)
                .Map(e => e.ToTable("InformationTypesMissionAreas").MapLeftKey("MissionArea_ID")
                    .MapRightKey("InformationType_ID"));

            modelBuilder.Entity<NetworkConnectionRule>()
                .HasMany(e => e.StepOneQuestionnaires)
                .WithMany(e => e.NetworkConnectionRules)
                .Map(e => e.ToTable("StepOneQuestionnaireNetworkConnectionRules").MapLeftKey("NetworkConnectionRule_ID")
                    .MapRightKey("StepOneQuestionnaire_ID"));

            

            modelBuilder.Entity<Overlay>()
                .HasMany(e => e.Groups)
                .WithMany(e => e.Overlays)
                .Map(e => e.ToTable("AccreditationsOverlays").MapLeftKey("Overlay_ID").MapRightKey("Accreditation_ID"));

            modelBuilder.Entity<Overlay>()
                .HasMany(e => e.NIST_Controls)
                .WithMany(e => e.Overlays)
                .Map(e => e.ToTable("NistControlsOverlays").MapLeftKey("Overlay_ID").MapRightKey("NIST_Control_ID"));

            modelBuilder.Entity<RelatedDocument>()
                .HasMany(e => e.SecurityAssessmentProcedures)
                .WithMany(e => e.RelatedDocuments)
                .Map(e => e.ToTable("SAP_RelatedDocuments").MapLeftKey("RelatedDocument_ID").MapRightKey("SAP_ID"));

            modelBuilder.Entity<RelatedTesting>()
                .HasMany(e => e.SecurityAssessmentProcedures)
                .WithMany(e => e.RelatedTestings)
                .Map(e => e.ToTable("SAP_RelatedTesting").MapLeftKey("RelatedTesting_ID").MapRightKey("SAP_ID"));

            modelBuilder.Entity<ResponsibilityRole>()
                .HasMany(e => e.Vulnerabilities)
                .WithMany(e => e.ResponsibilityRoles)
                .Map(e => e.ToTable("Vulnerabilities_RoleResponsibilities").MapLeftKey("Role_ID")
                    .MapRightKey("Vulnerability_ID"));

            modelBuilder.Entity<Group>()
                .HasOptional(e => e.SecurityAssessmentProcedure)
                .WithRequired(e => e.Group);

            modelBuilder.Entity<TestReference>()
                .HasMany(e => e.SecurityAssessmentProcedures)
                .WithMany(e => e.TestReferences)
                .Map(e => e.ToTable("SAP_TestReferences").MapLeftKey("TestReference_ID").MapRightKey("SAP_ID"));

            modelBuilder.Entity<TestScheduleItem>()
                .HasMany(e => e.SecurityAssessmentProcedures)
                .WithMany(e => e.TestScheduleItems)
                .Map(e => e.ToTable("SAP_TestScheduleItems").MapLeftKey("TestScheduleItem_ID").MapRightKey("SAP_ID"));

            modelBuilder.Entity<UniqueFinding>()
                .HasOptional(e => e.MitigationOrCondition);

            modelBuilder.Entity<UniqueFindingSourceFile>()
                .HasMany(e => e.UniqueFindings)
                .WithRequired(e => e.UniqueFindingSourceFile)
                .WillCascadeOnDelete(false);

            modelBuilder.Entity<UserCategory>()
                .HasMany(e => e.StepOneQuestionnaires)
                .WithMany(e => e.UserCategories)
                .Map(e => e.ToTable("StepOneQuestionnaireUserCategories").MapLeftKey("UserCategory_ID")
                    .MapRightKey("StepOneQuestionnaire_ID"));

            modelBuilder.Entity<Vulnerability>()
                .HasMany(e => e.UniqueFindings)
                .WithRequired(e => e.Vulnerability)
                .WillCascadeOnDelete(false);

            modelBuilder.Entity<VulnerabilityReference>()
                .HasMany(e => e.Vulnerabilities)
                .WithMany(e => e.VulnerabilityReferences)
                .Map(e => e.ToTable("VulnerabilitiesVulnerabilityReferences").MapLeftKey("Reference_ID")
                    .MapRightKey("Vulnerability_ID"));

            modelBuilder.Entity<VulnerabilitySource>()
                .HasMany(e => e.SCAP_Scores)
                .WithRequired(e => e.VulnerabilitySource)
                .WillCascadeOnDelete(false);

            modelBuilder.Entity<VulnerabilitySource>()
                .HasMany(e => e.Vulnerabilities)
                .WithMany(e => e.VulnerabilitySources)
                .Map(e => e.ToTable("VulnerabilitiesVulnerabilitySources").MapLeftKey("VulnerabilitySource_ID")
                    .MapRightKey("Vulnerability_ID"));

            modelBuilder.Entity<WindowsDomainUserSetting>()
                .HasMany(e => e.EnumeratedWindowsUsers)
                .WithMany(e => e.WindowsDomainUserSettings)
                .Map(e => e.ToTable("EnumeratedDomainUsersSettings").MapLeftKey("Domain_Settings_ID")
                    .MapRightKey("User_ID"));

            modelBuilder.Entity<WindowsLocalUserSetting>()
                .HasMany(e => e.EnumeratedWindowsUsers)
                .WithMany(e => e.WindowsLocalUserSettings)
                .Map(e => e.ToTable("EnumeratedLocalWindowsUsersSettings").MapLeftKey("Local_Settings_ID")
                    .MapRightKey("User_ID"));
        }
    }
}