namespace Vulnerator
{
    using System;
    using System.Collections.Generic;
    using System.ComponentModel.DataAnnotations;
    using System.ComponentModel.DataAnnotations.Schema;
    using System.Data.Entity.Spatial;

    [Table("AuthorizationInformation")]
    public partial class AuthorizationInformation
    {
        [System.Diagnostics.CodeAnalysis.SuppressMessage("Microsoft.Usage", "CA2214:DoNotCallOverridableMethodsInConstructors")]
        public AuthorizationInformation()
        {
            AuthorizationConditions = new HashSet<AuthorizationCondition>();
        }

        [Key]
        [DatabaseGenerated(DatabaseGeneratedOption.None)]
        public long AuthorizationInformation_ID { get; set; }

        [Required]
        [StringLength(25)]
        public string SecurityPlanApprovalStatus { get; set; }

        public DateTime? SecurityPlanApprovalDate { get; set; }

        [Required]
        [StringLength(25)]
        public string AuthorizationStatus { get; set; }

        [Required]
        [StringLength(5)]
        public string HasAuthorizationDocumentation { get; set; }

        public DateTime? AssessmentCompletionDate { get; set; }

        public DateTime? AuthorizationDate { get; set; }

        public DateTime? AuthorizationTerminationDate { get; set; }

        [System.Diagnostics.CodeAnalysis.SuppressMessage("Microsoft.Usage", "CA2227:CollectionPropertiesShouldBeReadOnly")]
        public virtual ICollection<AuthorizationCondition> AuthorizationConditions { get; set; }
    }
}
