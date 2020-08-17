using System.ComponentModel;
using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.ComponentModel;
using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;

namespace Vulnerator.Model.Entity
{
    public class SystemCategorization : INotifyPropertyChanged
    {
        public event PropertyChangedEventHandler PropertyChanged;

        [System.Diagnostics.CodeAnalysis.SuppressMessage("Microsoft.Usage", "CA2214:DoNotCallOverridableMethodsInConstructors")]
        public SystemCategorization()
        {
            GoverningPolicies = new HashSet<GoverningPolicy>();
            InterconnectedSystems = new HashSet<InterconnectedSystem>();
            JointAuthorizationOrganizations = new HashSet<JointAuthorizationOrganization>();
        }

        [Key]
        [DatabaseGenerated(DatabaseGeneratedOption.None)]
        public long SystemCategorization_ID { get; set; }

        [Required]
        [StringLength(25)]
        public string SystemClassification { get; set; }

        [Required]
        [StringLength(25)]
        public string InformationClassification { get; set; }

        [Required]
        [StringLength(25)]
        public string InformationReleasability { get; set; }

        [Required]
        [StringLength(5)]
        public string HasGoverningPolicy { get; set; }

        [Required]
        [StringLength(5)]
        public string VaryingClearanceRequirements { get; set; }

        [StringLength(2000)]
        public string ClearanceRequirementDescription { get; set; }

        [Required]
        [StringLength(5)]
        public string HasAggregationImpact { get; set; }

        [Required]
        [StringLength(5)]
        public string IsJointAuthorization { get; set; }
        
        [Required]
        [StringLength(5)]
        public string InvolvesIntelligenceActivities { get; set; }
        
        [Required]
        [StringLength(5)]
        public string InvolvesCryptoActivities { get; set; }
        
        [Required]
        [StringLength(5)]
        public string InvolvesCommandAndControl { get; set; }
        
        [Required]
        [StringLength(5)]
        public string IsMilitaryCritical { get; set; }
        
        [Required]
        [StringLength(5)]
        public string IsBusinessInfo { get; set; }
        
        [Required]
        [StringLength(5)]
        public string HasExecutiveOrderProtections { get; set; }
        
        [Required]
        [StringLength(5)]
        public string IsNss { get; set; }
 
        [Required]
        [StringLength(5)]
        public string CategorizationIsApproved { get; set; }

        public virtual Group Group { get; set; }
        
        [System.Diagnostics.CodeAnalysis.SuppressMessage("Microsoft.Usage", "CA2227:CollectionPropertiesShouldBeReadOnly")]
        public virtual ICollection<GoverningPolicy> GoverningPolicies { get; set; }

        [System.Diagnostics.CodeAnalysis.SuppressMessage("Microsoft.Usage", "CA2227:CollectionPropertiesShouldBeReadOnly")]
        public virtual ICollection<InterconnectedSystem> InterconnectedSystems { get; set; }

        [System.Diagnostics.CodeAnalysis.SuppressMessage("Microsoft.Usage", "CA2227:CollectionPropertiesShouldBeReadOnly")]
        public virtual ICollection<JointAuthorizationOrganization> JointAuthorizationOrganizations { get; set; }
    }
}
