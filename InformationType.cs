namespace Vulnerator
{
    using System;
    using System.Collections.Generic;
    using System.ComponentModel.DataAnnotations;
    using System.ComponentModel.DataAnnotations.Schema;
    using System.Data.Entity.Spatial;

    public partial class InformationType
    {
        [System.Diagnostics.CodeAnalysis.SuppressMessage("Microsoft.Usage", "CA2214:DoNotCallOverridableMethodsInConstructors")]
        public InformationType()
        {
            SystemCategorizationInformationTypes = new HashSet<SystemCategorizationInformationType>();
            MissionAreas = new HashSet<MissionArea>();
        }

        [Key]
        [DatabaseGenerated(DatabaseGeneratedOption.None)]
        public long InformationType_ID { get; set; }

        [Required]
        [StringLength(25)]
        public string InfoTypeId { get; set; }

        [Required]
        [StringLength(50)]
        public string InfoTypeName { get; set; }

        [StringLength(2147483647)]
        public string BaselineConfidentiality { get; set; }

        [StringLength(2147483647)]
        public string BaselineIntegrity { get; set; }

        [StringLength(2147483647)]
        public string BaselineAvailability { get; set; }

        [StringLength(2147483647)]
        public string EnhancedConfidentiality { get; set; }

        [StringLength(2147483647)]
        public string EnhancedIntegrity { get; set; }

        [StringLength(2147483647)]
        public string EnhancedAvailability { get; set; }

        [System.Diagnostics.CodeAnalysis.SuppressMessage("Microsoft.Usage", "CA2227:CollectionPropertiesShouldBeReadOnly")]
        public virtual ICollection<SystemCategorizationInformationType> SystemCategorizationInformationTypes { get; set; }

        [System.Diagnostics.CodeAnalysis.SuppressMessage("Microsoft.Usage", "CA2227:CollectionPropertiesShouldBeReadOnly")]
        public virtual ICollection<MissionArea> MissionAreas { get; set; }
    }
}
