namespace Vulnerator.Model.Entity
{
    using System;
    using System.Collections.Generic;
    using System.ComponentModel.DataAnnotations;
    using System.ComponentModel.DataAnnotations.Schema;
    using System.Data.Entity.Spatial;

    public partial class AuthorizationCondition
    {
        [System.Diagnostics.CodeAnalysis.SuppressMessage("Microsoft.Usage", "CA2214:DoNotCallOverridableMethodsInConstructors")]
        public AuthorizationCondition()
        {
            AuthorizationInformations = new HashSet<AuthorizationInformation>();
        }

        [Key]
        [DatabaseGenerated(DatabaseGeneratedOption.None)]
        public long AuthorizationCondition_ID { get; set; }

        [Required]
        [StringLength(500)]
        public string Condition { get; set; }

        public DateTime CompletionDate { get; set; }

        [Required]
        [StringLength(5)]
        public string IsCompleted { get; set; }

        [System.Diagnostics.CodeAnalysis.SuppressMessage("Microsoft.Usage", "CA2227:CollectionPropertiesShouldBeReadOnly")]
        public virtual ICollection<AuthorizationInformation> AuthorizationInformations { get; set; }
    }
}
