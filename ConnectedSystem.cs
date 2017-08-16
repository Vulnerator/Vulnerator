namespace Vulnerator
{
    using System;
    using System.Collections.Generic;
    using System.ComponentModel.DataAnnotations;
    using System.ComponentModel.DataAnnotations.Schema;
    using System.Data.Entity.Spatial;

    public partial class ConnectedSystem
    {
        [System.Diagnostics.CodeAnalysis.SuppressMessage("Microsoft.Usage", "CA2214:DoNotCallOverridableMethodsInConstructors")]
        public ConnectedSystem()
        {
            Accreditations = new HashSet<Accreditation>();
        }

        [Key]
        [DatabaseGenerated(DatabaseGeneratedOption.None)]
        public long ConnectedSystem_ID { get; set; }

        [Required]
        [StringLength(100)]
        public string ConnectedSystemName { get; set; }

        [Required]
        [StringLength(5)]
        public string IsAuthorized { get; set; }

        [System.Diagnostics.CodeAnalysis.SuppressMessage("Microsoft.Usage", "CA2227:CollectionPropertiesShouldBeReadOnly")]
        public virtual ICollection<Accreditation> Accreditations { get; set; }
    }
}
