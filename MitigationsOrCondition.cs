namespace Vulnerator
{
    using System;
    using System.Collections.Generic;
    using System.ComponentModel.DataAnnotations;
    using System.ComponentModel.DataAnnotations.Schema;
    using System.Data.Entity.Spatial;

    public partial class MitigationsOrCondition
    {
        [System.Diagnostics.CodeAnalysis.SuppressMessage("Microsoft.Usage", "CA2214:DoNotCallOverridableMethodsInConstructors")]
        public MitigationsOrCondition()
        {
            Groups = new HashSet<Group>();
            Hardwares = new HashSet<Hardware>();
        }

        [Key]
        [DatabaseGenerated(DatabaseGeneratedOption.None)]
        public long MitigationOrCondition_ID { get; set; }

        [Required]
        [StringLength(25)]
        public string ApplicableVulnerability { get; set; }

        [Required]
        [StringLength(2000)]
        public string MitigationText { get; set; }

        [Required]
        [StringLength(25)]
        public string MitigationType { get; set; }

        [Required]
        [StringLength(5)]
        public string IsGlobal { get; set; }

        [System.Diagnostics.CodeAnalysis.SuppressMessage("Microsoft.Usage", "CA2227:CollectionPropertiesShouldBeReadOnly")]
        public virtual ICollection<Group> Groups { get; set; }

        [System.Diagnostics.CodeAnalysis.SuppressMessage("Microsoft.Usage", "CA2227:CollectionPropertiesShouldBeReadOnly")]
        public virtual ICollection<Hardware> Hardwares { get; set; }
    }
}
