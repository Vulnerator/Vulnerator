namespace Vulnerator
{
    using System;
    using System.Collections.Generic;
    using System.ComponentModel.DataAnnotations;
    using System.ComponentModel.DataAnnotations.Schema;
    using System.Data.Entity.Spatial;

    public partial class IA_Controls
    {
        [System.Diagnostics.CodeAnalysis.SuppressMessage("Microsoft.Usage", "CA2214:DoNotCallOverridableMethodsInConstructors")]
        public IA_Controls()
        {
            Vulnerabilities = new HashSet<Vulnerability>();
        }

        [Key]
        [DatabaseGenerated(DatabaseGeneratedOption.None)]
        public long IA_Control_ID { get; set; }

        [Required]
        [StringLength(10)]
        public string IA_Control_Number { get; set; }

        [Required]
        [StringLength(10)]
        public string Impact { get; set; }

        [Required]
        [StringLength(50)]
        public string Subject_Area { get; set; }

        [Required]
        [StringLength(100)]
        public string Name { get; set; }

        [Required]
        [StringLength(250)]
        public string Description { get; set; }

        [Required]
        [StringLength(2000)]
        public string Threat_Vuln_Countermeasures { get; set; }

        [Required]
        [StringLength(2000)]
        public string General_Implementation_Guidance { get; set; }

        [Required]
        [StringLength(2000)]
        public string System_Specific_Guidance_Resources { get; set; }

        [System.Diagnostics.CodeAnalysis.SuppressMessage("Microsoft.Usage", "CA2227:CollectionPropertiesShouldBeReadOnly")]
        public virtual ICollection<Vulnerability> Vulnerabilities { get; set; }
    }
}
