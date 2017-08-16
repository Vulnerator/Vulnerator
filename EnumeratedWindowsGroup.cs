namespace Vulnerator
{
    using System;
    using System.Collections.Generic;
    using System.ComponentModel.DataAnnotations;
    using System.ComponentModel.DataAnnotations.Schema;
    using System.Data.Entity.Spatial;

    public partial class EnumeratedWindowsGroup
    {
        [System.Diagnostics.CodeAnalysis.SuppressMessage("Microsoft.Usage", "CA2214:DoNotCallOverridableMethodsInConstructors")]
        public EnumeratedWindowsGroup()
        {
            EnumeratedWindowsUsers = new HashSet<EnumeratedWindowsUser>();
            Hardwares = new HashSet<Hardware>();
        }

        [Key]
        [DatabaseGenerated(DatabaseGeneratedOption.None)]
        public long Group_ID { get; set; }

        [Required]
        [StringLength(50)]
        public string Group_Name { get; set; }

        [System.Diagnostics.CodeAnalysis.SuppressMessage("Microsoft.Usage", "CA2227:CollectionPropertiesShouldBeReadOnly")]
        public virtual ICollection<EnumeratedWindowsUser> EnumeratedWindowsUsers { get; set; }

        [System.Diagnostics.CodeAnalysis.SuppressMessage("Microsoft.Usage", "CA2227:CollectionPropertiesShouldBeReadOnly")]
        public virtual ICollection<Hardware> Hardwares { get; set; }
    }
}
