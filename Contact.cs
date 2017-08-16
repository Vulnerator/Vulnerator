namespace Vulnerator
{
    using System;
    using System.Collections.Generic;
    using System.ComponentModel.DataAnnotations;
    using System.ComponentModel.DataAnnotations.Schema;
    using System.Data.Entity.Spatial;

    public partial class Contact
    {
        [System.Diagnostics.CodeAnalysis.SuppressMessage("Microsoft.Usage", "CA2214:DoNotCallOverridableMethodsInConstructors")]
        public Contact()
        {
            InformationSystemOwners = new HashSet<InformationSystemOwner>();
            Accreditations = new HashSet<Accreditation>();
            Groups = new HashSet<Group>();
            Hardwares = new HashSet<Hardware>();
            Softwares = new HashSet<Software>();
        }

        [Key]
        [DatabaseGenerated(DatabaseGeneratedOption.None)]
        public long Contact_ID { get; set; }

        [Required]
        [StringLength(25)]
        public string First_Name { get; set; }

        [Required]
        [StringLength(50)]
        public string Last_Name { get; set; }

        [Required]
        [StringLength(50)]
        public string Email { get; set; }

        public long Title_ID { get; set; }

        public long Organization_ID { get; set; }

        public virtual Organization Organization { get; set; }

        public virtual Title Title { get; set; }

        [System.Diagnostics.CodeAnalysis.SuppressMessage("Microsoft.Usage", "CA2227:CollectionPropertiesShouldBeReadOnly")]
        public virtual ICollection<InformationSystemOwner> InformationSystemOwners { get; set; }

        public virtual Certification Certification { get; set; }

        [System.Diagnostics.CodeAnalysis.SuppressMessage("Microsoft.Usage", "CA2227:CollectionPropertiesShouldBeReadOnly")]
        public virtual ICollection<Accreditation> Accreditations { get; set; }

        [System.Diagnostics.CodeAnalysis.SuppressMessage("Microsoft.Usage", "CA2227:CollectionPropertiesShouldBeReadOnly")]
        public virtual ICollection<Group> Groups { get; set; }

        [System.Diagnostics.CodeAnalysis.SuppressMessage("Microsoft.Usage", "CA2227:CollectionPropertiesShouldBeReadOnly")]
        public virtual ICollection<Hardware> Hardwares { get; set; }

        [System.Diagnostics.CodeAnalysis.SuppressMessage("Microsoft.Usage", "CA2227:CollectionPropertiesShouldBeReadOnly")]
        public virtual ICollection<Software> Softwares { get; set; }
    }
}
