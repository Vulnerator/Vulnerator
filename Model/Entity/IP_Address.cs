namespace Vulnerator.Model.Entity
{
    using System.Collections.Generic;
    using System.Collections.ObjectModel;
    using System.ComponentModel.DataAnnotations;
    using System.ComponentModel.DataAnnotations.Schema;

    public partial class IP_Address
    {
        [System.Diagnostics.CodeAnalysis.SuppressMessage("Microsoft.Usage", "CA2214:DoNotCallOverridableMethodsInConstructors")]
        public IP_Address()
        { Hardwares = new ObservableCollection<Hardware>(); }

        [Key]
        [DatabaseGenerated(DatabaseGeneratedOption.None)]
        public long IP_Address_ID { get; set; }

        [Required]
        [StringLength(25)]
        [Column("IP_Address")]
        public string IpAddress { get; set; }

        [System.Diagnostics.CodeAnalysis.SuppressMessage("Microsoft.Usage", "CA2227:CollectionPropertiesShouldBeReadOnly")]
        public virtual ICollection<Hardware> Hardwares { get; set; }
    }
}
