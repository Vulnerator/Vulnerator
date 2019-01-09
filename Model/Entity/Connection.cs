namespace Vulnerator.Model.Entity
{
    using System.Collections.Generic;
    using System.Collections.ObjectModel;
    using System.ComponentModel.DataAnnotations;
    using System.ComponentModel.DataAnnotations.Schema;

    public partial class Connection
    {
        [System.Diagnostics.CodeAnalysis.SuppressMessage("Microsoft.Usage", "CA2214:DoNotCallOverridableMethodsInConstructors")]
        public Connection()
        { Accreditations = new ObservableCollection<Accreditation>(); }

        [Key]
        [DatabaseGenerated(DatabaseGeneratedOption.None)]
        public long Connection_ID { get; set; }

        [StringLength(5)]
        public string Internet { get; set; }

        [StringLength(5)]
        public string DODIN { get; set; }

        [StringLength(5)]
        public string DMZ { get; set; }

        [StringLength(5)]
        public string VPN { get; set; }

        [StringLength(5)]
        public string CNSDP { get; set; }

        [StringLength(5)]
        public string EnterpriseServicesProvider { get; set; }

        [System.Diagnostics.CodeAnalysis.SuppressMessage("Microsoft.Usage", "CA2227:CollectionPropertiesShouldBeReadOnly")]
        public virtual ICollection<Accreditation> Accreditations { get; set; }
    }
}
