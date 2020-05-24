namespace Vulnerator.Model.Entity
{
    using System.Collections.Generic;
    using System.Collections.ObjectModel;
    using System.ComponentModel.DataAnnotations;
    using System.ComponentModel.DataAnnotations.Schema;

    public partial class AdditionalTestConsideration
    {
        [System.Diagnostics.CodeAnalysis.SuppressMessage("Microsoft.Usage", "CA2214:DoNotCallOverridableMethodsInConstructors")]
        public AdditionalTestConsideration()
        { SAPs = new ObservableCollection<SAP>(); }

        [Key]
        [DatabaseGenerated(DatabaseGeneratedOption.None)]
        public long AdditionalTestConsideration_ID { get; set; }

        [StringLength(25)]
        public string AdditionalTestConsiderationTitle { get; set; }

        [StringLength(1000)]
        public string AdditionalTestConsiderationDetails { get; set; }

        [System.Diagnostics.CodeAnalysis.SuppressMessage("Microsoft.Usage", "CA2227:CollectionPropertiesShouldBeReadOnly")]
        public virtual ICollection<SAP> SAPs { get; set; }
    }
}
