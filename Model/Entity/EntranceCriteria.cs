namespace Vulnerator.Model.Entity
{
    using System.Collections.Generic;
    using System.Collections.ObjectModel;
    using System.ComponentModel.DataAnnotations;
    using System.ComponentModel.DataAnnotations.Schema;

    [Table("EntranceCriteria")]
    public partial class EntranceCriteria
    {
        [System.Diagnostics.CodeAnalysis.SuppressMessage("Microsoft.Usage", "CA2214:DoNotCallOverridableMethodsInConstructors")]
        public EntranceCriteria()
        { SAPs = new ObservableCollection<SAP>(); }

        [Key]
        [DatabaseGenerated(DatabaseGeneratedOption.None)]
        public long EntranceCriteria_ID { get; set; }

        [Column("EntranceCriteria")]
        [Required]
        [StringLength(100)]
        public string Entrance_Criteria { get; set; }

        [System.Diagnostics.CodeAnalysis.SuppressMessage("Microsoft.Usage", "CA2227:CollectionPropertiesShouldBeReadOnly")]
        public virtual ICollection<SAP> SAPs { get; set; }
    }
}
