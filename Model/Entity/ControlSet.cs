namespace Vulnerator.Model.Entity
{
    using System.Collections.Generic;
    using System.Collections.ObjectModel;
    using System.ComponentModel.DataAnnotations;
    using System.ComponentModel.DataAnnotations.Schema;

    public partial class ControlSet
    {
        [System.Diagnostics.CodeAnalysis.SuppressMessage("Microsoft.Usage", "CA2214:DoNotCallOverridableMethodsInConstructors")]
        public ControlSet()
        { NistControls = new ObservableCollection<NistControl>(); }

        [Key]
        [DatabaseGenerated(DatabaseGeneratedOption.None)]
        public long ControlSet_ID { get; set; }

        [Column("ControlSet")]
        [Required]
        [StringLength(50)]
        public string ControlSet1 { get; set; }

        [System.Diagnostics.CodeAnalysis.SuppressMessage("Microsoft.Usage", "CA2227:CollectionPropertiesShouldBeReadOnly")]
        public virtual ICollection<NistControl> NistControls { get; set; }
    }
}
