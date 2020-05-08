namespace Vulnerator.Model.Entity
{
    using System.Collections.Generic;
    using System.Collections.ObjectModel;
    using System.ComponentModel.DataAnnotations;
    using System.ComponentModel.DataAnnotations.Schema;

    [Table("Connectivity")]
    public partial class Connectivity
    {
        [System.Diagnostics.CodeAnalysis.SuppressMessage("Microsoft.Usage", "CA2214:DoNotCallOverridableMethodsInConstructors")]
        public Connectivity()
        { StepOneQuestionnaires = new ObservableCollection<StepOneQuestionnaire>(); }

        [Key]
        [DatabaseGenerated(DatabaseGeneratedOption.None)]
        public long Connectivity_ID { get; set; }

        [Column("Connectivity")]
        [Required]
        [StringLength(25)]
        public string Connectivity1 { get; set; }

        [Required]
        [StringLength(5)]
        public string OwnCircuit { get; set; }

        [Required]
        [StringLength(25)]
        public string CCSD_Number { get; set; }

        [Required]
        [StringLength(50)]
        public string CCSD_Location { get; set; }

        [Required]
        [StringLength(100)]
        public string CCSD_Support { get; set; }

        [System.Diagnostics.CodeAnalysis.SuppressMessage("Microsoft.Usage", "CA2227:CollectionPropertiesShouldBeReadOnly")]
        public virtual ICollection<StepOneQuestionnaire> StepOneQuestionnaires { get; set; }
    }
}
