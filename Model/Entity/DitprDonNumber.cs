namespace Vulnerator.Model.Entity
{
    using System.Collections.Generic;
    using System.Collections.ObjectModel;
    using System.ComponentModel.DataAnnotations;
    using System.ComponentModel.DataAnnotations.Schema;

    [Table("DITPR_DON_Numbers")]
    public partial class DitprDonNumber
    {
        [System.Diagnostics.CodeAnalysis.SuppressMessage("Microsoft.Usage", "CA2214:DoNotCallOverridableMethodsInConstructors")]
        public DitprDonNumber()
        { StepOneQuestionnaires = new ObservableCollection<StepOneQuestionnaire>(); }

        [Key]
        [DatabaseGenerated(DatabaseGeneratedOption.None)]
        public long DITPR_DON_Number_ID { get; set; }

        public long DITPR_DON_Number { get; set; }

        [System.Diagnostics.CodeAnalysis.SuppressMessage("Microsoft.Usage", "CA2227:CollectionPropertiesShouldBeReadOnly")]
        public virtual ICollection<StepOneQuestionnaire> StepOneQuestionnaires { get; set; }
    }
}
