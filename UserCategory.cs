namespace Vulnerator
{
    using System;
    using System.Collections.Generic;
    using System.ComponentModel.DataAnnotations;
    using System.ComponentModel.DataAnnotations.Schema;
    using System.Data.Entity.Spatial;

    public partial class UserCategory
    {
        [System.Diagnostics.CodeAnalysis.SuppressMessage("Microsoft.Usage", "CA2214:DoNotCallOverridableMethodsInConstructors")]
        public UserCategory()
        {
            StepOneQuestionnaires = new HashSet<StepOneQuestionnaire>();
        }

        [Key]
        [DatabaseGenerated(DatabaseGeneratedOption.None)]
        public long UserCategory_ID { get; set; }

        [Column("UserCategory")]
        [StringLength(25)]
        public string UserCategory1 { get; set; }

        [System.Diagnostics.CodeAnalysis.SuppressMessage("Microsoft.Usage", "CA2227:CollectionPropertiesShouldBeReadOnly")]
        public virtual ICollection<StepOneQuestionnaire> StepOneQuestionnaires { get; set; }
    }
}
