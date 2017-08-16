namespace Vulnerator.Model.Entity
{
    using System;
    using System.Collections.Generic;
    using System.ComponentModel.DataAnnotations;
    using System.ComponentModel.DataAnnotations.Schema;
    using System.Data.Entity.Spatial;

    public partial class NetworkConnectionRule
    {
        [System.Diagnostics.CodeAnalysis.SuppressMessage("Microsoft.Usage", "CA2214:DoNotCallOverridableMethodsInConstructors")]
        public NetworkConnectionRule()
        {
            StepOneQuestionnaires = new HashSet<StepOneQuestionnaire>();
        }

        [Key]
        [DatabaseGenerated(DatabaseGeneratedOption.None)]
        public long NetworkConnectionRule_ID { get; set; }

        [Required]
        [StringLength(25)]
        public string NewtorkConnectionName { get; set; }

        [Required]
        [StringLength(100)]
        public string ConnectionRule { get; set; }

        [System.Diagnostics.CodeAnalysis.SuppressMessage("Microsoft.Usage", "CA2227:CollectionPropertiesShouldBeReadOnly")]
        public virtual ICollection<StepOneQuestionnaire> StepOneQuestionnaires { get; set; }
    }
}
