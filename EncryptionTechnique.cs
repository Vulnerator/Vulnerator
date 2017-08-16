namespace Vulnerator
{
    using System;
    using System.Collections.Generic;
    using System.ComponentModel.DataAnnotations;
    using System.ComponentModel.DataAnnotations.Schema;
    using System.Data.Entity.Spatial;

    public partial class EncryptionTechnique
    {
        [System.Diagnostics.CodeAnalysis.SuppressMessage("Microsoft.Usage", "CA2214:DoNotCallOverridableMethodsInConstructors")]
        public EncryptionTechnique()
        {
            StepOneQuestionnaires = new HashSet<StepOneQuestionnaire>();
        }

        [Key]
        [DatabaseGenerated(DatabaseGeneratedOption.None)]
        public long EncryptionTechnique_ID { get; set; }

        [Column("EncryptionTechnique")]
        [Required]
        [StringLength(100)]
        public string EncryptionTechnique1 { get; set; }

        [Required]
        [StringLength(500)]
        public string KeyManagement { get; set; }

        [System.Diagnostics.CodeAnalysis.SuppressMessage("Microsoft.Usage", "CA2227:CollectionPropertiesShouldBeReadOnly")]
        public virtual ICollection<StepOneQuestionnaire> StepOneQuestionnaires { get; set; }
    }
}
