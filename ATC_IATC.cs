namespace Vulnerator
{
    using System;
    using System.Collections.Generic;
    using System.ComponentModel.DataAnnotations;
    using System.ComponentModel.DataAnnotations.Schema;
    using System.Data.Entity.Spatial;

    public partial class ATC_IATC
    {
        [System.Diagnostics.CodeAnalysis.SuppressMessage("Microsoft.Usage", "CA2214:DoNotCallOverridableMethodsInConstructors")]
        public ATC_IATC()
        {
            StepOneQuestionnaires = new HashSet<StepOneQuestionnaire>();
            ATC_IATC_PendingItems = new HashSet<ATC_IATC_PendingItems>();
        }

        [Key]
        [DatabaseGenerated(DatabaseGeneratedOption.None)]
        public long ATC_ID { get; set; }

        public DateTime ATC_GrantedDate { get; set; }

        public DateTime ATC_ExpirationDate { get; set; }

        [StringLength(25)]
        public string CND_ServiceProvider { get; set; }

        [System.Diagnostics.CodeAnalysis.SuppressMessage("Microsoft.Usage", "CA2227:CollectionPropertiesShouldBeReadOnly")]
        public virtual ICollection<StepOneQuestionnaire> StepOneQuestionnaires { get; set; }

        [System.Diagnostics.CodeAnalysis.SuppressMessage("Microsoft.Usage", "CA2227:CollectionPropertiesShouldBeReadOnly")]
        public virtual ICollection<ATC_IATC_PendingItems> ATC_IATC_PendingItems { get; set; }
    }
}
