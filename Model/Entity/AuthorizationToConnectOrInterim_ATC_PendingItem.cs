namespace Vulnerator.Model.Entity
{
    using System;
    using System.Collections.Generic;
    using System.Collections.ObjectModel;
    using System.ComponentModel.DataAnnotations;
    using System.ComponentModel.DataAnnotations.Schema;

    public partial class AuthorizationToConnectOrInterim_ATC_PendingItem
    {
        public AuthorizationToConnectOrInterim_ATC_PendingItem()
        { StepOneQuestionnaires = new ObservableCollection<StepOneQuestionnaire>(); }

        [Key]
        [DatabaseGenerated(DatabaseGeneratedOption.None)]
        public long AuthorizationToConnectOrInterim_ATC_PendingItem_ID { get; set; }

        [Required]
        [StringLength(50)]
        [Column("AuthorizationToConnectOrInterim_ATC_PendingItem")]
        public string AuthorizationToConnectOr_Interim_ATC_PendingItem { get; set; }

        [Required]
        public DateTime AuthorizationToConnectOrInterim_ATC_PendingItemDueDate { get; set; }
        
        [Required]
        public long StepOneQuestionnaire_ID { get; set; }
        
        [System.Diagnostics.CodeAnalysis.SuppressMessage("Microsoft.Usage", "CA2227:CollectionPropertiesShouldBeReadOnly")]
        public virtual ICollection<StepOneQuestionnaire> StepOneQuestionnaires { get; set; }
    }
}
