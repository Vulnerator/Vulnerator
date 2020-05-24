namespace Vulnerator.Model.Entity
{
    using System;
    using System.Collections.Generic;
    using System.Collections.ObjectModel;
    using System.ComponentModel.DataAnnotations;
    using System.ComponentModel.DataAnnotations.Schema;

    public partial class AuthorizationToConnectOrInterim_ATC
    {
        [System.Diagnostics.CodeAnalysis.SuppressMessage("Microsoft.Usage", "CA2214:DoNotCallOverridableMethodsInConstructors")]
        public AuthorizationToConnectOrInterim_ATC()
        {
            StepOneQuestionnaires = new ObservableCollection<StepOneQuestionnaire>();
            AuthorizationToConnectOrInterim_ATC_PendingItems = new ObservableCollection<AuthorizationToConnectOrInterim_ATC_PendingItems>();
        }

        [Key]
        [DatabaseGenerated(DatabaseGeneratedOption.None)]
        public long AuthorizationToConnectOrInterim_ATC_ID { get; set; }

        public DateTime AuthorizationToConnectOrInterim_ATC_GrantedDate { get; set; }

        public DateTime AuthorizationToConnectOrInterim_ATC_ExpirationDate { get; set; }

        [StringLength(25)]
        public string AuthorizationToConnectOrInterim_ATC_CND_ServiceProvider { get; set; }

        [System.Diagnostics.CodeAnalysis.SuppressMessage("Microsoft.Usage", "CA2227:CollectionPropertiesShouldBeReadOnly")]
        public virtual ICollection<StepOneQuestionnaire> StepOneQuestionnaires { get; set; }

        [System.Diagnostics.CodeAnalysis.SuppressMessage("Microsoft.Usage", "CA2227:CollectionPropertiesShouldBeReadOnly")]
        public virtual ICollection<AuthorizationToConnectOrInterim_ATC_PendingItems> AuthorizationToConnectOrInterim_ATC_PendingItems { get; set; }
    }
}
