namespace Vulnerator.Model.Entity
{
    using System;
    using System.Collections.Generic;
    using System.Collections.ObjectModel;
    using System.ComponentModel.DataAnnotations;
    using System.ComponentModel.DataAnnotations.Schema;

    public partial class AuthorizationToConnectOrInterim_ATC_PendingItems
    {
        [System.Diagnostics.CodeAnalysis.SuppressMessage("Microsoft.Usage", "CA2214:DoNotCallOverridableMethodsInConstructors")]
        public AuthorizationToConnectOrInterim_ATC_PendingItems()
        { AuthorizationToConnectOrInterim_ATC = new ObservableCollection<AuthorizationToConnectOrInterim_ATC>(); }

        [Key]
        [DatabaseGenerated(DatabaseGeneratedOption.None)]
        public long AuthorizationToConnectOrInterim_ATC_PendingItem_ID { get; set; }

        [Required]
        [StringLength(50)]
        public string AuthorizationToConnectOrInterim_ATC_PendingItem { get; set; }

        public DateTime AuthorizationToConnectOrInterim_ATC_PendingItemDueDate { get; set; }

        [System.Diagnostics.CodeAnalysis.SuppressMessage("Microsoft.Usage", "CA2227:CollectionPropertiesShouldBeReadOnly")]
        public virtual ICollection<AuthorizationToConnectOrInterim_ATC> AuthorizationToConnectOrInterim_ATC { get; set; }
    }
}
