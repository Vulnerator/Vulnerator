namespace Vulnerator.Model.Entity
{
    using System;
    using System.Collections.Generic;
    using System.ComponentModel.DataAnnotations;
    using System.ComponentModel.DataAnnotations.Schema;
    using System.Data.Entity.Spatial;

    public partial class WindowsLocalUserSetting
    {
        [System.Diagnostics.CodeAnalysis.SuppressMessage("Microsoft.Usage", "CA2214:DoNotCallOverridableMethodsInConstructors")]
        public WindowsLocalUserSetting()
        {
            EnumeratedWindowsUsers = new HashSet<EnumeratedWindowsUser>();
        }

        [Key]
        [DatabaseGenerated(DatabaseGeneratedOption.None)]
        public long WindowsLocalUserSettings_ID { get; set; }

        [Required]
        [StringLength(5)]
        public string WindowsLocalUserIsDisabled { get; set; }

        [Required]
        [StringLength(5)]
        public string WindowsLocalUserIsDisabledAutomatically { get; set; }

        [Required]
        [StringLength(5)]
        public string WindowsLocalUserCantChangePW { get; set; }

        [Required]
        [StringLength(5)]
        public string WindowsLocalUserNeverChangedPW { get; set; }

        [Required]
        [StringLength(5)]
        public string WindowsLocalUserNeverLoggedOn { get; set; }

        [Required]
        [StringLength(5)]
        public string WindowsLocalUserPW_NeverExpires { get; set; }

        [System.Diagnostics.CodeAnalysis.SuppressMessage("Microsoft.Usage", "CA2227:CollectionPropertiesShouldBeReadOnly")]
        public virtual ICollection<EnumeratedWindowsUser> EnumeratedWindowsUsers { get; set; }
    }
}
