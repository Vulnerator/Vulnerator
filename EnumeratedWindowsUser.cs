namespace Vulnerator
{
    using System;
    using System.Collections.Generic;
    using System.ComponentModel.DataAnnotations;
    using System.ComponentModel.DataAnnotations.Schema;
    using System.Data.Entity.Spatial;

    public partial class EnumeratedWindowsUser
    {
        [System.Diagnostics.CodeAnalysis.SuppressMessage("Microsoft.Usage", "CA2214:DoNotCallOverridableMethodsInConstructors")]
        public EnumeratedWindowsUser()
        {
            WindowsDomainUserSettings = new HashSet<WindowsDomainUserSetting>();
            WindowsLocalUserSettings = new HashSet<WindowsLocalUserSetting>();
            EnumeratedWindowsGroups = new HashSet<EnumeratedWindowsGroup>();
        }

        [Key]
        [DatabaseGenerated(DatabaseGeneratedOption.None)]
        public long User_ID { get; set; }

        [Required]
        [StringLength(25)]
        public string User_Name { get; set; }

        [Required]
        [StringLength(5)]
        public string Is_Guest_Account { get; set; }

        [Required]
        [StringLength(5)]
        public string Is_Domain_Account { get; set; }

        [Required]
        [StringLength(5)]
        public string Is_Local_Acount { get; set; }

        [System.Diagnostics.CodeAnalysis.SuppressMessage("Microsoft.Usage", "CA2227:CollectionPropertiesShouldBeReadOnly")]
        public virtual ICollection<WindowsDomainUserSetting> WindowsDomainUserSettings { get; set; }

        [System.Diagnostics.CodeAnalysis.SuppressMessage("Microsoft.Usage", "CA2227:CollectionPropertiesShouldBeReadOnly")]
        public virtual ICollection<WindowsLocalUserSetting> WindowsLocalUserSettings { get; set; }

        [System.Diagnostics.CodeAnalysis.SuppressMessage("Microsoft.Usage", "CA2227:CollectionPropertiesShouldBeReadOnly")]
        public virtual ICollection<EnumeratedWindowsGroup> EnumeratedWindowsGroups { get; set; }
    }
}
