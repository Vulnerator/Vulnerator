namespace Vulnerator
{
    using System;
    using System.Collections.Generic;
    using System.ComponentModel.DataAnnotations;
    using System.ComponentModel.DataAnnotations.Schema;
    using System.Data.Entity.Spatial;

    public partial class WindowsDomainUserSetting
    {
        [System.Diagnostics.CodeAnalysis.SuppressMessage("Microsoft.Usage", "CA2214:DoNotCallOverridableMethodsInConstructors")]
        public WindowsDomainUserSetting()
        {
            EnumeratedWindowsUsers = new HashSet<EnumeratedWindowsUser>();
        }

        [Key]
        [DatabaseGenerated(DatabaseGeneratedOption.None)]
        public long Domain_Settings_ID { get; set; }

        [Required]
        [StringLength(5)]
        public string Domain_Is_Disabled { get; set; }

        [Required]
        [StringLength(5)]
        public string Domain_Is_Disabled_Automatically { get; set; }

        [Required]
        [StringLength(5)]
        public string Domain_Cant_Change_PW { get; set; }

        [Required]
        [StringLength(5)]
        public string Domain_Never_Changed_PW { get; set; }

        [Required]
        [StringLength(5)]
        public string Domain_Never_Logged_On { get; set; }

        [Required]
        [StringLength(5)]
        public string Domain_PW_Never_Expires { get; set; }

        [System.Diagnostics.CodeAnalysis.SuppressMessage("Microsoft.Usage", "CA2227:CollectionPropertiesShouldBeReadOnly")]
        public virtual ICollection<EnumeratedWindowsUser> EnumeratedWindowsUsers { get; set; }
    }
}
