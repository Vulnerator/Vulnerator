namespace Vulnerator
{
    using System;
    using System.Collections.Generic;
    using System.ComponentModel.DataAnnotations;
    using System.ComponentModel.DataAnnotations.Schema;
    using System.Data.Entity.Spatial;

    public partial class TestScheduleItem
    {
        [System.Diagnostics.CodeAnalysis.SuppressMessage("Microsoft.Usage", "CA2214:DoNotCallOverridableMethodsInConstructors")]
        public TestScheduleItem()
        {
            SAPs = new HashSet<SAP>();
        }

        [Key]
        [DatabaseGenerated(DatabaseGeneratedOption.None)]
        public long TestScheduleItem_ID { get; set; }

        [StringLength(100)]
        public string TestEvent { get; set; }

        public long Category_ID { get; set; }

        public long DurationInDays { get; set; }

        public virtual Category Category { get; set; }

        [System.Diagnostics.CodeAnalysis.SuppressMessage("Microsoft.Usage", "CA2227:CollectionPropertiesShouldBeReadOnly")]
        public virtual ICollection<SAP> SAPs { get; set; }
    }
}
