namespace Vulnerator.Model.Entity
{
    using System.Collections.Generic;
    using System.Collections.ObjectModel;
    using System.ComponentModel.DataAnnotations;
    using System.ComponentModel.DataAnnotations.Schema;

    public partial class Category
    {
        [System.Diagnostics.CodeAnalysis.SuppressMessage("Microsoft.Usage", "CA2214:DoNotCallOverridableMethodsInConstructors")]
        public Category()
        { TestScheduleItems = new ObservableCollection<TestScheduleItem>(); }

        [Key]
        [DatabaseGenerated(DatabaseGeneratedOption.None)]
        public long Category_ID { get; set; }

        [Column("Category")]
        [Required]
        [StringLength(25)]
        public string Category1 { get; set; }

        [System.Diagnostics.CodeAnalysis.SuppressMessage("Microsoft.Usage", "CA2227:CollectionPropertiesShouldBeReadOnly")]
        public virtual ICollection<TestScheduleItem> TestScheduleItems { get; set; }
    }
}
