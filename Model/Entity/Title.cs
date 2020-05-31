using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.ComponentModel;
using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;

namespace Vulnerator.Model.Entity
{
    public class Title : INotifyPropertyChanged
    {
        public event PropertyChangedEventHandler PropertyChanged;
        
        public Title()
        { }

        [Key]
        [DatabaseGenerated(DatabaseGeneratedOption.None)]
        public long Title_ID { get; set; }

       [Required]
       [StringLength(200)]
       public string TitleName { get; set; }
       
       [Required]
       [StringLength(50)]
       public string TitleAcronym { get; set; }
    }
}