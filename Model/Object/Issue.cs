using System.Collections.Generic;
using System.Collections.ObjectModel;

namespace Vulnerator.Model.Object
{
    public class Issue
    {
        public string Title { get; set; }
        public int Number { get; set; }
        public string Body { get; set; }
        public string HtmlUrl { get; set; }
        public string Milestone { get; set; }
        public int Comments { get; set; }
        public ObservableCollection<Label> Labels { get; set; }

        public Issue()
        { Labels = new ObservableCollection<Label>(); }
    }

    public class Label
    {
        public string Color { get; set; }
        public string Name { get; set; }

        public Label()
        { }
    }
}
