using System.Collections.Generic;

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
        public List<Label> Labels = new List<Label>();
    }

    public class Label
    {
        public string Color { get; set; }
        public string Name { get; set; }
    }
}
