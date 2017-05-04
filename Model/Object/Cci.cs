using System.Collections.Generic;

namespace Vulnerator.Model.Object
{
    public class Cci
    {
        public string CciItem;
        public string Definition;
        public string Status;
        public string Type;
        public List<CciReference> CciReferences;
    }

    public class CciReference
    {
        public string Title;
        public string Version;
        public string Index;
    }
}
