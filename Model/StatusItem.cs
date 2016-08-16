using Vulnerator.ViewModel;

namespace Vulnerator.Model
{
    public class StatusItem : BaseInpc
    {
        private string _item
        {
            get;
            set;
        }
        public string Item
        {
            get { return _item; }
            set
            {
                if (_item != value)
                {
                    _item = value;
                    OnPropertyChanged("Item");
                }
            }
        }

        public StatusItem(string item)
        { this._item = item; }
    }
}
