using System.Collections;
using System.Collections.Specialized;
using System.ComponentModel;
using System.Threading;
using System.Windows.Data;


namespace Vulnerator.View.ViewHelper
{
    public class AutoRefreshCollectionViewSource : CollectionViewSource
    {
        private readonly SynchronizationContext _synchronizationContext = SynchronizationContext.Current;

        protected override void OnSourceChanged(object oldSource, object newSource)
        {
            if (oldSource != null)
            {
                SubscribeSourceEvents(oldSource, true);
            }
            if (newSource != null)
            {
                SubscribeSourceEvents(newSource, false);
            }
            base.OnSourceChanged(oldSource, newSource);
        }

        private void Item_PropertyChanged(object sender, PropertyChangedEventArgs e)
        {
            bool refresh = false;

            foreach (SortDescription sort in SortDescriptions)
            {
                if (sort.PropertyName == e.PropertyName)
                {
                    refresh = true;
                    break;
                }
            }

            if (!refresh)
            {
                foreach (GroupDescription group in GroupDescriptions)
                {
                    PropertyGroupDescription propertyGroup = group as PropertyGroupDescription;
                    if (propertyGroup != null && propertyGroup.PropertyName == e.PropertyName)
                    {
                        refresh = true;
                        break;
                    }
                }
            }

            if (refresh)
            {
                if (SynchronizationContext.Current == _synchronizationContext)
                {
                    View.Refresh();
                }
                else
                {
                    _synchronizationContext.Send(_ => View.Refresh(), null);
                }
            }
        }

        private void Source_CollectionChanged(object sender, NotifyCollectionChangedEventArgs e)
        {
            if (e.Action == NotifyCollectionChangedAction.Add)
            {
                SubscribeItemsEvents(e.NewItems, false);
            }
            else if (e.Action == NotifyCollectionChangedAction.Remove)
            {
                SubscribeItemsEvents(e.OldItems, true);
            }
        }

        private void SubscribeItemEvents(object item, bool remove)
        {
            INotifyPropertyChanged notify = item as INotifyPropertyChanged;
            if (notify != null)
            {
                if (remove)
                {
                    notify.PropertyChanged -= Item_PropertyChanged;
                }
                else
                {
                    notify.PropertyChanged += Item_PropertyChanged;
                }
            }
        }

        private void SubscribeItemsEvents(IEnumerable items, bool remove)
        {
            foreach (object item in items)
            {
                SubscribeItemEvents(item, remove);
            }
        }

        private void SubscribeSourceEvents(object source, bool remove)
        {
            INotifyCollectionChanged notify = source as INotifyCollectionChanged;
            if (notify != null)
            {
                if (remove)
                {
                    notify.CollectionChanged -= Source_CollectionChanged;
                }
                else
                {
                    notify.CollectionChanged += Source_CollectionChanged;
                }
            }
            SubscribeItemsEvents((IEnumerable)source, remove);
        }

    }
}
