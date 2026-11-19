Vulnerator 2.0 add-ons
======================

Add-ons are optional extensions (for example dashboards or integrations). This release includes one:

  Dashboards (folder "Dashboards") - part of Vulnerator 2.0 (MIT). Offline dashboards: open findings by
  severity, top hosts, compliance by control family, POA&M aging, trend, coverage gaps, STIG currency and
  active IAVMs. Open it from the Dashboards item in the menu. Its source is in the Vulnerator repository
  (AddOns/Dashboards). To remove it, close Vulnerator and delete the Dashboards folder.

To install another add-on, put its files in this folder: the main file ends in .AddOn.dll. An add-on that
comes with several files can have a folder of its own here. Then restart Vulnerator.

Settings > Integrations lists every add-on found and whether it loaded. An add-on that cannot be loaded is
skipped and the reason is written to the Vulnerator log; Vulnerator itself keeps working.

If Windows marks the files as downloaded from the internet, Vulnerator cannot load them: right-click each
file (or the .zip before extracting it), choose Properties, tick Unblock, and restart Vulnerator.

Add-ons see the data read-only and cannot change the database.
