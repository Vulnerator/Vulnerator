-- Earlier versions named report 2 'Navy RAR'; rename it in place so existing filters are kept.
UPDATE RequiredReports
SET DisplayedReportName = 'Risk Assessment Report'
WHERE DisplayedReportName = 'Navy RAR';

INSERT INTO RequiredReports
VALUES (NULL,
        'eMASS-Importable POA&M',
        'Excel',
        'True',
        'Vulnerability Management');

INSERT INTO RequiredReports
VALUES (NULL,
        'Risk Assessment Report',
        'Excel',
        'True',
        'Vulnerability Management');

INSERT INTO RequiredReports
VALUES (NULL,
        'SCAP & STIG Discrepancies',
        'Excel',
        'True',
        'Vulnerability Management');

INSERT INTO RequiredReports
VALUES (NULL,
        'Global',
        'N/A',
        'True',
        'N/A');

INSERT INTO RequiredReports
VALUES (NULL,
        'eMASS Hardware/Software List',
        'Excel',
        'True',
        'Vulnerability Management');

-- Vulnerator 2.0: successors of the Vulnerator 6 "STIG Details" tab and PDF summary. Fixed IDs: the Reporting page
-- dispatches on RequiredReport_ID.
INSERT OR IGNORE INTO RequiredReports
VALUES (6,
        'STIG Details',
        'Excel',
        'True',
        'Vulnerability Management');

INSERT OR IGNORE INTO RequiredReports
VALUES (7,
        'PDF Summary',
        'PDF',
        'True',
        'Vulnerability Management');

INSERT OR IGNORE INTO RequiredReports
VALUES (8,
        'Ports, Protocols & Services',
        'Excel',
        'True',
        'Vulnerability Management');

-- INSERT INTO RequiredReports
-- VALUES (NULL,
--         'Excel Summary',
--         'Excel',
--         'True',
--         'Vulnerability Management');
--
-- INSERT INTO RequiredReports
-- VALUES (NULL,
--         'Vulnerability Deep Dive (By Finding Type)',
--         'Excel',
--         'True',
--         'Vulnerability Management');
-- 
-- INSERT INTO RequiredReports
-- VALUES (NULL,
--         'Test Plan',
--         'Excel',
--         'True',
--         'Vulnerability Management');
-- 
-- INSERT INTO RequiredReports
-- VALUES (NULL,
--         'OS Breakdown',
--         'Excel',
--         'False',
--         'Configuration Management');
-- 
-- INSERT INTO RequiredReports
-- VALUES (NULL,
--         'User Breakdown',
--         'Excel',
--         'False',
--         'Configuration Management');
-- 
-- INSERT INTO RequiredReports
-- VALUES (NULL,
--         'PDF Summary',
--         'PDF',
--         'False',
--         'Vulnerability Management');