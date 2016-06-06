use cybersecurity;


select 
    Application.Application_Name,
    Vulnerability.Vulnerability_Name
from
    application
        inner join
    Vulnerability ON Vulnerability.Application_Application_ID = Application.Application_ID
order by Application.Application_Name desc;




select 
    *
from
    outlook_email;

select 
    *
from
    severity_map; where location = 'Eloy, AZ';


select 
    *
from
    incident_history;




select 
    vulnerability.Vulnerability_Name,
    vulnerability.Severity_Level,
    vulnerability.application_application_ID,
    severity_map.zip,
    system_finding.Incoming_IP address
from
    vulnerability
        inner join
    severity_map ON severity_map.Vulnerability_Vulnerability_ID = vulnerability.Vulnerability_ID
        inner join
    system_finding ON severity_map.Vulnerability_Vulnerability_ID = vulnerability.Vulnerability_ID
group by severity_map.zip
having vulnerability.Severity_Level = 'High';





select 
    *
from
    vulnerability
        inner join
    severity_map ON severity_map.Vulnerability_Vulnerability_ID = vulnerability.Vulnerability_ID
        inner join
    system_finding ON severity_map.Vulnerability_Vulnerability_ID = vulnerability.Vulnerability_ID
group by severity_map.zip
having vulnerability.Severity_Level = 'High';






select 
    *
from
    vulnerability
        inner join
    severity_map ON severity_map.Vulnerability_Vulnerability_ID = vulnerability.Vulnerability_ID
        inner join
    system_finding ON severity_map.Vulnerability_Vulnerability_ID = vulnerability.Vulnerability_ID
group by severity_map.zip
having vulnerability.Severity_Level = 'low'
    OR vulnerability.Severity_Level = 'medium';




select 
    *
from
    vulnerability
        inner join
    severity_map ON severity_map.Vulnerability_Vulnerability_ID = vulnerability.Vulnerability_ID
        inner join
    system_finding ON severity_map.Vulnerability_Vulnerability_ID = vulnerability.Vulnerability_ID
group by severity_map.zip
having vulnerability.Severity_Level = 'High';





select 
    *
from
    vulnerability
        inner join
    severity_map ON severity_map.Vulnerability_Vulnerability_ID = vulnerability.Vulnerability_ID
        inner join
    system_finding ON severity_map.Vulnerability_Vulnerability_ID = vulnerability.Vulnerability_ID
where
    vulnerability.Severity_Level = 'High'
order by Vulnerability_ID desc;




CREATE VIEW Hacker_Details AS
    SELECT 
        System_Finding.Pseudonym,
        Incident_History.Incident_Location,
        system_finding.Incoming_IP
    FROM
        System_Finding
            inner join
        Incident_History ON System_Finding.Incident_History_ID = Incident_History.Incident_History_ID
    group by Pseudonym;





select * from Hacker_Details;




drop view hacker_Details;





CREATE VIEW Hacker_Details AS
    SELECT 
        System_Finding.Pseudonym,
        Incident_History.Incident_Location,
        system_finding.Incoming_IP,
        incident_history.Last_Detected
    FROM
        System_Finding
            inner join
        Incident_History ON System_Finding.Incident_History_ID = Incident_History.Incident_History_ID
    group by Pseudonym;



select *from hacker_details;


count(vulnerability.Severity_Level) = 




Select 
    Incident_History.Last_Detected,
    Incident_History.First_Detected,
    System_Finding.Incoming_IP
from
    Incident_History
        inner join
    System_Finding ON Incident_History.Incident_History_ID = System_Finding.Incident_History_ID;


select *from incident_history;


select 
    *
from
    application;

SELECT 
    Application_ID, Application_Name
FROM
    Application
WHERE
    Application_Name IN (SELECT 
            Application_Name
        FROM
            Application
        WHERE
            Application_Type = 'Finanacial');


create view genuine_email_rec AS
    select 
        *
    from
        outlook_email
    where
        threat_flag = 0;

select 
    *
from
    genuine_email_rec;

select 
    *
from
    outlook_email;





START TRANSACTION ;
savepoint sp_1;
UPDATE Outlook_Email 
SET 
    Email_ID = 'team10@gmail.comm'
WHERE
    Event_ID = 1600;
SAVEPOINT sp1;
UPDATE Outlook_Email 
SET 
    Email_ID = 'TEAM_8@gmail.comm'
WHERE
    Event_ID = 1601;
SELECT 
    *
FROM
    Outlook_Email;
ROLLBACK TO SAVEPOINT sp1;
COMMIT;
SELECT 
    *
FROM
    Outlook_Email;
ROLLBACK;



START TRANSACTION ;
savepoint sp_2;
UPDATE Vulnerability 
SET 
    Sys_Damage_Property = 'Data loss'
WHERE
    Exposure_Time > 50
        && Severity_Level = 'medium';
SAVEPOINT sp2;
UPDATE Vulnerability 
SET 
    Sys_Damage_Property = 'Password compromised'
WHERE
    Exposure_Time < 30
        && Severity_Level = 'Low';
SELECT 
    *
FROM
    Vulnerability
where
    Severity_Level = 'Medium';
ROLLBACK TO SAVEPOINT sp2;
COMMIT;
SELECT 
    *
FROM
    Vulnerability
where
    Severity_Level = 'Low';
ROLLBACK;

select 
    *
from
    vulnerability;


create user 'Admin'@'localhost' identified by 'Admin';
create user 'Employee'@'localhost' identified by 'Emp';
create user 'RSA'@'localhost' identified by 'RSA';

grant All privileges on cybersecurity.*  to 'Admin'@'localhost';
grant select, update,insert on cybersecurity.*  to 'RSA'@'localhost';
grant all  on cybersecurity.Outlook_Email to 'Employee'@'localhost';

select host, user from mysql.user;


#Subquery

select 
    vulnerability.severity_level,
    vulnerability.vulnerability_name,
    Application.Application_Name
from
    vulnerability
        right outer join
    application ON vulnerability.Application_Application_ID = application.application_id
where
    (vulnerability.severity_level = 'High')
        && (application.Application_Type = (select 
            Application_Type
        from
            Application
        where
            Application.Outlook_Email_Event_ID = '1600'));





select * from cybersecurity.rsa_security_team;

update cybersecurity.rsa_security_team 
set Security_Team_Location = 'phoenix,AZ'
 where security_team_ID =245685;


# index creation

Create index Emp_Search on Employee(Employee_Name);
create index hacker_search on System_Finding (Pseudonym);


select * from Employee where employee_name = 'Zorina Abreu';


#Stored procedure:

USE CYBERSECURITY;
create user 'Adn'@'localhost' identified by 'Adn';
grant select, update,insert on cybersecurity.*  to 'Adn'@'localhost';

CREATE PROCEDURE Vulnerabilitydetails()
SELECT  Vulnerability_ID,vulnerability_Name,exposure_name,software_affected,incident_location
FROM SYSTEM_FINDING
INNER JOIN Vulnerability
ON Vulnerability.vulnerability_ID=system_finding.vulnerability_vulnerability_ID
INNER JOIN  INCIDENT_HISTORY
ON  system_finding.Incident_History_ID= INCIDENT_HISTORY.Incident_History_ID;
grant execute on procedure Vulnerabilitydetails to 'Adn'@'localhost';
CALL Vulnerabilitydetails();

DROP PROCEDURE Vulnerabilitydetails;



# stored procdure two


CREATE PROCEDURE Asset_Related_Vulnerability()
SELECT  Assets_Linked.Asset_Name,Assets_Linked.Asset_Type,Vulnerability.Vulnerability_Name, Vulnerability.Sys_Damage_Property
FROM Assets_Linked
INNER JOIN Vulnerability
ON Vulnerability.Assets_Linked_Asset_ID=Assets_Linked.Asset_ID
where vulnerability.Severity_Level='high';
drop procedure Asset_Related_Vulnerability;
CALL Asset_Related_Vulnerability();

DROP PROCEDURE Vulnerabilitydetails;
grant execute on procedure Vulnerabilitydetails to 'Admin'@'localhost';








