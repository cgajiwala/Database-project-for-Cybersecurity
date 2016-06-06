USE cybersecurity;


#update trigger
Create table backup_severity (
ID int not null ,
location varchar(30) not null,
changed_on datetime default null,
action varchar(30) default null
);

select * from backup_severity;

DROP trigger update_severity_map;

DELIMITER $$
CREATE TRIGGER updateseverity
AFTER UPDATE ON severity_map
FOR EACH ROW 
BEGIN
INSERT INTO backup_severity
SET action = 'update',
ID = OLD.severity_map_ID,
location = OLD.location,
changed_on = NOW();      
END$$
DELIMITER ;
Drop trigger updateseverity;


UPDATE severity_map
SET location= 'losangeles'
WHERE severity_map_ID =2123 ;

select * from severity_map;
Select * from backup_severity ; 

SHOW TRIGGERS WHERE 'table' = 'severity_map';


#Delete trigger
USE cybersecurity ;
Create table backup_Application(
ID int not null,
Name varchar(30) not null,
Type varchar(30) not null,
criticality varchar(30) not null,
changed_on datetime default null
);
Drop table backup_vulnerability_channel;
select * from backup_Application;
DELIMITER $$
CREATE TRIGGER After_delete_Application
AFTER DELETE ON Application
FOR EACH ROW
BEGIN
INSERT INTO backup_Application VALUES 
(OLD.Application_ID,
OLD.Application_Name,OLD.Application_type,
OLD.criticality,
NOW());
END$$
DELIMITER ;

DELETE FROM Application
WHERE Application_ID=50;
SET foreign_key_checks=0;
DELETE FROM application
where application_ID =51;
select * from application;
select*from backup_application ;

USE cybersecurity;



#insert trigger
CREATE table insert_mitigation(
ID varchar(30) not null,
level varchar(30) not null,
Pin varchar(30) not null,
status varchar(30) not null,
antispyware varchar(30) not null,
changed_on datetime default null
);
drop table insert_mitigation;

Delimiter $$
CREATE TRIGGER after_insert_mitigation
after insert on mitigation_plan
for each row
begin
insert into insert_mitigation values
(new.mitigation_ID,
new.mitigation_level,
new.RSA_Secure_Pin,
new.device_status,
new.anti_spyware,
now()
);
END$$
DELIMITER ;

select * from mitigation_plan ;

INSERT INTO mitigation_plan values
('MITID100','3','STID787388','Active','Norton');

SELECT * FROM insert_mitigation;

