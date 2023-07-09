# MSSQL SECURITY CHECK FRAMEWORK

MSSQLSC is a comprehensive toolkit, incorporating advanced tools and methodologies, specifically designed for performing in-depth audits on MSSQL databases. It is more than just a static set of tools; it's a dynamic framework that continuously evolves to meet the demands of the changing landscape of database security and audit requirements. I am dedicated to constantly updating and refining MSSQLSC, adding new features and methodologies based on the latest best practices and standards in the industry. 

# TABLE OF CONTENTS

1. [Introduction and Audit Objectives](#introduction-and-audit-objectives)
2. [Audit Methodology](#audit-methodology)
3. [Scope of the Audit](#scope-of-the-audit)
4. [Database Configuration Review](#database-configuration-review)
5. [Stored Procedures and Functions](#stored-procedures-and-functions)
6. [Security Measures Analysis](#security-measures-analysis)
7. [Access Control Review](#access-control-review)
8. [Authentication Mechanism Review](#authentication-mechanism-review)
9. [User Roles and Privileges](#user-roles-and-privileges)
10. [Audit Trail Review](#audit-trail-review)
11. [Backup and Recovery Procedures Review](#backup-and-recovery-procedures-review)
12. [Patch Management Review](#patch-management-review)
13. [Incident Response Plan Review](#incident-response-plan-review)
14. [Application Security Review](#application-security-review)
15. [Performance Review](#performance-review)
16. [Compliance Verification](#compliance-verification)
17. [Report and Recommendations](#report-and-recommendations)
18. [Appendix](#appendix)
19. [Approval and Signoff](#approval-and-signoff)

## CONTENTS
- [ ] Appendix[^1]
- [ ] Links[^2]

# AUDIT METHODOLOGY

The audit methodology incorporated in the MSSQLSC toolkit embodies a rigorous and systematic approach, ensuring a comprehensive and thorough review of the MSSQL databases. This adaptable framework begins with a meticulous planning stage, where the precise scope of the audit, including specific databases or operations, is clearly defined. The subsequent data collection stage involves MSSQLSC's advanced tools working seamlessly to gather the necessary data, all while ensuring minimal disruption to the ongoing database operations. This includes a thorough extraction of schemas, table structures, stored procedures, user permissions, and more.

Upon successful data collection, a detailed analysis is performed on the gathered data to identify potential security vulnerabilities, performance issues, and any instances of non-compliance with industry standards. The methodology emphasizes the importance of transparent reporting, meticulously crafting detailed reports that not only outline the identified issues but also provide their potential impacts, along with solid recommendations for remediation.

An integral part of this methodology is the review process, an iterative cycle that encourages continuous improvements in database management practices. This process allows for the perpetual refinement and evolution of the toolkit, making MSSQLSC a dynamic auditing solution that continuously adapts to the ever-changing landscape of database security.

Throughout the entire auditing process, MSSQLSC upholds a strong commitment to data privacy and integrity, ensuring that all sensitive information is handled securely. The adaptive nature of this toolkit ensures that it continually aligns with evolving data privacy standards and best practices in data management.

# SCOPE OF THE AUDIT

The scope of the audit defines the boundaries and the specific areas of the MSSQL databases that will be subject to examination during the audit process. This includes, but is not limited to, the evaluation of specific databases, tables, stored procedures, user roles, security measures, access controls, and the database's overall configuration. It also involves reviewing the database's backup and recovery procedures, patch management practices, incident response plans, application security, and performance. The scope is determined based on various factors such as business needs, compliance requirements, and risk assessments. Establishing a clear and comprehensive scope is a critical step in the audit process. It ensures that all essential aspects of the database environment are thoroughly audited, potential vulnerabilities are identified, and the necessary recommendations are made to improve security, efficiency, and overall database performance.

As part of the initial audit phase, identifying the database is an essential step.

Server Name and SQL Server Instance Name:
```
SELECT SERVERPROPERTY('MachineName') AS ServerName,
       SERVERPROPERTY('InstanceName') AS InstanceName;
```
SQL Server Version, Edition, and Engine Edition:
```
SELECT SERVERPROPERTY('ProductVersion') AS SQLServerVersion, 
       SERVERPROPERTY('ProductLevel') AS SQLServerLevel,
       SERVERPROPERTY('Edition') AS SQLServerEdition,
       SERVERPROPERTY('EngineEdition') AS SQLEngineEdition;
```
Operating System Information:
```
SELECT SERVERPROPERTY('IsClustered') AS IsClustered,
       SERVERPROPERTY('IsFullTextInstalled') AS IsFullTextInstalled,
       SERVERPROPERTY('IsIntegratedSecurityOnly') AS IsIntegratedSecurityOnly,
       SERVERPROPERTY('IsSingleUser') AS IsSingleUser,
       SERVERPROPERTY('OSVersion') AS OSVersion;
```
 
Regarding the IP address and MAC address, these are generally part of the server infrastructure details and may not be directly queried from SQL Server. They can be found using system-level commands or by checking the network configuration in the operating system where SQL Server is running.

For Windows, you can use `ipconfig /all` command in command prompt to get IP and MAC addresses.

For Linux, you can use `ifconfig` or `ip addr` to get the network configuration details.

# DATABASE CONFIGURATION REVIEW

The Database Configuration Review forms an integral part of the MSSQL audit. This phase involves a meticulous examination of the MSSQL databases' configuration settings to ensure they align with industry best practices, regulatory requirements, and specific organizational needs. Areas of focus include:

## Server Configuration

This includes review of the server settings like memory allocation, parallel processing settings, network configuration, and other server parameters that influence the overall performance and stability of the database server.

To check server-level configuration values:
```
EXEC sp_configure;
```
To check memory usage:
```
SELECT * FROM sys.dm_os_process_memory;
```

## Database Settings

Examination of the individual database settings such as database compatibility levels, recovery model, Auto-Shrink and Auto-Grow settings, collation settings, and more. These parameters directly impact the database's operational efficiency, data integrity, and recovery capabilities.

Note: Replace 'YourDatabase' with the actual database name.

To check database-level settings:
```
SELECT * FROM YourDatabase.sys.database_files;
```
To check database compatibility level, recovery model, and other settings:
```
SELECT * FROM sys.databases WHERE name = 'YourDatabase';
```

## Security Configuration

Review of the security configurations such as login settings, role permissions, firewall settings, and encryption methods. This assessment ensures that the database is protected against unauthorized access and data breaches.

Note: Replace 'YourDatabase' with the actual database name.

To view all SQL logins and their server role association:
```
EXEC sp_helpsrvrolemember;
```
To list all database users and associated roles:
```
USE YourDatabase;
EXEC sp_helprole;
```

## Maintenance Plans

Assessment of the scheduled maintenance plans including index maintenance, statistics updates, integrity checks, and backup routines. This ensures the optimal performance and reliability of the database.

Maintenance plans can be reviewed and configured in the SQL Server Management Studio (SSMS) under Management > Maintenance Plans.

## System Health Checks

Regular system health checks including the review of system logs, SQL Server error logs, and database error logs to identify any recurring issues or anomalies that might indicate a problem.

To check SQL Server logs:
```
EXEC xp_readerrorlog;
```

## High Availability and Disaster Recovery Settings

Review of high availability (HA) and disaster recovery (DR) settings such as AlwaysOn availability groups, database mirroring, log shipping, etc. This ensures business continuity and data availability in case of any unforeseen incidents.

For AlwaysOn availability groups, run the following:
```
SELECT * FROM sys.dm_hadr_availability_group_states;
SELECT * FROM sys.dm_hadr_availability_replica_states;
```

## Initiative

The Database Configuration Review is not a one-time task but a continuous part of the database audit process. Regular monitoring and reviewing of the database configuration play a crucial role in maintaining the health and performance of the database system.

# STORED PROCEDURES AND FUNCTIONS

The review of stored procedures and functions forms a critical component of the MSSQL audit process. These encapsulate the logic of the applications and are a common target for SQL injection attacks. Thus, it's important to ensure they're written securely and perform efficiently.

The audit of stored procedures and functions encompasses the following steps:

Note: Replace 'YourDatabase' with the actual database name.

## List All Stored Procedures and Functions

First, it's important to retrieve a list of all stored procedures and functions. This can be done with the following SQL commands:
```
SELECT name, type_desc 
FROM YourDatabase.sys.procedures;

SELECT name, type_desc 
FROM YourDatabase.sys.objects 
WHERE type_desc LIKE '%FUNCTION%';
```
Each stored procedure and function should be individually reviewed for security vulnerabilities. This includes checking for:

- Dynamic SQL that could potentially be exploited for SQL injection attacks.
- Excessive permissions that may violate the principle of least privilege.
- Direct access to tables, when access should be restricted to specific views.

Stored procedures and functions should also be analyzed for performance issues. This could involve checking for:

- Unused or inefficient indexes.
- Potential blocking issues.
- Inefficient queries that could be rewritten for better performance.

Each stored procedure and function should be well-documented, making it easier for any developer or DBA to understand their purpose, inputs, outputs, and any potential side effects.

# SECURITY MEASURES ANALYSIS

Security measures analysis is a critical part of the MSSQL audit process. It involves examining the different security mechanisms in place to protect the data stored in the database, mitigate threats, and ensure compliance with regulations. Key components of this analysis:

## Server-Level Security

This includes checking the server configuration, ensuring it's secured with firewall protection, up-to-date antivirus software, and ensuring the server is kept up-to-date with security patches.

- Use the Windows Defender Firewall with Advanced Security (or the equivalent on the server's operating system) to check the firewall rules.
- Use the antivirus software's control panel to check the status of the antivirus software.
- Use Windows Update (or the equivalent on the server's operating system) to check for available security updates.

## Database-Level Security

This involves checking database permissions to ensure that users and roles have been granted the minimum required permissions based on the principle of least privilege.
```
SELECT pr.principal_id, pr.name, pr.type_desc, 
       pe.permission_name, pe.state_desc
FROM sys.database_permissions pe
INNER JOIN sys.database_principals pr 
ON pe.grantee_principal_id = pr.principal_id;
```

## Encryption

Encryption of data at rest and in transit is important for securing sensitive data. For data at rest, check if Transparent Data Encryption (TDE) is enabled:
```
SELECT DB_Name(database_id) as DatabaseName, 
       encryption_state 
FROM sys.dm_database_encryption_keys;
```
For data in transit, check if the Force Encryption option is enabled on the SQL Server's network protocol (can be checked in SQL Server Configuration Manager).

## SQL Server Authentication Mode

SQL Server supports two authentication modes: Windows Authentication Mode (recommended due to its integration with Windows security features) and SQL Server and Windows Authentication Mode. This can be checked by:
```
EXEC xp_loginconfig 'login mode';
```

## Audit Logging

Audit logging helps in tracking access and changes made to the database. Ensure that auditing is enabled and properly configured.

## Data Masking and Row-Level Security

Check if sensitive data is being protected using features like Dynamic Data Masking and Row-Level Security.

Through this analysis, we will ensure that the MSSQL database has robust security measures in place.

# ACCESS CONTROL REVIEW

Access control is a key part of database security, ensuring that only authorized users have access to the data they need to perform their roles. A review of access controls should be an essential part of your MSSQL audit process, including the following aspects:

## User Accounts

A list of all database users, including system administrators, and their respective roles and permissions should be compiled and reviewed. This can be done using the following command:
```
SELECT DP1.name AS UserName, 
       DP2.name AS RoleName
FROM sys.database_role_members DRM
RIGHT OUTER JOIN sys.database_principals DP1
    ON DRM.member_principal_id = DP1.principal_id
LEFT OUTER JOIN sys.database_principals DP2
    ON DRM.role_principal_id = DP2.principal_id
WHERE DP1.type = 'S'
ORDER BY DP1.name;
```

## Roles and Permissions

The roles assigned to each user should be checked to ensure that they're appropriate for each user's job responsibilities, following the principle of least privilege. You can view the permissions of each role with:
```
SELECT DP1.name AS RoleName,
       DP2.name AS PermissionName,
       DP2.type AS PermissionType
FROM sys.database_role_members DRM
RIGHT OUTER JOIN sys.database_principals DP1
    ON DRM.member_principal_id = DP1.principal_id
LEFT OUTER JOIN sys.database_permissions DP2
    ON DRM.role_principal_id = DP2.grantee_principal_id
WHERE DP1.type = 'R'
ORDER BY DP1.name;
```

## Authentication Mechanisms

Review the authentication mechanisms in place, including password policies and the use of multi-factor authentication if applicable.

## Review of Administrative Accounts

Special attention should be paid to accounts with administrative privileges. The number of these accounts should be kept to a minimum and their activities should be closely monitored.

## Inactive Users

Review for any inactive user accounts, which could pose a potential security risk. Inactive accounts should be disabled or removed.

## Access to Sensitive Data

Review who has access to sensitive data. Access should be strictly controlled and logged.

# AUTHENTICATION MECHANISM REVIEW

Ensuring robust and secure authentication mechanisms is vital to protect data integrity and privacy within an MSSQL environment. Authentication is the process that verifies the identity of a user, process, or system. During the MSSQL audit process, an in-depth review of the authentication mechanisms should be conducted.

Key components of this review:

## Authentication Mode

SQL Server supports two authentication modes - Windows Authentication Mode and Mixed Mode (Windows Authentication and SQL Server Authentication).

- Windows Authentication is generally recommended due to its integration with Windows' security features. In this mode, users are authenticated by the Windows operating system before SQL Server is accessed.
- Mixed Mode allows users to connect through either Windows Authentication or SQL Server Authentication. In the latter, SQL Server validates the account name and password using information in the SQL Server master database.

To check the authentication mode, you can run the following SQL command:
```
EXEC xp_loginconfig 'login mode';
```

## Password Policies

For SQL Server Authentication, SQL Server supports standard password policies of the Windows operating system. This includes complexity validation, password history, and enforcement of password expiration. To retrieve the password policy information for SQL Server logins, you can use:
```
SELECT name, is_policy_checked, is_expiration_checked
FROM sys.sql_logins;
```

## Multi-Factor Authentication (MFA)

MFA adds an additional layer of security and is particularly recommended for accounts with elevated privileges. While SQL Server does not directly support MFA, it can be implemented through Azure Active Directory.

## Certificates and Asymmetric Keys

For connections requiring a higher level of security, SQL Server supports certificate-based and asymmetric key-based authentication.

## Contained Database Users

In a contained database, the user identity and related security information are stored within the database, and not in the master database. This can simplify the management of user logins, particularly in high availability and disaster recovery scenarios.

To list all contained database users, use the following query:
```
SELECT DP.name, DP.type_desc
FROM sys.database_principals AS DP
WHERE DP.authentication_type_desc = 'DATABASE';
```

# USER ROLES AND PRIVILEGES

The review of user roles and privileges is a critical aspect of any MSSQL audit process. It ensures that users have been assigned the appropriate level of access and permissions necessary to perform their roles, following the principle of least privilege.

## User Role Assignment

All users should be assigned appropriate roles that align with their job responsibilities. You can review the user roles using the following SQL command:
```
SELECT DP1.name AS UserName, 
       DP2.name AS RoleName
FROM sys.database_role_members DRM
RIGHT OUTER JOIN sys.database_principals DP1
    ON DRM.member_principal_id = DP1.principal_id
LEFT OUTER JOIN sys.database_principals DP2
    ON DRM.role_principal_id = DP2.principal_id
WHERE DP1.type = 'S'
ORDER BY DP1.name;
```

## Role Permissions

Check the permissions of each role to ensure that they align with what's necessary for that role. You can view the permissions of each role with:
```
SELECT DP1.name AS RoleName,
       DP2.name AS PermissionName,
       DP2.type AS PermissionType
FROM sys.database_role_members DRM
RIGHT OUTER JOIN sys.database_principals DP1
    ON DRM.member_principal_id = DP1.principal_id
LEFT OUTER JOIN sys.database_permissions DP2
    ON DRM.role_principal_id = DP2.grantee_principal_id
WHERE DP1.type = 'R'
ORDER BY DP1.name;
```

## Administrative Privileges

Accounts with elevated privileges such as 'db_owner' and 'sysadmin' should be kept to a minimum and monitored closely. You can check the members of a specific role like 'sysadmin' using the following command:
```
EXEC sp_helpsrvrolemember 'sysadmin';
```

## Object-Level Permissions

Permissions at the object level (tables, views, procedures, functions, etc.) should be reviewed. You can view these permissions with:
```
SELECT object_name(major_id) AS Object,
       USER_NAME(grantee_principal_id) AS Grantee,
       permission_name
FROM sys.database_permissions
WHERE class = 1;
```

## User Creation and Deletion

Monitor the creation and deletion of database users to detect unauthorized access or excessive permissions.

# AUDIT TRAIL REVIEW

An audit trail is a record of all activities that occur within a system. Reviewing the audit trail is a crucial part of the MSSQL audit process as it can help identify unauthorized activities or anomalies that might indicate a security issue.

Key components of the audit trail review include:

## SQL Server Audit

SQL Server provides robust auditing capabilities. Ensure that SQL Server Audit is enabled and properly configured to log relevant events such as login success and failure, changes to database schema or security settings, data modification, etc.

To view the server-level audits, use the following command:
```
SELECT * 
FROM sys.server_audits;
```
To view the database-level audits, use:
```
SELECT * 
FROM sys.database_audit_specifications;
```

## Audit Log Review

Regularly review audit logs for unusual activity. This includes login attempts from unusual locations or at odd hours, multiple failed login attempts, changes to security settings, or unexplained data modifications.

## Retention Policy

Ensure that an appropriate audit log retention policy is in place. The retention period should be sufficient to meet both operational needs and compliance requirements.

## Archiving

Older audit logs should be archived for future reference. Consider using automated tools to simplify the archiving process.

## Log Analysis Tools

Consider using automated log analysis tools, which can simplify the process of sorting through large amounts of log data and can help quickly identify suspicious activities.

# BACKUP AND RECOVERY PROCEDURES REVIEW

The review of backup and recovery procedures is an integral part of the MSSQL audit process. It ensures the ability to recover data and maintain system availability in the event of a disaster, hardware failure, or data corruption.

The following are key components to consider when reviewing backup and recovery procedures:

## Backup Strategy

A suitable backup strategy must be in place, depending on the business requirements. This might include full, differential, or transaction log backups. To check the last backup times for databases, you can use:
```
SELECT database_name, 
       MAX(backup_finish_date) AS LastBackUpTime
FROM   msdb.dbo.backupset
GROUP  BY database_name 
ORDER  BY 2 DESC;
```

## Backup Frequency

The frequency of backups should align with the amount of data the business can afford to lose (the Recovery Point Objective or RPO).

## Backup Verification

Backups should be regularly verified to ensure they are not corrupt and can be used for recovery. This can be achieved by periodically performing restore operations on a separate system.

## Offsite Storage

Backups should be stored offsite or in a geographically separate location to protect against regional disasters.

## Recovery Plan

A recovery plan should be documented and regularly tested. The plan should clearly define the steps to take in case of different types of failures and identify the personnel responsible for carrying out those steps.

## Security of Backups

Backups should be secured to prevent unauthorized access. This includes encryption of backup data and secure management of encryption keys.

## Log Shipping

For critical systems, consider using techniques like log shipping, which can minimize downtime and data loss by maintaining a backup server updated with transaction log backups from the primary server.


[^1]: Templates.
[^2]: Important Links.
