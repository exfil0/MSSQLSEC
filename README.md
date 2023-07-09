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

Note: Replace 'YourDatabase' with your actual database name.

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

Note: Replace 'YourDatabase' with your actual database name.

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

The review of stored procedures and functions forms a critical component of the MSSQL audit process. These encapsulate the logic of your applications and are a common target for SQL injection attacks. Thus, it's important to ensure they're written securely and perform efficiently.

The audit of stored procedures and functions encompasses the following steps:

Note: Replace 'YourDatabase' with your actual database name.

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

[^1]: Templates.
[^2]: Important Links.
