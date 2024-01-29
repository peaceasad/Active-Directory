# Enumeration

Load a PowerShell script using dot sourcing.

.  C: AD\Tools\PowerView.ps1
Above line have space after (.)


A module (or a script) can be imported with:
Import-Module C: \AD\Tools\ADModule-master\ActiveDirectory\ActiveDirectory.psd1

All the commands in a module can be listed with: 
>Get-Command -Module <module name>

It is NOT a security measure, it is present to prevent user from accidently executing scripts. 
Several ways to bypass 
>powershell –ExecutionPolicy bypass 

>powershell –c <cmd>

>powershell –encodedcommand $env:PSExecutionPolicyPreference="bypass"``

Above command is technique to bypass powershell, to get powershell terminal from cmd.

## Domain Enumeration

We are Using Two Tools, one is AD-Module and second one is PowerView

### 1st COMMAND PROMPT (AD-Module)

First run invishishell as non admin script
It will convert our cmd into PowerShell
Command:
>C:\CRTP_New\Tools\InviShell\RunWithRegistryNonAdmin\

Now Import the AD-Module
>Import-Module C:\AD\Tools\ADModule-master\Microsoft.ActiveDirectory.Management.dll 

>Import-Module C:\AD\Tools\ADModule-master\ActiveDirectory\ActiveDirectory.psd1 

**Get current domain**  
>Get-ADDomain (ActiveDirectory Module)

Get object of another domain 
>Get-ADDomain -Identity moneycorp.local


Get domain controllers for the current domain 
>Get-ADDomainController

Get domain controllers for another domain 
>Get-ADDomainController -DomainName moneycorp.local - Discover

Get a list of users in the current domain 
>Get-ADUser -Filter * -Properties * 

>Get-ADUser -Identity student1 -Properties * 


Get a list of users in the current domain 
>Get-ADUser -Filter * -Properties * 
>Get-ADUser -Identity student1 -Properties * 

Get a list of users in the current domain 
>Get-ADUser -Filter * -Properties * 

>Get-ADUser -Identity student1 -Properties *

Get list of all properties for users in the current domain  
>Get-ADUser -Filter * -Properties * | select -First 1 | 
Get-Member - MemberType *Property | select Name 

>Get-ADUser -Filter * -Properties * | select name,logoncount,@{expression={[datetime]::fromFileTime($_.pwdlastset )}}


Search for a particular string in a user's attributes: 
>Get-ADUser -Filter 'Description -like "*built*"' - Properties Description | select name,Description

Get OUs in a domain
>Get-ADOrganizationalUnit -Filter * -Properties *



---



### 2nd COMMAND PROMPT (PowerView)

Command:
>C:\CRTP_New\Tools\InviShell\RunWithRegistryNonAdmin\

Now run PowerView after getting inviShell
>.  C:\AD\Tools\PowerView.ps1
Above line have space afpter (.)


Get current domain 
>Get-Domain (PowerView) 

Get object of another domain 
>Get-Domain –Domain moneycorp.local 


Get domain policy for the current domain 
>Get-DomainPolicyData 

>(Get-DomainPolicyData).systemaccess 

>(Get-DomainPolicyData).kerberospolicy

Get domain policy for another domain 
>(Get-DomainPolicyData –domain moneycorp.local).systemaccess

Get domain controllers for the current domain 
>Get-DomainController 

Get domain controllers for another domain 
>Get-DomainController –Domain moneycorp.local 

Get a list of users in the current domain 
>Get-DomainUser 

>Get-DomainUser –Identity student1 

Get a list of users in the current domain 
>Get-DomainUser 

>Get-DomainUser –Identity student1 

Get a list of users in the current domain
>Get-DomainUser 

>Get-DomainUser –Identity student1

Get list of all properties for users in the current domain 
>Get-DomainUser -Identity student1 -Properties * 

>Get-DomainUser -Properties samaccountname,logonCount

Always use active account and this is best way to find active account

Search for a particular string in a user's attributes: 
>Get-DomainUser -LDAPFilter "Description=*built*" | Select name,Description

Try to find all user descriptions (TASK)

Get a list of computers in the current domain (page 47)
>Get-DomainComputer | select Name 

>Get-DomainComputer –OperatingSystem "*Server 2016*" 

>Get-DomainComputer -Ping

Get all the groups in the current domain 
>Get-DomainGroup | select Name 

>Get-DomainGroup –Domain  

Get all groups containing the word "admin" in group name 
>Get-DomainGroup *admin*

Get all the members of the Domain Admins group (page 49)
>Get-DomainGroupMember -Identity "Domain Admins" -Recurse

[-Recurse show the nested group member of Domain Group]


Get the group membership for a user: 
>Get-DomainGroup –UserName "student1"

List all the local groups on a machine (needs administrator privs on non-dc machines) : (page 50)
>Get-NetLocalGroup -ComputerName dcorp-dc -ListGroups 

Get members of all the local groups on a machine (needs administrator privs on non-dc machines) 
>Get-NetLocalGroup -ComputerName dcorp-dc -Recurse 

Get members of the local group "Administrators" on a machine (needs administrator privs on non-dc machines) : 
>Get-NetLocalGroupMember -ComputerName dcorp-dc -GroupName Administrators 

Get actively logged users on a computer (needs local admin rights on the target) 
>Get-NetLoggedon –ComputerName <server name>

Get locally logged users on a computer (needs remote registry on the target - started by-default on server OS)
>Get-LoggedonLocal -ComputerName dcorp-dc  

Get the last logged user on a computer (needs administrative rights and remote registry on the target) 
>Get-LastLoggedOn –ComputerName  <server name>

Find shares on hosts in current domain. 
>Invoke-ShareFinder –Verbose 

Find sensitive files on computers in the domain 
>Invoke-FileFinder –Verbose 

Get all fileservers of the domain 
>Get-NetFileServer

GPO Enumeration

Get list of GPO in current domain.
>Get-DomainGPO 

>Get-DomainGPO -ComputerIdentity dcorp-student1

Here we can enumarate, what is group policy and where do they apply 

We cannot eumerate, exactly what setting is seted 

What exactly setting is applied on the remote machine.


Get GPO(s) which use Restricted Groups or groups.xml for interesting users 
>Get-DomainGPOLocalGroup

(Above command shows restricted group in the Domain, but lab is not seted for this command.)

Get OUs in a domain 
>Get-DomainOU 

Get GPO applied on an OU. Read GPOname from gplink attribute from 
>Get-NetOU Get-DomainGPO -Identity "{AB306569-220D-43FF-B03B83E8F4EF8081}"


>(Get-DomainOU -Identity StudentMachine).distinguishedname | %{Get-DomainComputer -SearchBase $_} | select name

Above command give result of all the computer present in OU

>Get-DomainGPO -Identity (Get-DomainOU -Identity StudentMachines).gplink.substring(11,(Get-DomainOU -Identit StudentMachines).gplink.length-72)

Above command gives you result of group policy applied on student machine

### ACL

Get the ACLs associated with the specified object 
> Get-DomainObjectAcl -SamAccountName student1 –ResolveGUIDs

Get the ACLs associated with the specified prefix to be used for search 
>Get-DomainObjectAcl -SearchBase "LDAP://CN=Domain Admins,CN=Users,DC=dollarcorp,DC=moneycorp,DC=local" -ResolveGUIDs - Verbose

We can also enumerate ACLs using ActiveDirectory module but without resolving GUIDs 
>(Get-Acl 'AD:\CN=Administrator,CN=Users,DC=dollarcorp,DC=moneycorp,DC=local') .Access 

### Domain Trust

Get a list of all domain trusts for the current domain 
>Get-DomainTrust 

>Get-DomainTrust –Domain us.dollarcorp.moneycorp.local


### Domain User Hunting


Find computers where a domain admin (or specified user/group) has sessions: 
>Find-DomainUserLocation -Verbose 

>Find-DomainUserLocation -UserGroupIdentity "RDPUsers" 

**Purpose**: It could be used to identify and report on the access rights and permissions of domain users within an Active Directory environment.

The output could include details about the user's group memberships, permissions on specific resources, and other relevant information.


>Get-DomainGroupMember

>Get-DomainGroupMember -Identity "Domain Admins"

The cmdlet is designed to retrieve the members of a specified Active Directory group.

The output typically includes information about the members of the specified group, such as their usernames, distinguished names, and other attributes.

>Get-NetComputer

The cmdlet is designed to enumerate and gather information about computer objects in the Active Directory domain. 

The output typically includes information about various computer objects in the domain, such as computer names, DNS names, operating systems, and other relevant details

Find computers where a domain admin session is available and current user has admin access (uses Test-AdminAccess).
>Find-DomainUserLocation -CheckAccess 


Find computers (File Servers and Distributed File servers) where a domain admin session is available. 
>Find-DomainUserLocation –Stealth 


