# **Windows Survey**
This program is intended to be a windows post-exploitation tool to scout the target Windows operating system via API calls. The program will gather the information from the operating system and will output it to a google protobuff for an easy to read format.

**Proposed project timeline:** (remove from final)

    Day 1 - Project outline
    Day 2 & 3 - Learn windows API in c++, Google protobuff
    Day 4 - Create one function (system info) and output to file using protobuff
    Day 5 - 8 Create as many of the other functions as possible

**The program will (hopefully) incorporate the following functions:**

    get-systeminfo
    get-interactivelogons
    get-lastlogin
    get-networkinfo
    get-processes
    get-antivirus
    get-netstat
    get-routes
    get-hotfixes

get-systeminfo

    get-systeminfo will gather basic system information. (Hardware/OS Info)
        OS Name 
        OS Version
        Architecture
        Hostname
        Domain Name
        FQDN
        Windows Directory
        System Directory
        Local Time
        Last Boot time

get-interactivelogons

    get-interactivelogons will get information about which users are interactively logged on to the system

get-lastlogin

    get-lastlogin will get information about the last logged on user

get-networkinfo

    get-networkinfo will get information about the network adapters the host has using the GetAapterInfo API.

get-processes

    get-procceses will report the running proccesses on the host. Further implementations will only gather processes created in the last hour, processes without a service etc...

get-netstat

    get-netstat will report all the network connections the host has.

get-routes

    get-routes will report any routes the host has.


Obviously this has the potential to be a lot of data. I would like to add functionality to format the output file to cleanly organize the host information for analysis. Possible output to csv for import into excel with separate pages for each function.      