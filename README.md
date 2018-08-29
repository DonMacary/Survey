# **Windows Survey**
This program is intended to be a windows post-exploitation tool to scout the target Windows operating system via API calls. The program will gather the information from the operating system and will output it to a file (eventually using google protobuff for easily transferable data)

**Proposed project timeline:** (remove from final)

    Day 1 - Project outline
    Day 2 & 3 - Learn windows API in c++, Google protobuff
    Day 4 - Create one function (system info) and output to file using protobuff
    Day 5 - 8 Create as many of the other functions as possible

**The program will (hopefully) incorporate the following functions:**

	getSystemInfo();
	getUserName();
	getNetworkInfo();
	getNetstat();
	getRoutes();
    getProcesses();

OPTIONAL
    get-lastlogin
    get-antivirus
    get-hotfixes

getSystemInfo();

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

getUserName()

    getUserName() will get information about which user is interactively logged on to the system using the GetUserNameEx API

getNetworkInfo()

    getNetworkInfo() will get information about the network adapters the host has using the GetAapterInfo API.

get-processes

    get-procceses will report the running proccesses on the host. Further implementations will only gather processes created in the last hour, processes without a service etc...

getNetstat()

    getNetstat() will report all the network connections the host has.

getRoutes()

    getRoutes() will report any routes the host has.

getMemoryInfo();

    gets info on the computer's memory.

getProcesses();

	get-procceses will report the running proccesses on the host. Further implementations will only gather processes created in the last hour, processes without a service etc...

OPTIONAL FUNCTIONS
get-lastlogin

    get-lastlogin will get information about the last logged on user

    