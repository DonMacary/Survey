# **Windows Survey**
This program is intended to be a windows post-exploitation tool to scout the target Windows operating system via API calls. The program will gather the information from the operating system and will output it to a file (eventually using google protobuff for easily transferable data)

**NOTE: All functions now take in a ofstream file object and print to a file called results.txt, this file name and locaton can be changed by editing the win_survey.cpp file!!**

**The program will (hopefully) incorporate the following functions:**

	getSystemInfo();
	getUserName();
	getNetworkInfo();
	getNetstat();
	getRoutes();
    getProcesses();
	getMemoryInfo();
	getHDDInfo();
	getBIOS();

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

getHDDInfo();

	gets the computer's HDD total space and available space.

getProcesses();

	get-procceses will report the running proccesses on the host. Further implementations will only gather processes created in the last hour, processes without a service etc...

getBIOS();
	
	gets some basic data from the BIOS.

OPTIONAL FUNCTIONS
get-lastlogin

    get-lastlogin will get information about the last logged on user

    