# **Windows Survey**
This program is intended to be a windows post-exploitation tool to scout the target Windows operating system via API calls. The program will gather the information from the operating system and will output it to a google protobuff for an easy to read format.

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

OPTIONAL
    get-lastlogin
    get-antivirus
    get-hotfixes

getSystemInfo();

    getSystemInfo will gather basic system information. (Hardware/OS Info)
        OS Name - Version Helpers API
        Architecture - GetNativeSystemInfo API 
        Hostname - GetComputerNameEX API
        Domain Name - GetComputerNameEX API
        FQDN - GetComputerNameEX API
        Windows Directory - GetWindowsDirectory API
        System Directory - GetSystemDirectory API
        Local Time - GetLocalTime API
        System Time - GetSystemTime API

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

OPTIONAL FUNCTIONS
get-lastlogin

    get-lastlogin will get information about the last logged on user


Obviously this has the potential to be a lot of data. I would like to add functionality to format the output file to cleanly organize the host information for analysis. Possible output to csv for import into excel with separate pages for each function.      