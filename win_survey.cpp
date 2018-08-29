/********************************************************************************************************************
/   AUTHORS: ELF, Vering
/   PROGRAM NAME: win_survey.cpp
/   PROGRAM DESCRIPTION: Windows Host Enumeration Survey
/   FUNCTIONS:
/		getSystemInfo();
/			get-systeminfo will gather basic system information. (Hardware/OS Info)
/				OS Name 
/				OS Version
/				Architecture
/				Hostname
/				Domain Name
/				FQDN
/				Windows Directory
/				System Directory
/				Local Time
/				Last Boot time
/		getUserName();
/			getUserName() will get information about which user is interactively logged on to the system using the GetUserNameEx API
/		getNetworkInfo();
/			getNetworkInfo() will get information about the network adapters the host has using the GetAapterInfo API.
/		getNetstat();
/			getNetstat() will report all the network connections the host has.
/		getRoutes();
/			getRoutes() will report any routes the host has.
/		getMemoryInfo();
/			gets info on the computer's memory.
/		getProcesses();
/			get-procceses will report the running proccesses on the host. Further implementations will only gather processes created in the last hour, processes without a service etc...
**********************************************************************************************************************/
#define WIN32_LEAN_AND_MEAN

#undef _WINSOCKAPI_
#define _WINSOCKAPI_
#include <windows.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <iostream>
#include "Function_calls.h"

int main(void)
{
	getSystemInfo();
	getUserName();
	getNetworkInfo();
	getNetstat();
	getRoutes();
	getMemoryInfo(std::ofstream &outputfile);
<<<<<<< HEAD
	getHDDInfo(std::ofstream &outputfile);
=======
	getProcesses(std::ofstream &outputfile);
>>>>>>> 4edb1549908718060c417c60cd9ab0147de72b45
	getchar();
	getchar();
	return 0;
}