/********************************************************************************************************************
/   AUTHORS: ELF, Verring
/   PROGRAM NAME: win_survey.cpp
/   PROGRAM DESCRIPTION: Windows Host Enumeration Survey
/   FUNCTIONS:
/       get-systeminfo
/           gather basic system information. (Hardware/OS Info)
/       get-interactivelogons
/           get information about which users are interactively logged on to the system
/       get-lastlogin
/            get information about the last logged on user
/       get-networkinfo
/           get information about the network adapters the host has.
/       get-processes
/           report the running proccesses on the host
/       get-netstat
/           report all the network connections the host has.
/       get-routes
/           report any routes the host has.
/       get-hotfixes
/           report all patches on the system
**********************************************************************************************************************/
#include <Windows.h>
#include <iostream>
#include "Function_calls.h"



int main(void)
{
	getSystemInfo();

	getchar();
	getchar();
	return 0;
}


