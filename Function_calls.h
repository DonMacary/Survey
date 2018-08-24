#pragma once
#define _WIN32_WINNT 0x0500

#include <windows.h>
#include <stdio.h>
#include <tchar.h>
#include <string.h>
#include <iostream>
#include <VersionHelpers.h>


void getSysName();
void getOSInfo();
void getSystemInfo();

//Uses GetComputerNameEX API to gather the FQDN, Hostname and Domain Name from the system
void getSysName()
{

	TCHAR buffer[256] = TEXT(""); //Variable to store the name
	DWORD dwSize = sizeof(buffer); // buffer size

	if (!GetComputerNameEx(ComputerNameDnsFullyQualified, buffer, &dwSize)) // grabs the FQDN
	{
		std::cout << "Get FQDN failed" << std::endl;
	}
	else
	{
		std::cout << "FQDN: " << buffer << std::endl;			//print it out
	}
	ZeroMemory(buffer, dwSize);				//empty the string  and the size

	if (!GetComputerNameEx(ComputerNameDnsHostname, buffer, &dwSize))		//grabs the hostname
	{
		std::cout << "Get Hostname failed" << std::endl;
	}
	else
	{
		std::cout << "Hostname: " << buffer << std::endl;		//prints it out
	}
	
	ZeroMemory(buffer, dwSize);				 //empty the string  and the size

	if (!GetComputerNameEx(ComputerNameDnsDomain, buffer, &dwSize))		//grabs the domain name
	{
		std::cout << "Get Domain name failed" << std::endl;
	}
	else
	{
		std::cout << "Domain Name: " << buffer << std::endl;	//prints it out
	}
	
	ZeroMemory(buffer, dwSize);				 //empty the string  and the size

};

//This function uses the Version Helpers API to check the Operating system version. See README for details on why this method was used vs others.
void getOSInfo()
{
	//Since the helper functions only report if the system is that version or greater, An iterator is needed to keep track of all the tests the system has returned true for.
	//The versions are checked in ascending order to make this possible. 
	int i = 0;			//iterator to count which version of windows
	bool server = false;
	std::cout << "OS Name: ";
	if (IsWindowsXPOrGreater())
	{
		i++;
	}

	if (IsWindowsXPSP1OrGreater())
	{
		i++;
	}

	if (IsWindowsXPSP2OrGreater())
	{
		i++;
	}

	if (IsWindowsXPSP3OrGreater())
	{
		i++;
	}

	if (IsWindowsVistaOrGreater())
	{
		i++;
	}

	if (IsWindowsVistaSP1OrGreater())
	{
		i++;
	}

	if (IsWindowsVistaSP2OrGreater())
	{
		i++;
	}

	if (IsWindows7OrGreater())
	{
		i++;
	}

	if (IsWindows7SP1OrGreater())
	{
		i++;
	}

	if (IsWindows8OrGreater())
	{
		i++;
	}

	if (IsWindows8Point1OrGreater())
	{
		i++;
	}

	if (IsWindows10OrGreater())
	{
		i++;
	}

	if (IsWindowsServer())
	{
		server = true;
	}
	//once we have checked all conditions including wherether or not it is a server then we can report the version based off how many tests it returned true for.
	switch (i)
	{
	case 0:
		std::cout << "PreWindows XP" << std::endl;
		break;
	case 1:
		//It is difficult to differentiate all the server versions, therefor I just report the generation of server (and not R2 etc...)
		if (server == true)
		{
			std::cout << "Windows Server 2000" << std::endl;
		}
		else
		{
			std::cout << "Windows XP" << std::endl;
		}

		break;
	case 2:
		if (server == true)
		{
			std::cout << "Windows Server 2000" << std::endl;
		}
		else
		{
			std::cout << "Windows XP Service Pack 1" << std::endl;
		}
		break;
	case 3:
		if (server == true)
		{
			std::cout << "Windows Server 2000" << std::endl;
		}
		else
		{
			std::cout << "Windows XP Service Pack 2" << std::endl;
		}
		break;
	case 4:
		if (server == true)
		{
			std::cout << "Windows Server 2000" << std::endl;
		}
		else
		{
			std::cout << "Windows XP Service Pack 3" << std::endl;
		}
		break;
	case 5:
		if (server == true)
		{
			std::cout << "Windows Server 2003" << std::endl;
		}
		else
		{
			std::cout << "Windows Vista" << std::endl;
		}
		break;
	case 6:
		if (server == true)
		{
			std::cout << "Windows Server 2003" << std::endl;
		}
		else
		{
			std::cout << "Windows Vista Service Pack 1" << std::endl;
		}
		break;
	case 7:
		if (server == true)
		{
			std::cout << "Windows Server 2003" << std::endl;
		}
		else
		{
			std::cout << "Windows Vista Service Pack 2" << std::endl;
		}
		break;
	case 8:
		if (server == true)
		{
			std::cout << "Windows Server 2008" << std::endl;
		}
		else
		{
			std::cout << "Windows 7" << std::endl;
		}
		break;
	case 9:
		if (server == true)
		{
			std::cout << "Windows Server 2008" << std::endl;
		}
		else
		{
			std::cout << "Windows 7 Service Pack 1" << std::endl;
		}
		break;
	case 10:
		if (server == true)
		{
			std::cout << "Windows Server 2012" << std::endl;
		}
		else
		{
			std::cout << "Windows 8" << std::endl;
		}
		break;
	case 11:
		if (server == true)
		{
			std::cout << "Windows Server 2012" << std::endl;
		}
		else
		{
			std::cout << "Windows 8.1" << std::endl;
		}

		break;
	case 12:
		if (server == true)
		{
			std::cout << "Windows Server 2016" << std::endl;
		}
		else
		{
			std::cout << "Windows 10" << std::endl;
		}

		break;
	default:
		std::cout << "Unknown Version" << std::endl;
		break;
	}


}



//gathers natvie system information and then checks the processor architecture and reports it. Uses the GetNativeSystemInfo API. 
void getArchitecture()
{
	std::cout << "Architecture: ";
	SYSTEM_INFO sys;
	GetNativeSystemInfo(&sys);
	//checks the SYSTEM_INFO object processor architecture parameter against a list of known values. These values were found on Microsofts Webstie:
	//https://msdn.microsoft.com/en-us/library/windows/desktop/ms724958(v=vs.85).aspx 
	switch (sys.wProcessorArchitecture)
	{
		case 0:
			std::cout << "x86" << std::endl;
			break;
		case 5:
			std::cout << "ARM" << std::endl;
			break;
		case 6:
			std::cout << "Intel Itanium-based" << std::endl;
			break;
		case 9:
			std::cout << "x64" << std::endl;
			break;
		case 12:
			std::cout << "ARM64" << std::endl;
			break;
		default:
			std::cout << "Unknown" << std::endl;
			break;
	}

}
void getSystemInfo()
{
	std::cout << "[+] System Information" << std::endl << std::endl;

	getOSInfo();
	getArchitecture();
	getSysName(); //gets the System hostname, FQDN and Domain Name

};