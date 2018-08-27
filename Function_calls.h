#pragma once
#pragma comment(lib, "Secur32.lib")
#pragma comment(lib, "iphlpapi.lib")
#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "netapi32.lib")
#define SECURITY_WIN32
//#define _WIN32_WINNT 0x0500
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif




#include <windows.h>
#include <stdio.h>
#include <tchar.h>
#include <string.h>
#include <iostream>
#include <VersionHelpers.h>
#include <security.h>
#include <iphlpapi.h>
#include <assert.h>
#include <LM.h>
#include <sddl.h>

void getSysName();
void getOSInfo();
void getArchitecture();
void getWindowsPath();
void getSystemPath();
void getTime();
void getSystemInfo();
void getNetworkInfo();
void getUserName();
int getAccountInfo(int argc, wchar_t * argv[]);

const wchar_t* userName[100];


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

};

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

};


//prints the path to the windows directory (most of the time this will be C:\Windows...) This uses the GetWindowsDirectory API. 
void getWindowsPath()
{
	TCHAR PATH[256] = TEXT("");		//variable to store the path
	DWORD size = sizeof(PATH);		//size of the path variable 
	UINT results = GetWindowsDirectory(PATH, size);		//stores the path in the variable and the sresult of the function is an int which means various things

														//if the result int is = 0 then the GetWindowsDirectory API failed
	if (results == 0)
	{
		std::cout << "Windows Directory Path: Failed to find" << std::endl;
	}
	//if the result is = the size of the path variable then it means that the path is too long to print (we would need to increase the path buffer)
	else if (results == size)
	{
		std::cout << "Windows Directory Path: Path is too large to print" << std::endl;
	}
	//otherwise were successful so print the path!
	else
	{
		std::cout << "Windows Directory Path: " << PATH << std::endl;
	}
};

//prints the path to the system directory (C:\Windows\System32 usually..) Uses the GetSystemDirectory API
void getSystemPath()
{
	TCHAR PATH[256] = TEXT("");		//variable to store the path
	DWORD size = sizeof(PATH);		//size of the path variable 
	UINT results = GetSystemDirectory(PATH, size);		//stores the path in the variable and the sresult of the function is an int which means various things
														//if the result int is = 0 then the GetWindowsDirectory API failed
	if (results == 0)
	{
		std::cout << "Windows System Path: Failed to find" << std::endl;
	}
	//if the result is = the size of the path variable then it means that the path is too long to print (we would need to increase the path buffer)
	else if (results == size)
	{
		std::cout << "Windows System Path: Path is too large to print" << std::endl;
	}
	//otherwise were successful so print the path!
	else
	{
		std::cout << "Windows System Path: " << PATH << std::endl;
	}

};

//utilizes the GetLocalTime and GetSystemTime APIs to report the local and system time of the host. 
void getTime()
{
	SYSTEMTIME localtime;			//local time variable
	SYSTEMTIME systime;				//system time (UTC) variable
	GetLocalTime(&localtime);		//API to get the local time
	GetSystemTime(&systime);		//API to get the system time
	std::cout << "Local Time: " << localtime.wMonth << "/" << localtime.wDay << "/" << localtime.wYear << " " << localtime.wHour << ":" << localtime.wMinute
		<< ":" << localtime.wSecond << std::endl;
	std::cout << "System Time: " << systime.wMonth << "/" << systime.wDay << "/" << systime.wYear << " " << systime.wHour << ":" << systime.wMinute
		<< ":" << systime.wSecond << std::endl;

};

//main function to report Target's system information. This is called in main. 
void getSystemInfo()
{
	std::cout << "[+] System Information" << std::endl << std::endl;

	getOSInfo();			//reports the operating system name
	getArchitecture();		//reports the system architecture type 
	getSysName();			//reports the System hostname, FQDN and Domain Name
	getWindowsPath();		//reports the Windows directory path
	getSystemPath();		//reports the System directory path
	getTime();				//reports thte Local and System time

};

//gets the username of the currently logged in user using the GetUserNameEx API
void getUserName()
{
	TCHAR buffer[256] = TEXT("");
	DWORD buffer_size = sizeof(buffer);
	LPDWORD nSize = &buffer_size;
	GetUserNameEx(NameSamCompatible, buffer, nSize);
	std::string user = buffer;

	std::cout << "NameSamCompatible: " << buffer << std::endl;
	for (int i = 0; i < 100; i++)
	{
		userName[i] = *user.c_str();
	}

};

//reports information about the network adapters on the host machine using the GetAdaptersInfo API. 
void getNetworkInfo()
{
	std::cout << std::endl << "[+] Network Adapters" << std::endl << std::endl;

	IP_ADAPTER_INFO  *pAdapterInfo;				//pointer to a adapter info 
	ULONG            ulOutBufLen;				//buffer for input parameter
	DWORD            dwRetVal;					//error checking variable


	pAdapterInfo = (IP_ADAPTER_INFO *)malloc(sizeof(IP_ADAPTER_INFO));		//allocating memory for the pointer
	ulOutBufLen = sizeof(IP_ADAPTER_INFO);									//declare the size of the buffer as the size of the adapter info pointer


	//initial GetAdapterInfo call with error checking - This call to the function is meant to fail, 
	//and is used to ensure that the ulOutBufLen variable specifies a size sufficient for holding all the information returned to pAdapterInfo
	if (GetAdaptersInfo(pAdapterInfo, &ulOutBufLen) != ERROR_SUCCESS) 
	{
		free(pAdapterInfo);		//free up the pointer so we can make the call again
		pAdapterInfo = (IP_ADAPTER_INFO *)malloc(ulOutBufLen);			//correctly initialize the size of the pointer based off the size of the buffer from the initial call
	}

	//now that we have the right size of the adapter pointer we call the function again and store the result in dwRetVal. We do an initial error check to make sure the function 
	//call went through and print if it failed.
	if ((dwRetVal = GetAdaptersInfo(pAdapterInfo, &ulOutBufLen)) != ERROR_SUCCESS) 
	{
		std::cout << "GetAdaptersInfo call failed with " << dwRetVal << std::endl;
	}

	//store the adapter information in a PIP_ADAPTER_INFO object, this is essentially an array that stores all the adapters. We will iterate through this array and 
	//print each adpaters information
	PIP_ADAPTER_INFO pAdapter = pAdapterInfo;
	while (pAdapter) {
		std::cout << "Adapter Name: " << pAdapter->Description << std::endl;			//displays thhe network adapter name
		std::cout << "\tIP Address: " << pAdapter->IpAddressList.IpAddress.String << std::endl;		//displays the ip address
		std::cout << "\tIP Mask: " << pAdapter->IpAddressList.IpMask.String << std::endl;			//displays the subnet mask
		std::cout << "\tGateway: " << pAdapter->GatewayList.IpAddress.String <<std::endl;			//displays the gateway
		//checks if dhcp is enabled, if so state so and if it can find the dhcp server address, report it.
		if (pAdapter->DhcpEnabled)
		{	
			std::cout << "\tDHCP Enabled: Yes" << std::endl;
			std::cout << "\t\tDHCP Server: \t" << pAdapter->DhcpServer.IpAddress.String << std::endl;
		}
		else
			std::cout << "\tDHCP Enabled: No" << std::endl;

		pAdapter = pAdapter->Next;	//move to the next adapter in the array
	}

	//free the object when done
	if (pAdapterInfo)
		free(pAdapterInfo);


}

//gets the user accounts.
int getAccountInfo(int argc, wchar_t * argv[])
{
	DWORD dwLevel = 0;
	LPUSER_INFO_0 pBuf = NULL;
	LPUSER_INFO_1 pBuf1 = NULL;
	LPUSER_INFO_2 pBuf2 = NULL;
	LPUSER_INFO_3 pBuf3 = NULL;
	LPUSER_INFO_4 pBuf4 = NULL;
	LPUSER_INFO_10 pBuf10 = NULL;
	LPUSER_INFO_11 pBuf11 = NULL;
	LPUSER_INFO_20 pBuf20 = NULL;
	LPUSER_INFO_23 pBuf23 = NULL;

	NET_API_STATUS nStatus;

	LPTSTR sStringSid = NULL;

	int i = 0;
	int j = 0;

	if (argc != 3)
	{
		std::cout << stderr << "Usage: " << argv[0] << "\\\\ServerName UserName" << std::endl;
		exit(1);
	}

	while (i < 24)
	{
		// Call the NetUserGetInfo function.

		dwLevel = i;

		std::cout << "\nCalling NetUserGetInfo with Servername=" << argv[1] << " Username=" << argv[2] << " Level=" << dwLevel << std::endl;
		nStatus = NetUserGetInfo(argv[1], argv[2], dwLevel, (LPBYTE *)&pBuf);
		
		// If the call succeeds, print the user information.
		
		if (nStatus == NERR_Success)
		{
			if (pBuf != NULL)
			{

				switch (i)
				{
				case 0:
					std::cout << "User account name: " << pBuf->usri0_name << std::endl;
					break;
				case 1:
					pBuf1 = (LPUSER_INFO_1)pBuf;
					std::cout << "User account name: " << pBuf1->usri1_name << std::endl;
					std::cout << "\tPassword: " << pBuf1->usri1_password << std::endl;
					std::cout << "\tPassword age (seconds): " << pBuf1->usri1_password_age << std::endl;
					std::cout << "\tPrivilege level: " << pBuf1->usri1_priv << std::endl;
					std::cout << "\tHome directory: " << pBuf1->usri1_home_dir << std::endl;
					std::cout << "\tUser comment: " << pBuf1->usri1_comment << std::endl;
					std::cout << "\tFlags (in hex): " << pBuf1->usri1_flags << std::endl;
					std::cout << "\tScript path: " << pBuf1->usri1_script_path << std::endl;
					break;
				case 2:
					pBuf2 = (LPUSER_INFO_2)pBuf;
					std::cout << "User account name: " << pBuf2->usri2_name << std::endl;
					std::cout << "\tPassword: " << pBuf2->usri2_password << std::endl;
					std::cout << "\tPassword age (seconds): " << pBuf2->usri2_password_age << std::endl;
					std::cout << "\tPrivilege level: " << pBuf2->usri2_priv << std::endl;
					std::cout << "\tHome directory: " << pBuf2->usri2_home_dir << std::endl;
					std::cout << "\tComment: " << pBuf2->usri2_comment << std::endl;
					std::cout << "\tFlags (in hex): " << pBuf2->usri2_flags << std::endl;
					std::cout << "\tScript path: " << pBuf2->usri2_script_path << std::endl;
					std::cout << "\tAuth flags (in hex): " << pBuf2->usri2_auth_flags << std::endl;
					std::cout << "\tFull name: " << pBuf2->usri2_full_name << std::endl;
					std::cout << "\tUser comment: " << pBuf2->usri2_usr_comment << std::endl;
					std::cout << "\tParameters: " << pBuf2->usri2_parms << std::endl;
					std::cout << "\tWorkstations: " << pBuf2->usri2_workstations << std::endl;
					std::cout << "\tLast logon (seconds since January 1, 1970 GMT: " << pBuf2->usri2_last_logon << std::endl;
					std::cout << "\tLast logoff (seconds since January 1, 1970 GMT): " << pBuf2->usri2_last_logoff << std::endl;
					std::cout << "\tAccount expires (seconds since January 1, 1970 GMT): " << pBuf2->usri2_acct_expires << std::endl;
					std::cout << "\tMax storage: " << pBuf2->usri2_max_storage << std::endl;
					std::cout << "\tUnits per week: " << pBuf2->usri2_units_per_week << std::endl;
					std::cout << "\tLogon hours: ";
					for (j = 0; j < 21; j++)
					{
						std::cout << (BYTE)pBuf2->usri2_logon_hours[j];
					}
					std::cout << std::endl;
					std::cout << "\tBad password count: " << pBuf2->usri2_bad_pw_count << std::endl;
					std::cout << "\tNumber of logons: " << pBuf2->usri2_num_logons << std::endl;
					std::cout << "\tLogon server: " << pBuf2->usri2_logon_server << std::endl;
					std::cout << "\tCountry code: " << pBuf2->usri2_country_code << std::endl;
					std::cout << "\tCode page: " << pBuf2->usri2_code_page << std::endl;
					break;
				case 4:
					pBuf4 = (LPUSER_INFO_4)pBuf;
					std::cout << "\tUser account name: " << pBuf4->usri4_name << std::endl;
					std::cout << "\tPassword: " << pBuf4->usri4_password << std::endl;
					std::cout << "\tPrivilege level: " << pBuf4->usri4_priv << std::endl;
					std::cout << "\tHome directory: " << pBuf4->usri4_home_dir << std::endl;
					std::cout << "\tComment: " << pBuf4->usri4_comment << std::endl;
					std::cout << "\tFlags (in hex): " << pBuf4->usri4_flags << std::endl;
					std::cout << "\tScript path: " << pBuf4->usri4_script_path << std::endl;
					std::cout << "\tAuth flags (in hex): " << pBuf4->usri4_auth_flags << std::endl;
					std::cout << "\tFull name: " << pBuf4->usri4_full_name << std::endl;
					std::cout << "\tUser comment: " << pBuf4->usri4_usr_comment << std::endl;
					std::cout << "\tParameters: " << pBuf4->usri4_parms << std::endl;
					std::cout << "\tWorkstations: " << pBuf4->usri4_workstations << std::endl;
					std::cout << "\tLast logon (seconds sinc January 1, 1970 GMT: " << pBuf4->usri4_last_logon << std::endl;
					std::cout << "\tLast logoff (seconds since January 1, 1970 GMT: " << pBuf4->usri4_last_logoff << std::endl;
					std::cout << "\tAccount expires (seconds since January 1, 1970 GMT: " << pBuf4->usri4_acct_expires << std::endl;
					std::cout << "\tMax storage: " << pBuf4->usri4_max_storage << std::endl;
					std::cout << "\tUnits per week: " << pBuf4->usri4_units_per_week << std::endl;
					std::cout << "\tLogon hours: ";
					for (j = 0; j < 21; j++)
					{
						std::cout << (BYTE)pBuf4->usri4_logon_hours[j];
					}
					std::cout << std::endl;
					std::cout << "\tBad password count: " << pBuf4->usri4_bad_pw_count << std::endl;
					std::cout << "\tNumber of logons: " << pBuf4->usri4_num_logons << std::endl;
					std::cout << "\tLogon server: " << pBuf4->usri4_logon_server << std::endl;
					std::cout << "\tCountry code: " << pBuf4->usri4_country_code << std::endl;
					std::cout << "\tCode page: " << pBuf4->usri4_code_page << std::endl;
					if (ConvertSidToStringSid
					(pBuf4->usri4_user_sid, &sStringSid))
					{
						std::cout << "\tUser SID: " << sStringSid << std::endl;
						LocalFree(sStringSid);
					}
					else
					{
						std::cout << "ConvertSidToStringSid failed with error " << GetLastError() << std::endl;
					}
					std::cout << "\tPrimary group ID: " << pBuf4->usri4_primary_group_id << std::endl;
					std::cout << "\tProfile: " << pBuf4->usri4_profile << std::endl;
					std::cout << "\tHome directory drive letter: " << pBuf4->usri4_home_dir_drive << std::endl;
					std::cout << "\tPassword expired information: " << pBuf4->usri4_password_expired << std::endl;
					break;
				case 10:
					pBuf10 = (LPUSER_INFO_10)pBuf;
					std::cout << "\tUser account name: " << pBuf10->usri10_name << std::endl;
					std::cout << "\tComment: " << pBuf10->usri10_comment << std::endl;
					std::cout << "\tUser comment: " << pBuf10->usri10_usr_comment << std::endl;
					std::cout << "\tFull name: " << pBuf10->usri10_full_name << std::endl;
					break;
				case 11:
					pBuf11 = (LPUSER_INFO_11)pBuf;
					std::cout << "\tUser account name: " << pBuf11->usri11_name << std::endl;
					std::cout << "\tComment: " << pBuf11->usri11_comment << std::endl;
					std::cout << "\tUser comment: " << pBuf11->usri11_usr_comment << std::endl;
					std::cout << "\tFull name: " << pBuf11->usri11_full_name << std::endl;
					std::cout << "\tPrivilege level: " << pBuf11->usri11_priv << std::endl;
					std::cout << "\tAuth flags (in hex): " << pBuf11->usri11_auth_flags << std::endl;
					std::cout << "\tPassword age (seconds): " << pBuf11->usri11_password_age << std::endl;
					std::cout << "\tHome directory: " << pBuf11->usri11_home_dir << std::endl;
					std::cout << "\tParameters: " << pBuf11->usri11_parms << std::endl;
					std::cout << "\tLast logon (seconds since January 1, 1970 GMT: " << pBuf11->usri11_last_logon << std::endl;
					std::cout << "\tLast logoff (seconds since January 1, 1970 GMT): " << pBuf11->usri11_last_logoff << std::endl;
					std::cout << "\tBad password count: " << pBuf11->usri11_bad_pw_count << std::endl;
					std::cout << "\tNumber of logons: " << pBuf11->usri11_num_logons << std::endl;
					std::cout << "\tLogon server: " << pBuf11->usri11_logon_server << std::endl;
					std::cout << "\tCountry code: " << pBuf11->usri11_country_code << std::endl;
					std::cout << "\tWorkstations: " << pBuf11->usri11_workstations << std::endl;
					std::cout << "\tMax storage: " << pBuf11->usri11_max_storage << std::endl;
					std::cout << "\tUnits per week: " << pBuf11->usri11_units_per_week << std::endl;
					wprintf(L"\tLogon hours:");
					std::cout << "\tLogon hours: ";
					for (j = 0; j < 21; j++)
					{
						std::cout << (BYTE)pBuf11->usri11_logon_hours[j];
					}
					std::cout << std::endl;
					std::cout << "\tCode page " << pBuf11->usri11_code_page << std::endl;
					break;
				case 20:
					pBuf20 = (LPUSER_INFO_20)pBuf;
					std::cout << "\tUser account name: " << pBuf20->usri20_name << std::endl;
					std::cout << "\tFull name: " << pBuf20->usri20_full_name << std::endl;
					std::cout << "\tComment: " << pBuf20->usri20_comment << std::endl;
					std::cout << "\tFlags (in hex): " << pBuf20->usri20_flags << std::endl;
					std::cout << "\tUser ID: " << pBuf20->usri20_user_id << std::endl;
					break;
				case 23:
					pBuf23 = (LPUSER_INFO_23)pBuf;
					std::cout << "\tUser account name: " << pBuf23->usri23_name << std::endl;
					std::cout << "\tFull name: " << pBuf23->usri23_full_name << std::endl;
					std::cout << "\tComment: " << pBuf23->usri23_comment << std::endl;
					std::cout << "\tFlags (in hex): " << pBuf23->usri23_flags << std::endl;
					if (ConvertSidToStringSid
					(pBuf23 -> usri23_user_sid, &sStringSid))
					{
						std::cout << "\tUser SID: " << sStringSid << std::endl;
						LocalFree(sStringSid);
					}
					else
					{
						std::cout << "ConvertSidToStringSid failed with error: " << GetLastError() << std::endl;
					}
					break;
				default:
					break;
				}
			}
		}
		// Otherwise, print the system error.
		//
		else
			std::cout << stderr << "NetUserGetInfo failed with error: " << nStatus << std::endl;
		//
		// Free the allocated memory.
		//
		if (pBuf != NULL)
			NetApiBufferFree(pBuf);

		switch (i)
		{
		case 0:
		case 1:
		case 10:
			i++;
			break;
		case 2:
			i = 4;
			break;
		case 4:
			i = 10;
			break;
		case 11:
			i = 20;
			break;
		case 20:
			i = 23;
			break;
		default:
			i = 24;
			break;
		}
	}
	return 1;
}