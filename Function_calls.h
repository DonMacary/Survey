#pragma once
#pragma comment(lib, "Secur32.lib")
#pragma comment(lib, "iphlpapi.lib")
#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "netapi32.lib")
#pragma comment(lib, "Ws2_32.lib")
#pragma comment(lib, "user32.lib")
#define SECURITY_WIN32
//#define _WIN32_WINNT 0x0500

#define WIN32_LEAN_AND_MEAN
#define MALLOC(x) HeapAlloc(GetProcessHeap(), 0, (x))
#define FREE(x) HeapFree(GetProcessHeap(), 0, (x))
#define DIV 1073741824
#define BATDIV 60



#undef _WINSOCKAPI_
#define _WINSOCKAPI_
#include <windows.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <stdio.h>
#include <tchar.h>
#include <string.h>
#include <iostream>
#include <iomanip>
#include <VersionHelpers.h>
#include <security.h>
#include <iphlpapi.h>
#include <assert.h>
#include <LM.h>
#include <sddl.h>
#include <Iprtrmib.h>
#include <psapi.h>
#include <tlhelp32.h>
#include <tchar.h>
#include <fstream>


void getSysName(std::ofstream &outputfile);
void getOSInfo(std::ofstream &outputfile);
void getArchitecture(std::ofstream &outputfile);
void getWindowsPath(std::ofstream &outputfile);
void getSystemPath(std::ofstream &outputfile);
void getTime(std::ofstream &outputfile);
void getSystemInfo(std::ofstream &outputfile);
void getNetworkInfo(std::ofstream &outputfile);
void getUserName(std::ofstream &outputfile);
void getNetstat(std::ofstream &outputfile);
void getRoutes(std::ofstream &outputfile);
void getMemoryInfo(std::ofstream &outputfile);
void getHDDInfo(std::ofstream &outputfile);
void getProcesses(std::ofstream &outputfile);
void getBIOS(std::ofstream &outputfile);



//Uses GetComputerNameEX API to gather the FQDN, Hostname and Domain Name from the system
void getSysName(std::ofstream &outputfile)
{

	TCHAR buffer[256] = TEXT(""); //Variable to store the name
	DWORD dwSize = sizeof(buffer); // buffer size

	if (!GetComputerNameEx(ComputerNameDnsFullyQualified, buffer, &dwSize)) // grabs the FQDN
	{
		std::cout << "Get FQDN failed" << std::endl;
		outputfile << "Get FQDN failed" << std::endl;
	}
	else
	{
		std::cout << "FQDN: " << buffer << std::endl;			//print it out
		outputfile << "FQDN: " << buffer << std::endl;
	}
	ZeroMemory(buffer, dwSize);				//empty the string  and the size

	if (!GetComputerNameEx(ComputerNameDnsHostname, buffer, &dwSize))		//grabs the hostname
	{
		std::cout << "Get Hostname failed" << std::endl;
		outputfile << "Get Hostname failed" << std::endl;
	}
	else
	{
		std::cout << "Hostname: " << buffer << std::endl;		//prints it out
		outputfile << "Hostname: " << buffer << std::endl;
	}

	ZeroMemory(buffer, dwSize);				 //empty the string  and the size

	if (!GetComputerNameEx(ComputerNameDnsDomain, buffer, &dwSize))		//grabs the domain name
	{
		std::cout << "Get Domain name failed" << std::endl;
		outputfile << "Get Domain name failed" << std::endl;
	}
	else
	{
		std::cout << "Domain Name: " << buffer << std::endl;	//prints it out
		outputfile << "Domain Name: " << buffer << std::endl;
	}

	ZeroMemory(buffer, dwSize);				 //empty the string  and the size

};

//This function uses the Version Helpers API to check the Operating system version. See README for details on why this method was used vs others.
void getOSInfo(std::ofstream &outputfile)
{
	//Since the helper functions only report if the system is that version or greater, An iterator is needed to keep track of all the tests the system has returned true for.
	//The versions are checked in ascending order to make this possible. 
	int i = 0;			//iterator to count which version of windows
	bool server = false;
	std::cout << "OS Name: ";
	outputfile << "OS Name: ";
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
		outputfile << "PreWindows XP" << std::endl;
		break;
	case 1:
		//It is difficult to differentiate all the server versions, therefor I just report the generation of server (and not R2 etc...)
		if (server == true)
		{
			std::cout << "Windows Server 2000" << std::endl;
			outputfile << "Windows Server 2000" << std::endl;
		}
		else
		{
			std::cout << "Windows XP" << std::endl;
			outputfile << "Windows XP" << std::endl;
		}

		break;
	case 2:
		if (server == true)
		{
			std::cout << "Windows Server 2000" << std::endl;
			outputfile << "Windows Server 2000" << std::endl;
		}
		else
		{
			std::cout << "Windows XP Service Pack 1" << std::endl;
			outputfile << "Windows XP Service Pack 1" << std::endl;
		}
		break;
	case 3:
		if (server == true)
		{
			std::cout << "Windows Server 2000" << std::endl;
			outputfile << "Windows Server 2000" << std::endl;
		}
		else
		{
			std::cout << "Windows XP Service Pack 2" << std::endl;
			outputfile << "Windows XP Service Pack 2" << std::endl;
		}
		break;
	case 4:
		if (server == true)
		{
			std::cout << "Windows Server 2000" << std::endl;
			outputfile << "Windows Server 2000" << std::endl;
		}
		else
		{
			std::cout << "Windows XP Service Pack 3" << std::endl;
			outputfile << "Windows XP Service Pack 3" << std::endl;
		}
		break;
	case 5:
		if (server == true)
		{
			std::cout << "Windows Server 2003" << std::endl;
			outputfile << "Windows Server 2003" << std::endl;
		}
		else
		{
			std::cout << "Windows Vista" << std::endl;
			outputfile << "Windows Vista" << std::endl;
		}
		break;
	case 6:
		if (server == true)
		{
			std::cout << "Windows Server 2003" << std::endl;
			outputfile << "Windows Server 2003" << std::endl;
		}
		else
		{
			std::cout << "Windows Vista Service Pack 1" << std::endl;
			outputfile << "Windows Vista Service Pack 1" << std::endl;
		}
		break;
	case 7:
		if (server == true)
		{
			std::cout << "Windows Server 2003" << std::endl;
			outputfile << "Windows Server 2003" << std::endl;
		}
		else
		{
			std::cout << "Windows Vista Service Pack 2" << std::endl;
			outputfile << "Windows Vista Service Pack 2" << std::endl;
		}
		break;
	case 8:
		if (server == true)
		{
			std::cout << "Windows Server 2008" << std::endl;
			outputfile << "Windows Server 2008" << std::endl;
		}
		else
		{
			std::cout << "Windows 7" << std::endl;
			outputfile << "Windows 7" << std::endl;
		}
		break;
	case 9:
		if (server == true)
		{
			std::cout << "Windows Server 2008" << std::endl;
			outputfile << "Windows Server 2008" << std::endl;
		}
		else
		{
			std::cout << "Windows 7 Service Pack 1" << std::endl;
			outputfile << "Windows 7 Service Pack 1" << std::endl;
		}
		break;
	case 10:
		if (server == true)
		{
			std::cout << "Windows Server 2012" << std::endl;
			outputfile << "Windows Server 2012" << std::endl;
		}
		else
		{
			std::cout << "Windows 8" << std::endl;
			outputfile << "Windows 8" << std::endl;
		}
		break;
	case 11:
		if (server == true)
		{
			std::cout << "Windows Server 2012" << std::endl;
			outputfile << "Windows Server 2012" << std::endl;
		}
		else
		{
			std::cout << "Windows 8.1" << std::endl;
			outputfile << "Windows 8.1" << std::endl;
		}

		break;
	case 12:
		if (server == true)
		{
			std::cout << "Windows Server 2016" << std::endl;
			outputfile << "Windows Server 2016" << std::endl;
		}
		else
		{
			std::cout << "Windows 10" << std::endl;
			outputfile << "Windows 10" << std::endl;
		}

		break;
	default:
		std::cout << "Unknown Version" << std::endl;
		outputfile << "Unknown Version" << std::endl;
		break;
	}

};

//gathers natvie system information and then checks the processor architecture and reports it. Uses the GetNativeSystemInfo API. 
void getArchitecture(std::ofstream &outputfile)
{
	std::cout << "Architecture: ";
	outputfile << "Architecture: ";
	SYSTEM_INFO sys;
	GetNativeSystemInfo(&sys);
	//checks the SYSTEM_INFO object processor architecture parameter against a list of known values. These values were found on Microsofts Webstie:
	//https://msdn.microsoft.com/en-us/library/windows/desktop/ms724958(v=vs.85).aspx 
	switch (sys.wProcessorArchitecture)
	{
	case 0:
		std::cout << "x86" << std::endl;
		outputfile << "x86" << std::endl;
		break;
	case 5:
		std::cout << "ARM" << std::endl;
		outputfile << "ARM" << std::endl;
		break;
	case 6:
		std::cout << "Intel Itanium-based" << std::endl;
		outputfile << "Intel Itanium-based" << std::endl;
		break;
	case 9:
		std::cout << "x64" << std::endl;
		outputfile << "x64" << std::endl;
		break;
	case 12:
		std::cout << "ARM64" << std::endl;
		outputfile << "ARM64" << std::endl;
		break;
	default:
		std::cout << "Unknown" << std::endl;
		outputfile << "Unknown" << std::endl;
		break;
	}

};


//prints the path to the windows directory (most of the time this will be C:\Windows...) This uses the GetWindowsDirectory API. 
void getWindowsPath(std::ofstream &outputfile)
{
	TCHAR PATH[256] = TEXT("");		//variable to store the path
	DWORD size = sizeof(PATH);		//size of the path variable 
	UINT results = GetWindowsDirectory(PATH, size);		//stores the path in the variable and the sresult of the function is an int which means various things

														//if the result int is = 0 then the GetWindowsDirectory API failed
	if (results == 0)
	{
		std::cout << "Windows Directory Path: Failed to find" << std::endl;
		outputfile << "Windows Directory Path: Failed to find" << std::endl;
	}
	//if the result is = the size of the path variable then it means that the path is too long to print (we would need to increase the path buffer)
	else if (results == size)
	{
		std::cout << "Windows Directory Path: Path is too large to print" << std::endl;
		outputfile << "Windows Directory Path: Path is too large to print" << std::endl;
	}
	//otherwise were successful so print the path!
	else
	{
		std::cout << "Windows Directory Path: " << PATH << std::endl;
		outputfile << "Windows Directory Path: " << PATH << std::endl;
	}
};

//prints the path to the system directory (C:\Windows\System32 usually..) Uses the GetSystemDirectory API
void getSystemPath(std::ofstream &outputfile)
{
	TCHAR PATH[256] = TEXT("");		//variable to store the path
	DWORD size = sizeof(PATH);		//size of the path variable 
	UINT results = GetSystemDirectory(PATH, size);		//stores the path in the variable and the sresult of the function is an int which means various things
														//if the result int is = 0 then the GetWindowsDirectory API failed
	if (results == 0)
	{
		std::cout << "Windows System Path: Failed to find" << std::endl;
		outputfile << "Windows System Path: Failed to find" << std::endl;
	}
	//if the result is = the size of the path variable then it means that the path is too long to print (we would need to increase the path buffer)
	else if (results == size)
	{
		std::cout << "Windows System Path: Path is too large to print" << std::endl;
		outputfile << "Windows System Path: Path is too large to print" << std::endl;
	}
	//otherwise were successful so print the path!
	else
	{
		std::cout << "Windows System Path: " << PATH << std::endl;
		outputfile << "Windows System Path: " << PATH << std::endl;
	}

};

//utilizes the GetLocalTime and GetSystemTime APIs to report the local and system time of the host. 
void getTime(std::ofstream &outputfile)
{
	SYSTEMTIME localtime;			//local time variable
	SYSTEMTIME systime;				//system time (UTC) variable
	GetLocalTime(&localtime);		//API to get the local time
	GetSystemTime(&systime);		//API to get the system time
	std::cout << "Local Time: " << localtime.wMonth << "/" << localtime.wDay << "/" << localtime.wYear << " " << localtime.wHour << ":" << localtime.wMinute
		<< ":" << localtime.wSecond << std::endl;
	outputfile << "Local Time: " << localtime.wMonth << "/" << localtime.wDay << "/" << localtime.wYear << " " << localtime.wHour << ":" << localtime.wMinute
		<< ":" << localtime.wSecond << std::endl;
	std::cout << "System Time: " << systime.wMonth << "/" << systime.wDay << "/" << systime.wYear << " " << systime.wHour << ":" << systime.wMinute
		<< ":" << systime.wSecond << std::endl;
	outputfile << "System Time: " << systime.wMonth << "/" << systime.wDay << "/" << systime.wYear << " " << systime.wHour << ":" << systime.wMinute
		<< ":" << systime.wSecond << std::endl;

};

//main function to report Target's system information. This is called in main. 
void getSystemInfo(std::ofstream &outputfile)
{
	std::cout << "[+] System Information" << std::endl << std::endl;
	outputfile << "[+] System Information" << std::endl << std::endl;

	getOSInfo(outputfile);			//reports the operating system name
	getArchitecture(outputfile);		//reports the system architecture type 
	getSysName(outputfile);			//reports the System hostname, FQDN and Domain Name
	getWindowsPath(outputfile);		//reports the Windows directory path
	getSystemPath(outputfile);		//reports the System directory path
	getTime(outputfile);				//reports thte Local and System time

};

//gets the username of the currently logged in user using the GetUserNameEx API
void getUserName(std::ofstream &outputfile)
{
	std::cout << std::endl << "[+] User Name" << std::endl << std::endl;
	outputfile << std::endl << "[+] User Name" << std::endl << std::endl;
	TCHAR buffer[256] = TEXT("");
	DWORD buffer_size = sizeof(buffer);
	LPDWORD nSize = &buffer_size;
	GetUserNameEx(NameSamCompatible, buffer, nSize);
	std::string user = buffer;

	std::cout << "NameSamCompatible: " << buffer << std::endl;
	outputfile << "NameSamCompatible: " << buffer << std::endl;
	//the below portion goes with getAccountInfo. Since that is currently on hold, the following code has been commented out.
	/*LPWSTR userName = {0};
	MultiByteToWideChar(CP_ACP, MB_PRECOMPOSED, buffer, -1, userName, 256);
	getAccountInfo(userName);*/
};

//reports information about the network adapters on the host machine using the GetAdaptersInfo API. 
void getNetworkInfo(std::ofstream &outputfile)
{
	std::cout << std::endl << "[+] Network Adapters" << std::endl << std::endl;
	outputfile << std::endl << "[+] Network Adapters" << std::endl << std::endl;

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
		outputfile << "GetAdaptersInfo call failed with " << dwRetVal << std::endl;
	}

	//store the adapter information in a PIP_ADAPTER_INFO object, this is essentially an array that stores all the adapters. We will iterate through this array and 
	//print each adpaters information
	PIP_ADAPTER_INFO pAdapter = pAdapterInfo;
	while (pAdapter) {
		std::cout << "Adapter Name: " << pAdapter->Description << std::endl;			//displays thhe network adapter name
		outputfile << "Adapter Name: " << pAdapter->Description << std::endl;
		std::cout << "\tIP Address: " << pAdapter->IpAddressList.IpAddress.String << std::endl;		//displays the ip address
		outputfile << "\tIP Address: " << pAdapter->IpAddressList.IpAddress.String << std::endl;
		std::cout << "\tIP Mask: " << pAdapter->IpAddressList.IpMask.String << std::endl;			//displays the subnet mask
		outputfile << "\tIP Mask: " << pAdapter->IpAddressList.IpMask.String << std::endl;
		std::cout << "\tGateway: " << pAdapter->GatewayList.IpAddress.String << std::endl;			//displays the gateway
		outputfile << "\tGateway: " << pAdapter->GatewayList.IpAddress.String << std::endl;
		//checks if dhcp is enabled, if so state so and if it can find the dhcp server address, report it.
		if (pAdapter->DhcpEnabled)
		{
			std::cout << "\tDHCP Enabled: Yes" << std::endl;
			outputfile << "\tDHCP Enabled: Yes" << std::endl;
			std::cout << "\t\tDHCP Server: \t" << pAdapter->DhcpServer.IpAddress.String << std::endl;
			outputfile << "\t\tDHCP Server: \t" << pAdapter->DhcpServer.IpAddress.String << std::endl;
		}
		else
		{
			std::cout << "\tDHCP Enabled: No" << std::endl;
			outputfile << "\tDHCP Enabled: No" << std::endl;
		}
		pAdapter = pAdapter->Next;	//move to the next adapter in the array
	}

	//free the object when done
	if (pAdapterInfo)
		free(pAdapterInfo);


}

//displays the netstat information for the host using the GetExtendedTCPTable API. This function gets the 
void getNetstat(std::ofstream &outputfile)
{
	std::cout << std::internal;
	outputfile << std::internal;
	std::cout << std::endl << "[+] Active Connections" << std::endl << std::endl;
	outputfile << std::endl << "[+] Active Connections" << std::endl << std::endl;
	std::cout << std::setw(10) << "  Proto" << std::setw(25) << "Local Address" << std::setw(35) << "Foreign Address" << std::setw(15) << "State" << std::setw(20) << "PID" << std::endl;
	outputfile << std::setw(10) << "  Proto" << std::setw(25) << "Local Address" << std::setw(35) << "Foreign Address" << std::setw(15) << "State" << std::setw(20) << "PID" << std::endl;
	PMIB_TCPTABLE_OWNER_PID pTCPtable;			//a pointer to the table that holds all of the network connections
	PMIB_TCPROW_OWNER_PID pTCProw;				//a pointer to a specific row in the table
	DWORD size = 0;									//the size of the table (number of entries)
	DWORD dwResult = 0;							//holds error code results



	pTCPtable = (MIB_TCPTABLE_OWNER_PID *)malloc(sizeof(MIB_TCPTABLE_OWNER_PID));		//allocating memory for the table pointer
	pTCProw = (MIB_TCPROW_OWNER_PID *)malloc(sizeof(MIB_TCPTABLE_OWNER_PID));			//allocating memory for the row pointer
	size = sizeof(MIB_TCPROW_OWNER_PID);												//setting the initial size - this will be modified on the first function call

	if (pTCPtable == NULL)
	{
		std::cout << "Error allocating memory" << std::endl;
		outputfile << "Error allocating memory" << std::endl;
		return;
	}

	//much like the network adapter function we will need to call the API twice - once to get the actual size of the table (since all we can do right now is guess) and then the second
	//time to actually get the table filled out. 
	if (GetExtendedTcpTable(pTCPtable, &size, TRUE, AF_INET, TCP_TABLE_OWNER_PID_ALL, 0) == ERROR_INSUFFICIENT_BUFFER)
	{
		free(pTCPtable);				//free the memory for the table 
		pTCPtable = (MIB_TCPTABLE_OWNER_PID *)malloc(size);				//reallocate the memory for the table to the correct size
		if (pTCPtable == NULL)				//make sure the memory was allocated properly
		{
			std::cout << "Error allocating memory" << std::endl;
			outputfile << "Error allocating memory" << std::endl;
			return;
		}
	}
	dwResult = GetExtendedTcpTable(pTCPtable, &size, TRUE, AF_INET, TCP_TABLE_OWNER_PID_ALL, 0);			//second call to the API and store the results ina  variable for error checking
	if (dwResult != NO_ERROR)		//if there was an error then return and dont go any further!!
	{
		std::cout << "There was an error getting the Extended TCP Table" << std::endl;
		outputfile << "There was an error getting the Extended TCP Table" << std::endl;
		return;
	}

	//loop through all the rows in the table, on each row output the data NOTE - THIS WILL NEED TO BE CLEANED UP TO BETTER OUTPUT THE DATA (it looks weird right now)
	for (DWORD dwCounter = 0; dwCounter < pTCPtable->dwNumEntries; dwCounter++)
	{
		pTCProw = &pTCPtable->table[dwCounter];			//sets the tcprow to the current row

		char localAddrStr[INET_ADDRSTRLEN];				//a string to store the local address
		char remoteAddrStr[INET_ADDRSTRLEN];			//a string to store the remote address

		InetNtop(AF_INET, &pTCProw->dwLocalAddr, (PSTR)localAddrStr, sizeof(localAddrStr));				//this function converts the binary remote address to a string so it is human readable
		InetNtop(AF_INET, &pTCProw->dwRemoteAddr, (PSTR)remoteAddrStr, sizeof(remoteAddrStr));


		std::cout << std::setw(10) << "  TCP";				//print TCP
		outputfile << std::setw(10) << "  TCP";
		std::cout << std::setw(25) << localAddrStr << ":" << ntohs((u_short)pTCProw->dwLocalPort);			//the last function in this converts the port to human readable format (from binary value)
		outputfile << std::setw(25) << localAddrStr << ":" << ntohs((u_short)pTCProw->dwLocalPort);
		std::cout << std::setw(25) << remoteAddrStr << ":" << ntohs((u_short)pTCProw->dwRemotePort);
		outputfile << std::setw(25) << remoteAddrStr << ":" << ntohs((u_short)pTCProw->dwRemotePort);

		//checks all the different possible states and prints the wording for that state
		switch (pTCProw->dwState) {
		case MIB_TCP_STATE_CLOSED:
			std::cout << std::setw(20) << "CLOSED\t";
			outputfile << std::setw(20) << "CLOSED\t";
			break;
		case MIB_TCP_STATE_LISTEN:
			std::cout << std::setw(20) << "LISTEN\t";
			outputfile << std::setw(20) << "LISTEN\t";
			break;
		case MIB_TCP_STATE_SYN_SENT:
			std::cout << std::setw(20) << "SYN-SENT\t";
			outputfile << std::setw(20) << "SYN-SENT\t";
			break;
		case MIB_TCP_STATE_SYN_RCVD:
			std::cout << std::setw(20) << "SYN-RECEIVED\t";
			outputfile << std::setw(20) << "SYN-RECEIVED\t";
			break;
		case MIB_TCP_STATE_ESTAB:
			std::cout << std::setw(20) << "ESTABLISHED\t";
			outputfile << std::setw(20) << "ESTABLISHED\t";
			break;
		case MIB_TCP_STATE_FIN_WAIT1:
			std::cout << std::setw(20) << "FIN-WAIT-1\t";
			outputfile << std::setw(20) << "FIN-WAIT-1\t";
			break;
		case MIB_TCP_STATE_FIN_WAIT2:
			std::cout << std::setw(20) << "FIN-WAIT-2 \t";
			outputfile << std::setw(20) << "FIN-WAIT-2 \t";
			break;
		case MIB_TCP_STATE_CLOSE_WAIT:
			std::cout << std::setw(20) << "CLOSE-WAIT\t";
			outputfile << std::setw(20) << "CLOSE-WAIT\t";
			break;
		case MIB_TCP_STATE_CLOSING:
			std::cout << std::setw(20) << "CLOSING\t";
			outputfile << std::setw(20) << "CLOSING\t";
			break;
		case MIB_TCP_STATE_LAST_ACK:
			std::cout << std::setw(20) << "LAST-ACK\t";
			outputfile << std::setw(20) << "LAST-ACK\t";
			break;
		case MIB_TCP_STATE_TIME_WAIT:
			std::cout << std::setw(20) << "TIME-WAIT\t";
			outputfile << std::setw(20) << "TIME-WAIT\t";
			break;
		case MIB_TCP_STATE_DELETE_TCB:
			std::cout << std::setw(20) << "DELETE-TCB\t";
			outputfile << std::setw(20) << "DELETE-TCB\t";
			break;
		default:
			std::cout << std::setw(20) << "UNKNOWN dwState value\t";
			outputfile << std::setw(20) << "UNKNOWN dwState value\t";
			break;
		}
		//print the PID
		std::cout << std::setw(10) << pTCProw->dwOwningPid << std::endl;
		outputfile << std::setw(10) << pTCProw->dwOwningPid << std::endl;
	}
	//free the memory for the pointers and ge on your way!!!
	pTCProw = NULL;
	free(pTCProw);
	free(pTCPtable);

};

//Uses the GetIpForwardTable API to get information about the hosts routes
void getRoutes(std::ofstream &outputfile)
{

	//print the header
	std::cout << std::endl << "[+] Routes" << std::endl << std::endl;
	std::cout << std::left;
	std::cout << std::setw(25) << "Network Destination" << std::setw(25) << "Netmask" << std::setw(25) << "Gateway" << std::setw(25) << "Interface" << std::setw(25) << "Metric" << std::endl;
	outputfile << std::endl << "[+] Routes" << std::endl << std::endl;
	outputfile << std::left;
	outputfile << std::setw(25) << "Network Destination" << std::setw(25) << "Netmask" << std::setw(25) << "Gateway" << std::setw(25) << "Interface" << std::setw(25) << "Metric" << std::endl;
	// Declare and initialize variables.

	/* variables used for GetIfForwardTable */
	PMIB_IPFORWARDTABLE pIpForwardTable;			//pointer to the table which holds to routes
	PMIB_IPFORWARDROW pIpForwardRow;				//pointer to a specific row in the table 
	DWORD dwSize = 0;								//size of the table
	DWORD dwRetVal = 0;								//variable to hold the results for error checking

	pIpForwardTable = (MIB_IPFORWARDTABLE *)malloc(sizeof(MIB_IPFORWARDTABLE));		//allocate memory for the table - this will need to be done again after we know the correct size
	pIpForwardRow = (MIB_IPFORWARDROW *)malloc(sizeof(MIB_IPFORWARDROW));			//allocate memory for the row

																					//ensure memory was allocated correctly
	if (pIpForwardTable == NULL)
	{
		std::cout << "Error allocating memory" << std::endl;
		outputfile << "Error allocating memory" << std::endl;
		return;
	}

	//calls the API but we expect that it will fail since our size isnt big enough - this will put the correct size into the dwSize variable
	if (GetIpForwardTable(pIpForwardTable, &dwSize, 0) == ERROR_INSUFFICIENT_BUFFER)
	{
		free(pIpForwardTable);			//free the memory in the table so we can reallocate
		pIpForwardTable = (MIB_IPFORWARDTABLE *)malloc(dwSize);			//reallocate memory with the correct size
																		//ensure memory was correctly allocated
		if (pIpForwardTable == NULL)
		{
			std::cout << "Error allocating memory" << std::endl;
			outputfile << "Error allocating memory" << std::endl;
			return;
		}
	}

	/* Note that the IPv4 addresses returned in
	* GetIpForwardTable entries are in network byte order
	*/
	//as long as there is no errors loop through each row in the table
	if ((dwRetVal = GetIpForwardTable(pIpForwardTable, &dwSize, 0)) == NO_ERROR)
	{
		for (int i = 0; i < (int)pIpForwardTable->dwNumEntries; i++) {

			pIpForwardRow = &pIpForwardTable->table[i];				//sets the row to the iteration

			char destIP[INET_ADDRSTRLEN];				//a string to store the destination address
			char maskIP[INET_ADDRSTRLEN];			//a string to store the mask IP
			char gatewayIP[INET_ADDRSTRLEN];			//a string to store the gateway/interfaceIP

														//these functions convert the numeric byte entries for the IPs into strings
			InetNtop(AF_INET, &pIpForwardRow->dwForwardDest, (PSTR)destIP, sizeof(destIP));
			InetNtop(AF_INET, &pIpForwardRow->dwForwardMask, (PSTR)maskIP, sizeof(maskIP));
			InetNtop(AF_INET, &pIpForwardRow->dwForwardNextHop, (PSTR)gatewayIP, sizeof(gatewayIP));

			//print the destIP and Mask
			std::cout << std::setw(25) << destIP;
			outputfile << std::setw(25) << destIP;
			std::cout << std::setw(25) << maskIP;
			outputfile << std::setw(25) << maskIP;
			//on the first entry we know that it is the default gateway so were just gonna print it how it is (this is hacky I know)
			if (i == 0)
			{
				std::cout << std::setw(25) << gatewayIP;
				outputfile << std::setw(25) << gatewayIP;
				std::cout << std::setw(25) << pIpForwardRow->dwForwardIfIndex;
				outputfile << std::setw(25) << pIpForwardRow->dwForwardIfIndex;
			}
			//for the rest of the entries were going to print the gateway as On-Link (this will need to be changed as we have multiple interfaces but for now it works)
			//in the future i will need to compare the interface index to one gathered from the network adapter and then print the IP from that...
			else
			{
				std::cout << std::setw(25) << "On-link" << std::setw(25) << gatewayIP;
				outputfile << std::setw(25) << "On-link" << std::setw(25) << gatewayIP;
			}
			std::cout << std::setw(25) << pIpForwardRow->dwForwardMetric1 << std::endl;
			outputfile << std::setw(25) << pIpForwardRow->dwForwardMetric1 << std::endl;
		}
		pIpForwardRow = NULL;			//NULL out the row so we can free
		free(pIpForwardTable);			//free the table
		free(pIpForwardRow);			//free the row
		return;
	}
	else {
		std::cout << "\tGetIpForwardTable failed." << std::endl;
		outputfile << "\tGetIpForwardTable failed." << std::endl;
		pIpForwardRow = NULL;
		free(pIpForwardTable);
		free(pIpForwardRow);
		return;
	}
};


//gets info on the computer's memory.
void getMemoryInfo(std::ofstream &outputfile)
{
	MEMORYSTATUSEX memStat;

	memStat.dwLength = sizeof(memStat);

	GlobalMemoryStatusEx(&memStat);
	std::cout << std::endl << "[+] Memory" << std::endl << std::endl;
	std::cout << "Memory in use: " << memStat.dwMemoryLoad << "%" << std::endl;
	std::cout << "Total physical memory: " << memStat.ullTotalPhys / DIV << "GB" << std::endl;
	std::cout << "Available physical memory: " << memStat.ullAvailPhys / DIV << "GB" << std::endl;
	std::cout << "Total virtual memory: " << memStat.ullTotalVirtual / DIV << "GB" << std::endl;
	std::cout << "Available virtual memeory: " << memStat.ullAvailVirtual / DIV << "GB" << std::endl;

	outputfile << std::endl << "[+] Memory" << std::endl << std::endl;
	outputfile << "Memory in use: " << memStat.dwMemoryLoad << "%" << std::endl;
	outputfile << "Total physical memory: " << memStat.ullTotalPhys / DIV << "GB" << std::endl;
	outputfile << "Available physical memory: " << memStat.ullAvailPhys / DIV << "GB" << std::endl;
	outputfile << "Total virtual memory: " << memStat.ullTotalVirtual / DIV << "GB" << std::endl;
	outputfile << "Available virtual memeory: " << memStat.ullAvailVirtual / DIV << "GB" << std::endl;
};

void getHDDInfo(std::ofstream &outputfile)
{
	std::cout << std::endl << "[+] Hard Drive Space" << std::endl << std::endl;
	outputfile << std::endl << "[+] Hard Drive Space" << std::endl << std::endl;
	ULARGE_INTEGER p1, p2, p3;
	GetDiskFreeSpaceEx(".", &p1, &p2, &p3);
	std::cout << "Total Space: " << p2.QuadPart / DIV << "GB" << std::endl;
	outputfile << "Total Space: " << p2.QuadPart / DIV << "GB" << std::endl;
	std::cout << "Free Space: " << p3.QuadPart / DIV << "GB" << std::endl;
	outputfile << "Free Space: " << p3.QuadPart / DIV << "GB" << std::endl;
}
//Creates a snapshot of the processes running on the host and then prints each one out one by one. Uses the CreateToolhelp32Snapshot function and the OpenProcess API
void getProcesses(std::ofstream &outputfile)
{
	HANDLE hProcessSnap;				//Handle on the process snapshot
	HANDLE hProcess;					//handle on the current process being printed
	PROCESSENTRY32 pe32;				//variable which stores the current process information
	DWORD dwPriorityClass;				//priority class variable

	std::cout << std::endl << "[+] Processes" << std::endl;
	outputfile << std::endl << "[+] Processes" << std::endl;

	// Take a snapshot of all processes in the system.
	hProcessSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if (hProcessSnap == INVALID_HANDLE_VALUE)				//handles if the snapshot did not work
	{
		std::cout << "Failure to snapshot processes" << std::endl;
		outputfile << "Failure to snapshot processes" << std::endl;
		return;
	}

	// Set the size of the structure before using it.
	pe32.dwSize = sizeof(PROCESSENTRY32);

	// Retrieve information about the first process,
	// and exit if unsuccessful
	if (!Process32First(hProcessSnap, &pe32))
	{
		CloseHandle(hProcessSnap);          // clean the snapshot object
		return;
	}

	// Now walk the snapshot of processes, and
	// display information about each process in turn
	do
	{
		std::cout << std::endl << std::endl << "=====================================================" << std::endl;
		outputfile << std::endl << std::endl << "=====================================================" << std::endl;
		std::cout << std::endl << "PROCESS NAME: " << pe32.szExeFile << std::endl;
		outputfile << std::endl << "PROCESS NAME: " << pe32.szExeFile << std::endl;
		std::cout << std::endl << "------------------------------------------------------" << std::endl;
		outputfile << std::endl << "------------------------------------------------------" << std::endl;
		std::cout << std::endl << "  Process ID: " << pe32.th32ProcessID << std::endl;
		outputfile << std::endl << "  Process ID: " << pe32.th32ProcessID << std::endl;
		std::cout << std::endl << "  Parent process ID: " << pe32.th32ParentProcessID << std::endl;
		outputfile << std::endl << "  Parent process ID: " << pe32.th32ParentProcessID << std::endl;

	} while (Process32Next(hProcessSnap, &pe32));

	CloseHandle(hProcessSnap);
	return;
};
void getBIOS(std::ofstream &outputfile)
{
	typedef struct RAW_SMBIOS_DATA
	{
		BYTE    Used20CallingMethod;
		BYTE    MajorVersion;
		BYTE    MinorVersion;
		BYTE    Revision;
		DWORD   Length;
		BYTE    SMBIOSTableData[];
	} RawSmbiosData;

	BYTE buffer[0x4000];
	RawSmbiosData *pData = (RawSmbiosData *)buffer;

	if (sizeof(buffer) > GetSystemFirmwareTable('RSMB', 0, buffer, sizeof(buffer))) {
		int major = pData->MajorVersion;
		int minor = pData->MinorVersion;
		std::cout << "SMBios Version: " << major << "." << minor << std::endl;
		std::cout << "SMBios Table Length: " << pData->Length << " bytes" << std::endl;
	}
}

