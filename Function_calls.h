#pragma once
#include <windows.h>
#include <stdio.h>
#include <tchar.h>
#include <string.h>
#include <iostream>


void getSysName()
{
	TCHAR buffer[256] = TEXT("");
	DWORD dwSize = sizeof(buffer);

	GetComputerNameEx(ComputerNameDnsFullyQualified, buffer, &dwSize);
	std::cout << "FQDN: " << buffer << std::endl;

	GetComputerNameEx(ComputerNameDnsHostname, buffer, &dwSize);
	std::cout << "Hostname: " << buffer << std::endl;

	GetComputerNameEx(ComputerNameDnsDomain, buffer, &dwSize);
	std::cout << "Domain Name: " << buffer << std::endl;

};