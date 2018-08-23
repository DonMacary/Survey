#pragma once
#include <windows.h>
#include <stdio.h>
#include <tchar.h>
#include <string.h>
#include <iostream>
#include <secext.h>
#include <security.h>
#include <windef.h>


void getName();
void getUserName();

void getName()
{
	TCHAR buffer[256] = TEXT("");
	DWORD dwSize = sizeof(buffer);
	GetComputerNameEx(ComputerNameDnsFullyQualified, buffer, &dwSize);

	std::cout << buffer << std::endl;
	GetComputerNameEx(ComputerNameDnsHostname, buffer, &dwSize);
	std::cout << buffer << std::endl;

	GetComputerNameEx(ComputerNameDnsDomain, buffer, &dwSize);
	std::cout << buffer << std::endl;

}

void getUserName()
{
	TCHAR buffer[256] = TEXT("");
	PULONG nSize = sizeof(buffer);
	GetUserNameEx(NameFullyQualifiedDN, buffer, nSize);

	std::cout << buffer << std::endl;
}