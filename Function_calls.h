#pragma once
#include <windows.h>
#include <stdio.h>
#include <tchar.h>
#include <string.h>
#include <iostream>

void getUserName();
typedef enum EXTENDED_NAME_FORMAT {
	NameUnknown,
	NameFullyQualifiedDN,
	NameSamCompatible,
	NameDisplay,
	NameUniqueId,
	NameCanonical,
	NameUserPrincipal,
	NameCanonicalEx,
	NameServicePrincipal,
	NameDnsDomain,
	NameGivenName,
	NameSurname
}  *PEXTENDED_NAME_FORMAT;

BOOLEAN SEC_ENTRY getUserName(
	EXTENDED_NAME_FORMAT NameFullyQualifiedDN,
	LPSTR                lpNameBuffer,
	PULONG               nSize
);