#include <string>

namespace process
{

static void dump(HANDLE primaryToken)
{
	PTOKEN_PRIVILEGES pTokenBuf = NULL;
	DWORD dwTokenBufSize;

	if (((GetTokenInformation(primaryToken, TokenPrivileges, NULL, 0, &dwTokenBufSize) == 0) && (GetLastError() != ERROR_INSUFFICIENT_BUFFER))
		|| ((pTokenBuf = (PTOKEN_PRIVILEGES)malloc(dwTokenBufSize)) == NULL)
		|| (GetTokenInformation(primaryToken, TokenPrivileges, pTokenBuf, dwTokenBufSize, &dwTokenBufSize) == 0))
	{
		DWORD lLastError = GetLastError();
		char lErrorText[512];

		printf("Failed to retrieve TokenPrivileges information: error %lu (%s)", lLastError, lErrorText);
	}
	else
	{
		char privname[256];
		DWORD privnameSize, i;

		printf("Effective privileges (#%lu) of token:\n", pTokenBuf->PrivilegeCount);

		/* print effective user rights */
		for (i = 0; i < pTokenBuf->PrivilegeCount; i++)
		{
			privnameSize = sizeof(privname);
			if (LookupPrivilegeNameA(NULL, &(pTokenBuf->Privileges[i].Luid), privname, &privnameSize) != 0)
			{
				DWORD attr = pTokenBuf->Privileges[i].Attributes;
				char buf[200];
				char* pBuf = buf;
				int nBytes;

				if (attr == 0)
				{
					nBytes = snprintf(pBuf, sizeof(buf) - (pBuf - buf), "Disabled ");
					if (nBytes > 0) pBuf += nBytes;
				}
				else
				{
					if (attr & SE_PRIVILEGE_ENABLED)
					{
						nBytes = snprintf(pBuf, sizeof(buf) - (pBuf - buf), "Enabled ");
						if (nBytes > 0) pBuf += nBytes;
					}
					if (attr & SE_PRIVILEGE_ENABLED_BY_DEFAULT)
					{
						nBytes = snprintf(pBuf, sizeof(buf) - (pBuf - buf), "EnabledByDefault ");
						if (nBytes > 0) pBuf += nBytes;
					}
					if (attr & SE_PRIVILEGE_REMOVED)
					{
						nBytes = snprintf(pBuf, sizeof(buf) - (pBuf - buf), "Removed ");
						if (nBytes > 0) pBuf += nBytes;
					}
					if (attr & SE_PRIVILEGE_USED_FOR_ACCESS)
					{
						nBytes = snprintf(pBuf, sizeof(buf) - (pBuf - buf), "UsedForAccess ");
						if (nBytes > 0) pBuf += nBytes;
					}
				}

				printf("   %03d: %-35s %0x (%s)\n", i, privname, pTokenBuf->Privileges[i].Attributes, buf);
			}
		}
	}

	if (pTokenBuf != NULL)
	{
		free(pTokenBuf);
	}
}

BOOL SetPrivilege(HANDLE hToken, const char* aPrivilege, BOOL bEnablePrivilege, char* errorBuf, size_t errorBufSize)
{
	LUID luid = { 0 };
	BOOL bRet = LookupPrivilegeValue(NULL, aPrivilege, &luid);
	if (!bRet && errorBuf != NULL && errorBufSize != 0)
	{
		char lErrorText[512];
		DWORD lLastError = GetLastError();
	}

	if (bRet)
	{
		TOKEN_PRIVILEGES tp = { 0 };

		tp.PrivilegeCount = 1;
		tp.Privileges[0].Luid = luid;
		tp.Privileges[0].Attributes = bEnablePrivilege ? SE_PRIVILEGE_ENABLED : 0;

		// Enable the privilege or disable the privilege.
		if (AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(tp), 0, 0))
		{
			DWORD lLastError = GetLastError();
			if (lLastError == ERROR_SUCCESS)
			{
				// success
				bRet = TRUE;
			}
			else if (lLastError == ERROR_NOT_ALL_ASSIGNED)
			{
				if (errorBuf != NULL && errorBufSize != 0)
				{
					snprintf(
						errorBuf, errorBufSize, "AdjustTokenPrivileges: the token does not have the specified privilege %s, so it cannot be %s", aPrivilege,
						bEnablePrivilege ? "enabled" : "disabled");
				}
			}
			else
			{
				// according MSDN, this code should not be hit
				if (errorBuf != NULL && errorBufSize != 0)
				{
					snprintf(errorBuf, errorBufSize, "AdjustTokenPrivileges failed with unexpected error %lu", lLastError);
				}
			}
		}
		else if (errorBuf != NULL && errorBufSize != 0)
		{
			char lErrorText[512];
			DWORD lLastError = GetLastError();
			snprintf(errorBuf, errorBufSize, "AdjustTokenPrivileges failed with error %lu (%s)", lLastError, lErrorText);
		}
	}

	return bRet;
}


void spawn_as_user(const std::string& command)
{
	STARTUPINFO start_info = { 0 };
	PROCESS_INFORMATION piProcInfo = { 0 };
	HANDLE userToken = nullptr;
	HANDLE primaryToken = nullptr;
	TOKEN_TYPE lTokenType;
	DWORD lReturnLength = 0;

	char* pEnvironment = nullptr;
	char* pWorkdir = nullptr;

	HANDLE hProcessToken;
	OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES, &hProcessToken);
	char lErrorText[1024];

	
	if (!SetPrivilege(hProcessToken, SE_TCB_NAME, TRUE, lErrorText, sizeof(lErrorText)))
	{
		printf("SetPrivilege(SE_TCB_NAME) failed. The error is: %s", lErrorText);
	}
	/* Need SE_DEBUG_NAME privilege to be able to succeed OpenProcess() for processes in different terminal
	   server session. The OpenProcess() function is used in HAL_process_exists().
	*/
	if (!SetPrivilege(hProcessToken, SE_DEBUG_NAME, TRUE, lErrorText, sizeof(lErrorText)))
	{
		printf("SetPrivilege(SE_DEBUG_NAME) failed. The error is: %s", lErrorText);
	}

	CloseHandle(hProcessToken);

	auto LogonOK = LogonUser("ndjonge", "infor", "Anne&Lena1234!", LOGON32_LOGON_NETWORK_CLEARTEXT, LOGON32_PROVIDER_DEFAULT, &userToken);





	dump(userToken);

	DWORD lLastError;

	if (!GetTokenInformation(userToken, TokenType, &lTokenType, sizeof(lTokenType), &lReturnLength))
	{
		lLastError = GetLastError();
		return;
	}

	if (!DuplicateTokenEx(userToken, MAXIMUM_ALLOWED, NULL, SecurityDelegation, TokenPrimary, &primaryToken))
	{
		lLastError = GetLastError();

		const char* tokenImpersonationType = "SecurityDelegation";
		// If delegation is not allowed, the error is usually ERROR_BAD_IMPERSONATION_LEVEL, try a lower level of impersonation.

		if (!DuplicateTokenEx(userToken, MAXIMUM_ALLOWED, NULL, SecurityImpersonation, TokenPrimary, &primaryToken))
		{
			lLastError = GetLastError();
			return;
		}
	}


	dump(userToken);

	if (lTokenType != TokenPrimary)
	{
		start_info.lpDesktop = "WinSta0\\Default";

		auto ret = CreateProcessAsUser(
			primaryToken, nullptr, const_cast<LPSTR>(command.data()), nullptr, nullptr, TRUE,
			CREATE_NEW_PROCESS_GROUP | DETACHED_PROCESS | CREATE_DEFAULT_ERROR_MODE | NORMAL_PRIORITY_CLASS | CREATE_SUSPENDED, pEnvironment, pWorkdir, &start_info, &piProcInfo);
		lLastError = GetLastError();
		CloseHandle(primaryToken);
		CloseHandle(userToken);
	}
	else
		return;
}

} // namespace process
