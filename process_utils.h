#pragma once
#include <Sddl.h>
#include <string>
#include <windows.h>

namespace process
{

namespace
{

void RunAs(LPWSTR inUser, LPWSTR inPW, LPWSTR inCommand);

} // namespace

struct PRIVILAGENAME_MAPPING
{
	CHAR SymbolName[1024];
	CHAR PrivilegeName[1024];
};

const PRIVILAGENAME_MAPPING PrivilegeNameMapping[] = { { "SE_CREATE_TOKEN_NAME", SE_CREATE_TOKEN_NAME },
													   { "SE_ASSIGNPRIMARYTOKEN_NAME", SE_ASSIGNPRIMARYTOKEN_NAME },
													   { "SE_LOCK_MEMORY_NAME", SE_LOCK_MEMORY_NAME },
													   { "SE_INCREASE_QUOTA_NAME", SE_INCREASE_QUOTA_NAME },
													   { "SE_UNSOLICITED_INPUT_NAME", SE_UNSOLICITED_INPUT_NAME }, // no LUID?
													   { "SE_MACHINE_ACCOUNT_NAME", SE_MACHINE_ACCOUNT_NAME },
													   { "SE_TCB_NAME", SE_TCB_NAME },
													   { "SE_SECURITY_NAME", SE_SECURITY_NAME },
													   { "SE_TAKE_OWNERSHIP_NAME", SE_TAKE_OWNERSHIP_NAME },
													   { "SE_LOAD_DRIVER_NAME", SE_LOAD_DRIVER_NAME },
													   { "SE_SYSTEM_PROFILE_NAME", SE_SYSTEM_PROFILE_NAME },
													   { "SE_SYSTEMTIME_NAME", SE_SYSTEMTIME_NAME },
													   { "SE_PROF_SINGLE_PROCESS_NAME", SE_PROF_SINGLE_PROCESS_NAME },
													   { "SE_INC_BASE_PRIORITY_NAME", SE_INC_BASE_PRIORITY_NAME },
													   { "SE_CREATE_PAGEFILE_NAME", SE_CREATE_PAGEFILE_NAME },
													   { "SE_CREATE_PERMANENT_NAME", SE_CREATE_PERMANENT_NAME },
													   { "SE_BACKUP_NAME", SE_BACKUP_NAME },
													   { "SE_RESTORE_NAME", SE_RESTORE_NAME },
													   { "SE_SHUTDOWN_NAME", SE_SHUTDOWN_NAME },
													   { "SE_DEBUG_NAME", SE_DEBUG_NAME },
													   { "SE_AUDIT_NAME", SE_AUDIT_NAME },
													   { "SE_SYSTEM_ENVIRONMENT_NAME", SE_SYSTEM_ENVIRONMENT_NAME },
													   { "SE_CHANGE_NOTIFY_NAME", SE_CHANGE_NOTIFY_NAME },
													   { "SE_REMOTE_SHUTDOWN_NAME", SE_REMOTE_SHUTDOWN_NAME },
													   { "SE_UNDOCK_NAME", SE_UNDOCK_NAME },
													   { "SE_SYNC_AGENT_NAME", SE_SYNC_AGENT_NAME },
													   { "SE_ENABLE_DELEGATION_NAME", SE_ENABLE_DELEGATION_NAME },
													   { "SE_MANAGE_VOLUME_NAME", SE_MANAGE_VOLUME_NAME },
													   { "SE_IMPERSONATE_NAME", SE_IMPERSONATE_NAME },
													   { "SE_CREATE_GLOBAL_NAME", SE_CREATE_GLOBAL_NAME },
													   { "SE_TRUSTED_CREDMAN_ACCESS_NAME", SE_TRUSTED_CREDMAN_ACCESS_NAME },
													   { "SE_RELABEL_NAME", SE_RELABEL_NAME },
													   { "SE_INC_WORKING_SET_NAME", SE_INC_WORKING_SET_NAME },
													   { "SE_TIME_ZONE_NAME", SE_TIME_ZONE_NAME },
													   { "SE_CREATE_SYMBOLIC_LINK_NAME", SE_CREATE_SYMBOLIC_LINK_NAME },
													   { "", "" } };

BOOL LookupPrivilegeName(
	LPCWSTR SystemName,
	CONST PLUID Luid,
	LPSTR* SymbolName,
	LPSTR PrivilegeName,
	LPDWORD PrivilegeNameLength,
	LPSTR DisplayName,
	LPDWORD DisplayNameLength,
	BOOL NoErrMsg)
{
	BOOL Ret = FALSE;
	DWORD LanguageId;
	int Index = -1;

	Ret = LookupPrivilegeName(NULL, Luid, PrivilegeName, PrivilegeNameLength);
	if (!Ret)
	{
		if (GetLastError() != ERROR_INSUFFICIENT_BUFFER && !NoErrMsg) wprintf(L"LookupPrivilegeName failed - 0x%08x\n", GetLastError());
		goto cleanup;
	}

	Ret = LookupPrivilegeDisplayName(NULL, PrivilegeName, DisplayName, DisplayNameLength, &LanguageId);
	if (!Ret)
	{
		if (GetLastError() != ERROR_INSUFFICIENT_BUFFER && !NoErrMsg) wprintf(L"LookupPrivilegeDisplayName failed - 0x%08x\n", GetLastError());
		goto cleanup;
	}

	Ret = FALSE;
	const PRIVILAGENAME_MAPPING* p = PrivilegeNameMapping;
	for (Index = 0; p->SymbolName[0] != 0; ++p, ++Index)
	{
		if (strcmp(PrivilegeName, p->PrivilegeName) == 0)
		{
			Ret = TRUE;
			break;
		}
	}

	if (Ret)
		SymbolName = (LPSTR*)&PrivilegeNameMapping[Index].SymbolName[0];
	else if (NoErrMsg)
		wprintf(L"%s not found\n", PrivilegeName);

cleanup:
	return Ret;
}

BOOL LookupPrivilegeValueEx(LPCSTR SystemName, LPCSTR Name, PLUID Luid)
{
	BOOL Ret = LookupPrivilegeValue(SystemName, Name, Luid);
	if (!Ret && GetLastError() == ERROR_NO_SUCH_PRIVILEGE)
	{
		const PRIVILAGENAME_MAPPING* p;
		for (p = PrivilegeNameMapping; p->SymbolName[0] != 0; ++p)
		{
			if (strcmp(Name, p->SymbolName) == 0) return LookupPrivilegeValue(SystemName, p->PrivilegeName, Luid);
		}
		SetLastError(ERROR_NO_SUCH_PRIVILEGE);
		Ret = FALSE;
	}
	return Ret;
}

// >0 Enabled
// =0 Disabled
// <0 Not assigned
BOOL CheckPrivilege(HANDLE Token, LPCSTR PrivilegeName, LPLONG Privileged)
{
	LUID luid;
	if (!LookupPrivilegeValueEx(NULL, PrivilegeName, &luid))
	{
		wprintf(L"LookupPrivilegeValue failed - 0x%08x\n", GetLastError());
		return FALSE;
	}

	PRIVILEGE_SET PrivilegeSet;
	PrivilegeSet.Control = 0;
	PrivilegeSet.PrivilegeCount = 1;
	PrivilegeSet.Privilege[0].Luid = luid;
	PrivilegeSet.Privilege[0].Attributes = 0; // not used

	BOOL Check;
	if (!PrivilegeCheck(Token, &PrivilegeSet, &Check))
	{
		wprintf(L"PrivilegeCheck failed - 0x%08x\n", GetLastError());
		return FALSE;
	}

	if (Check)
		*Privileged = 1;
	else
	{
		TOKEN_PRIVILEGES tp;
		tp.PrivilegeCount = 1;
		tp.Privileges[0].Luid = luid;
		tp.Privileges[0].Attributes = 0;

		if (!AdjustTokenPrivileges(Token, FALSE, &tp, sizeof(TOKEN_PRIVILEGES), NULL, NULL))
		{
			wprintf(L"AdjustTokenPrivileges failed - 0x%08x\n", GetLastError());
			return FALSE;
		}

		*Privileged = (GetLastError() == ERROR_NOT_ALL_ASSIGNED) ? -1 : 0;
	}

	return TRUE;
}

void RunAs(LPSTR inUser, LPSTR inPW, LPSTR inCommand)
{
	HANDLE CallerToken = NULL;
	HANDLE CalleeToken = NULL;
	HWINSTA WinstaOld = NULL;
	HWINSTA Winsta0 = NULL;
	HDESK Desktop = NULL;
	PSID LogonSid = NULL;
	STARTUPINFO si;
	PROCESS_INFORMATION pi;
	LONG PrivCheck = 0;

	if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ALL_ACCESS, &CallerToken))
	{
		wprintf(L"OpenProcessToken failed - 0x%08x\n", GetLastError());
		goto Cleanup;
	}

	CheckPrivilege(CallerToken, SE_INCREASE_QUOTA_NAME, &PrivCheck);

	if (PrivCheck < 0) printf("CreateProcessAsUser requires %s.  Check the user's privileges.\n", SE_INCREASE_QUOTA_NAME);

	CheckPrivilege(CallerToken, SE_ASSIGNPRIMARYTOKEN_NAME, &PrivCheck);

	if (PrivCheck < 0) printf("CreateProcessAsUser requires %s.  Check the user's privileges.\n", SE_ASSIGNPRIMARYTOKEN_NAME);

	if (!LogonUser(inUser, NULL, inPW, LOGON32_LOGON_INTERACTIVE, LOGON32_PROVIDER_DEFAULT, &CalleeToken))
	{
		printf("LogonUser failed - 0x%08x\n", GetLastError());
		goto Cleanup;
	}

#ifdef _GUI
	Winsta0 = OpenWindowStation(L"winsta0", FALSE, READ_CONTROL | WRITE_DAC);
	if (!Winsta0)
	{
		wprintf(L"OpenWindowStation failed - 0x%08x\n", GetLastError());
		goto Cleanup;
	}

	WinstaOld = GetProcessWindowStation();
	if (!SetProcessWindowStation(Winsta0))
	{
		wprintf(L"SetProcessWindowStation failed - 0x%08x\n", GetLastError());
		goto Cleanup;
	}
	Desktop = OpenDesktop(L"default", 0, FALSE, READ_CONTROL | WRITE_DAC | DESKTOP_WRITEOBJECTS | DESKTOP_READOBJECTS);
	SetProcessWindowStation(WinstaOld);
	if (!Desktop)
	{
		wprintf(L"OpenDesktop failed - 0x%08x\n", GetLastError());
		goto Cleanup;
	}

	if (!GetLogonSidFromToken(CalleeToken, &LogonSid)) goto Cleanup;

#ifdef _TRACING
	wprintf(L"PID      : 0x%x\n", GetCurrentProcessId());
	wprintf(L"HWINSTA  : 0x%x\n", Winsta0);
	wprintf(L"HDESK    : 0x%x\n", Desktop);
	wprintf(L"Logon SID: %p\n", LogonSid);
	wprintf(L"-----\n");
	getwchar();
#endif

	if (!AddAceToWindowStation(Winsta0, LogonSid))
	{
		wprintf(L"AddAceToWindowStation failed - 0x%08x\n", GetLastError());
		goto Cleanup;
	}

	if (!AddAceToDesktop(Desktop, LogonSid))
	{
		wprintf(L"AddAceToDesktop failed - 0x%08x\n", GetLastError());
		goto Cleanup;
	}
#endif

	ZeroMemory(&si, sizeof(STARTUPINFO));
	si.cb = sizeof(STARTUPINFO);

#ifdef _GUI
	si.lpDesktop = "winsta0\\default";
#else
	si.lpDesktop = "";
#endif

	if (!ImpersonateLoggedOnUser(CalleeToken))
	{
		wprintf(L"ImpersonateLoggedOnUser failed - 0x%08x\n", GetLastError());
		goto Cleanup;
	}

	if (!CreateProcessAsUser(CalleeToken, NULL, "cmd", NULL, NULL, FALSE, 0, NULL, NULL, &si, &pi))
	{
		wprintf(L"CreateProcessAsUser failed - 0x%08x\n", GetLastError());
		goto Cleanup;
	}

	WaitForSingleObject(pi.hProcess, INFINITE);

	RevertToSelf();

#ifdef _GUI
	RemoveAccessAllowedAcesBasedSID(Winsta0, LogonSid);
	RemoveAccessAllowedAcesBasedSID(Desktop, LogonSid);
#endif

	CloseHandle(pi.hProcess);
	CloseHandle(pi.hThread);

Cleanup:
	if (LogonSid) HeapFree(GetProcessHeap(), 0, LogonSid);
	if (Winsta0) CloseWindowStation(Winsta0);
	if (Desktop) CloseDesktop(Desktop);
	if (CalleeToken) CloseHandle(CalleeToken);
	if (CallerToken) CloseHandle(CallerToken);
}

void spawn_as_user(const std::string& command) { RunAs("testuser", "test", "notepad"); }

} // namespace process
