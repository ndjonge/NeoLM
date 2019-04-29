#pragma once

#ifdef WIN32
#include <Sddl.h>
#include <string>
#include <windows.h>
#include <windowsx.h> 
#include <userenv.h> 
#endif

namespace process
{

#ifdef WIN32
void spawn_as_user(const std::string& command, const std::string& user, const std::string& password)
{
	HANDLE CallerToken = NULL;
	HANDLE CalleeToken = NULL;
	STARTUPINFO si;
	PROCESS_INFORMATION pi;

	if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ALL_ACCESS, &CallerToken))
	{
		if (CallerToken) CloseHandle(CallerToken);

		throw std::runtime_error{ "OpenProcessToken failed - " + std::to_string(GetLastError()) };
	}

	//	CheckPrivilege(CallerToken, SE_INCREASE_QUOTA_NAME, &PrivCheck);
	//	CheckPrivilege(CallerToken, SE_ASSIGNPRIMARYTOKEN_NAME, &PrivCheck);

	if (!LogonUser(user.c_str(), NULL, password.c_str(), LOGON32_LOGON_INTERACTIVE, LOGON32_PROVIDER_DEFAULT, &CalleeToken))
	{
		if (CallerToken) CloseHandle(CallerToken);

		throw std::runtime_error{ "LogonUser failed - " + std::to_string(GetLastError()) };
	}

	ZeroMemory(&si, sizeof(STARTUPINFO));
	si.cb = sizeof(STARTUPINFO);
	si.lpDesktop = "";

	if (!ImpersonateLoggedOnUser(CalleeToken))
	{
		if (CallerToken) CloseHandle(CallerToken);

		throw std::runtime_error{ "ImpersonateLoggedOnUser failed - " + std::to_string(GetLastError()) };
	}

	if (!CreateProcessAsUser(CalleeToken, NULL, const_cast<char*>(command.data()), NULL, NULL, FALSE, 0, NULL, NULL, &si, &pi))
	{
		if (CalleeToken) CloseHandle(CalleeToken);

		throw std::runtime_error{ "CreateProcessAsUser failed - " + std::to_string(GetLastError()) };
	}

	WaitForSingleObject(pi.hProcess, INFINITE);

	RevertToSelf();

	CloseHandle(pi.hProcess);
	CloseHandle(pi.hThread);

//Cleanup:
//	if (Winsta0) CloseWindowStation(Winsta0);
//	if (Desktop) CloseDesktop(Desktop);
//	if (LogonSid) HeapFree(GetProcessHeap(), 0, LogonSid);

}

#endif

} // namespace process
