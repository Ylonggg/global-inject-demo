#include "stdafx.h"
#include "customization_session.h"
#include "session_private_namespace.h"
#include "logger.h"
#include <cwchar>

extern HINSTANCE g_hDllInst;

namespace
{
	// 고정 숨김 프로세스 이름
	#define STR_HIDE_PROCESS_NAME (L"notepad.exe")

	// ZwQuerySystemInformation 관련 선언
	typedef LONG NTSTATUS;
#ifndef STATUS_SUCCESS
	#define STATUS_SUCCESS ((NTSTATUS)0x00000000L)
#endif

	typedef enum _SYSTEM_INFORMATION_CLASS {
		SystemBasicInformation = 0,
		SystemPerformanceInformation = 2,
		SystemTimeOfDayInformation = 3,
		SystemProcessInformation = 5,
		SystemProcessorPerformanceInformation = 8,
		SystemInterruptInformation = 23,
		SystemExceptionInformation = 33,
		SystemRegistryQuotaInformation = 37,
		SystemLookasideInformation = 45
	} SYSTEM_INFORMATION_CLASS;

	typedef struct _SYSTEM_PROCESS_INFORMATION {
		ULONG NextEntryOffset;
		ULONG NumberOfThreads;
		BYTE Reserved1[48];
		PVOID Reserved2[3];
		HANDLE UniqueProcessId;
		PVOID Reserved3;
		ULONG HandleCount;
		BYTE Reserved4[4];
		PVOID Reserved5[11];
		SIZE_T PeakPagefileUsage;
		SIZE_T PrivatePageCount;
		LARGE_INTEGER Reserved6[6];
	} SYSTEM_PROCESS_INFORMATION, *PSYSTEM_PROCESS_INFORMATION;

	typedef NTSTATUS(WINAPI* PFZWQUERYSYSTEMINFORMATION)(
		SYSTEM_INFORMATION_CLASS SystemInformationClass,
		PVOID SystemInformation,
		ULONG SystemInformationLength,
		PULONG ReturnLength);

	// MinHook이 원본 포인터를 채워줄 변수
	PFZWQUERYSYSTEMINFORMATION pOriginalZwQuerySystemInformation = nullptr;

	// Hook 함수: 프로세스 리스트에서 STR_HIDE_PROCESS_NAME 항목 제거
	NTSTATUS WINAPI NewZwQuerySystemInformation(
		SYSTEM_INFORMATION_CLASS SystemInformationClass,
		PVOID SystemInformation,
		ULONG SystemInformationLength,
		PULONG ReturnLength)
	{
		// 원본 호출
		NTSTATUS status = STATUS_SUCCESS;
		if (pOriginalZwQuerySystemInformation) {
			status = pOriginalZwQuerySystemInformation(SystemInformationClass, SystemInformation, SystemInformationLength, ReturnLength);
		}
		else {
			return STATUS_SUCCESS;
		}

		if (status != STATUS_SUCCESS) {
			return status;
		}

		// Process 목록일 때만 필터 적용
		if (SystemInformationClass == SystemProcessInformation && SystemInformation != nullptr) {
			PSYSTEM_PROCESS_INFORMATION pCur = reinterpret_cast<PSYSTEM_PROCESS_INFORMATION>(SystemInformation);
			PSYSTEM_PROCESS_INFORMATION pPrev = nullptr;

			while (TRUE) {
				// Reserved2[1]가 프로세스 이름 포인터를 포함하는 경우가 많음(환경에 따라 다를 수 있음)
				if (pCur->Reserved2[1] != nullptr) {
					PWSTR pName = reinterpret_cast<PWSTR>(pCur->Reserved2[1]);
					if (pName != nullptr && _wcsicmp(pName, STR_HIDE_PROCESS_NAME) == 0) {
						// 현재 항목을 리스트에서 제거
						if (pPrev) {
							// 이전 항목이 있으면 NextEntryOffset을 더한다.
							if (pCur->NextEntryOffset == 0) {
								pPrev->NextEntryOffset = 0;
							}
							else {
								pPrev->NextEntryOffset += pCur->NextEntryOffset;
							}
						}
						else {
							// 첫 항목을 제거: 다음 블록을 앞으로 당김
							if (pCur->NextEntryOffset != 0) {
								BYTE* pBase = reinterpret_cast<BYTE*>(SystemInformation);
								BYTE* pNext = reinterpret_cast<BYTE*>(pCur) + pCur->NextEntryOffset;
								// SystemInformationLength이 0일 수도 있으니 안전하게 계산
								SIZE_T tailSize = (SystemInformationLength > 0 && pNext > pBase && (SIZE_T)(pNext - pBase) < SystemInformationLength)
									? SystemInformationLength - (pNext - pBase)
									: 0;
								if (tailSize > 0) {
									memmove(pCur, pNext, tailSize);
									// pCur는 덮어쓴 다음 항목을 가리키도록 유지하여 계속 검사
									continue;
								}
								else {
									// 다음 항목이 없으면 빈 리스트로 만든다.
									// pCur는 그대로 두고 루프 종료
									break;
								}
							}
							else {
								// 리스트에 하나만 있는 경우: 빈 리스트 처리
								// 아무 것도 할 수 없으므로 루프 종료
								break;
							}
						}
						// 삭제한 경우 pPrev는 변경하지 않음
					}
					else {
						// 삭제 대상 아님 -> 이전 포인터 갱신
						pPrev = pCur;
					}
				}
				else {
					// 이름 포인터가 없으면 이전 포인터 갱신
					pPrev = pCur;
				}

				if (pCur->NextEntryOffset == 0) {
					break;
				}

				pCur = reinterpret_cast<PSYSTEM_PROCESS_INFORMATION>(reinterpret_cast<BYTE*>(pCur) + pCur->NextEntryOffset);
			}
		}

		return status;
	}
}

// MinHook 기반 훅 설치: ZwQuerySystemInformation만 훅
MH_STATUS InitCustomizationHooks()
{
	HMODULE hNtdll = GetModuleHandleW(L"ntdll.dll");
	if (!hNtdll) {
		return MH_ERROR_MODULE_NOT_FOUND;
	}

	FARPROC pTarget = GetProcAddress(hNtdll, "ZwQuerySystemInformation");
	if (!pTarget) {
		return MH_ERROR_FUNCTION_NOT_FOUND;
	}

	MH_STATUS status = MH_CreateHook(pTarget, reinterpret_cast<void*>(NewZwQuerySystemInformation),
		reinterpret_cast<void**>(&pOriginalZwQuerySystemInformation));
	if (status == MH_OK) {
		status = MH_QueueEnableHook(pTarget);
	}

	return status;
}

bool CustomizationSession::Start(bool runningFromAPC, HANDLE sessionManagerProcess, HANDLE sessionMutex) noexcept
{
	auto instance = new (std::nothrow) CustomizationSession();
	if (!instance) {
		LOG(L"Allocation of CustomizationSession failed");
		return false;
	}

	if (!instance->StartAllocated(runningFromAPC, sessionManagerProcess, sessionMutex)) {
		delete instance;
		return false;
	}

	// Instance will free itself.
	return true;
}

bool CustomizationSession::StartAllocated(bool runningFromAPC, HANDLE sessionManagerProcess, HANDLE sessionMutex) noexcept
{
	// Create the session semaphore. This will block the library if another instance
	// (from another session manager process) is already injected and its customization session is active.
	WCHAR szSemaphoreName[sizeof("CustomizationSessionSemaphore-pid=1234567890")];
	swprintf_s(szSemaphoreName, L"CustomizationSessionSemaphore-pid=%u", GetCurrentProcessId());

	HRESULT hr = m_sessionSemaphore.create(1, 1, szSemaphoreName);
	if (FAILED(hr)) {
		LOG(L"Semaphore creation failed with error %08X", hr);
		return false;
	}

	m_sessionSemaphoreLock = m_sessionSemaphore.acquire();

	if (WaitForSingleObject(sessionManagerProcess, 0) != WAIT_TIMEOUT) {
		VERBOSE(L"Session manager process is no longer running");
		return false;
	}

	if (!InitSession(runningFromAPC, sessionManagerProcess)) {
		return false;
	}

	if (runningFromAPC) {
		// Create a new thread for us to allow the program's main thread to run.
		try {
			// Note: Before creating the thread, the CRT/STL bumps the
			// reference count of the module, something a plain CreateThread
			// doesn't do.
			std::thread thread(&CustomizationSession::RunAndDeleteThis, this,
				sessionManagerProcess, sessionMutex);
			thread.detach();
		}
		catch (const std::exception& e) {
			LOG(L"%S", e.what());
			UninitSession();
			return false;
		}
	}
	else {
		// No need to create a new thread, a dedicated thread was created for us
		// before injection.
		RunAndDeleteThis(sessionManagerProcess, sessionMutex);
	}

	return true;
}

bool CustomizationSession::InitSession(bool runningFromAPC, HANDLE sessionManagerProcess) noexcept
{
	MH_STATUS status = MH_Initialize();
	if (status != MH_OK) {
		LOG(L"MH_Initialize failed with %d", status);
		return false;
	}

	if (runningFromAPC) {
		// No other threads should be running, skip thread freeze.
		MH_SetThreadFreezeMethod(MH_FREEZE_METHOD_NONE_UNSAFE);
	}
	else {
		MH_SetThreadFreezeMethod(MH_FREEZE_METHOD_FAST_UNDOCUMENTED);
	}

	try {
		m_newProcessInjector.emplace(sessionManagerProcess);
	}
	catch (const std::exception& e) {
		LOG(L"InitSession failed: %S", e.what());
		m_newProcessInjector.reset();
		MH_Uninitialize();
		return false;
	}

	status = InitCustomizationHooks();
	if (status != MH_OK) {
		LOG(L"InitCustomizationHooks failed with %d", status);
	}

	status = MH_ApplyQueued();
	if (status != MH_OK) {
		LOG(L"MH_ApplyQueued failed with %d", status);
	}

	if (runningFromAPC) {
		MH_SetThreadFreezeMethod(MH_FREEZE_METHOD_FAST_UNDOCUMENTED);
	}

	return true;
}

void CustomizationSession::RunAndDeleteThis(HANDLE sessionManagerProcess, HANDLE sessionMutex) noexcept
{
	m_sessionManagerProcess.reset(sessionManagerProcess);

	if (sessionMutex) {
		m_sessionMutex.reset(sessionMutex);
	}

	// Prevent the system from displaying the critical-error-handler message box.
	// A message box like this was appearing while trying to load a dll in a
	// process with the ProcessSignaturePolicy mitigation, and it looked like this:
	// https://stackoverflow.com/q/38367847
	DWORD dwOldMode;
	SetThreadErrorMode(SEM_FAILCRITICALERRORS, &dwOldMode);

	Run();

	SetThreadErrorMode(dwOldMode, nullptr);

	delete this;
}

void CustomizationSession::Run() noexcept
{
	DWORD waitResult = WaitForSingleObject(m_sessionManagerProcess.get(), INFINITE);
	if (waitResult != WAIT_OBJECT_0) {
		LOG(L"WaitForSingleObject returned %u, last error %u", waitResult, GetLastError());
	}

	VERBOSE(L"Uninitializing and freeing library");

	UninitSession();
}

void CustomizationSession::UninitSession() noexcept
{
	// MinHook uninitialize: 훅 해제 및 리소스 정리
	MH_STATUS status = MH_Uninitialize();
	if (status != MH_OK) {
		LOG(L"MH_Uninitialize failed with status %d", status);
	}

	m_newProcessInjector.reset();
}
