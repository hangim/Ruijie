#include <tchar.h>
#include <windows.h>
#include "process.h"

BOOL FindAndKillProcessByName(LPCTSTR strProcessName) {
    if(NULL == strProcessName) {
        return FALSE; 
    }

    HANDLE handle32Snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (INVALID_HANDLE_VALUE == handle32Snapshot) {
            return FALSE;
    }
 
    PROCESSENTRY32 pEntry;       
    pEntry.dwSize = sizeof( PROCESSENTRY32 );
 
    //Search for all the process and terminate it
    if(Process32First(handle32Snapshot, &pEntry)) {
        BOOL bFound = FALSE;
        if (!_tcsicmp(pEntry.szExeFile, strProcessName)) {
            bFound = TRUE;
        }
        while((!bFound)&&Process32Next(handle32Snapshot, &pEntry)) {
            if (!_tcsicmp(pEntry.szExeFile, strProcessName)) {
                bFound = TRUE;
            }
        }
        if(bFound) {
            CloseHandle(handle32Snapshot);
            HANDLE handLe =  OpenProcess(PROCESS_TERMINATE , FALSE, pEntry.th32ProcessID);
            BOOL bResult = TerminateProcess(handLe,0);
            return bResult;
        }
    }
 
    CloseHandle(handle32Snapshot);
    return FALSE;
}
