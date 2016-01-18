#include "stdafx.h"
#include <windows.h>
#include <Winternl.h>
#include <iostream>
#include <ctype.h>
#include <string>
#include <Lmcons.h>
#include "StdAfx.h"
#include "tlhelp32.h"
#include "stdio.h"
#include<windows.h>
using namespace std;
#include <windows.h>
#include <tchar.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

using namespace std;
typedef NTSTATUS (WINAPI *ZwQueryInformationProcess)(
  __in       HANDLE ProcessHandle,
  __in       PROCESSINFOCLASS ProcessInformationClass,
  __out      PVOID ProcessInformation,
  __in       ULONG ProcessInformationLength,
  __out_opt  PULONG ReturnLength
);
typedef NTSTATUS (WINAPI *ZwSetInformationThread) (
    __in HANDLE ThreadHandle,
    __in THREADINFOCLASS ThreadInformationClass,
    __in_bcount(ThreadInformationLength) PVOID ThreadInformation,
    __in ULONG ThreadInformationLength
    );
BOOL IsAdmin(VOID)
{
bool bIsAdmin = false;
HANDLE htok = 0;
return false;
}
void leavingtime(void)
{
typedef struct tagLASTINPUTINFO { UINT cbSize; DWORD dwTime; } LASTINPUTINFO, *PLASTINPUTINFO;   
typedef BOOL (*MyGetLastInputInfo)(PLASTINPUTINFO);  
MyGetLastInputInfo MyGetLastInputInfo_Address;  


LASTINPUTINFO lii;  
    lii.cbSize=sizeof(LASTINPUTINFO);  

    HMODULE hModule = LoadLibrary(_T("User32.dll"));  
    MyGetLastInputInfo_Address = (MyGetLastInputInfo)GetProcAddress(hModule,"GetLastInputInfo");  
    if (MyGetLastInputInfo_Address == NULL)  
    {  
        MessageBox(0,_T("GetProcAddress error"),0,0);  
        return;  
    }  
    
    //MyGetLastInputInfo_Address(&lii);  
    
    __asm  
    {  
        lea eax,lii  
        push eax  
        call MyGetLastInputInfo_Address  
    }  
     
    unsigned long ulTickTimes = GetTickCount() - lii.dwTime;  
    if (ulTickTimes >= 10000)  
    {  
        MessageBox(0,_T("离开状态"),_T("离开"),0);  
    }  
}
void getusername()
{

    TCHAR name [ UNLEN + 1 ];
DWORD size = UNLEN + 1;
GetUserName( (TCHAR*)name, &size );

}
void getmodulehandle()
{


    HMODULE hModule = GetModuleHandle(_T("SbieDll.dll"));  
    _tprintf(TEXT("with GetModuleHandle(NULL) = 0x%x\r\n"), hModule);  

}

void  antidebug_ZwSetInformationThread()
{
      HMODULE hModule = LoadLibrary(TEXT("ntdll.dll"));
      ZwSetInformationThread pZwSetInformationThread = (ZwSetInformationThread)GetProcAddress(hModule, "ZwSetInformationThread");

       pZwSetInformationThread(GetCurrentThread(), (THREADINFOCLASS)0x11, 0, 0);

}
bool  antidebug_ZwQueryInformationProcess()
{


     HMODULE hmod;
     ZwQueryInformationProcess pZwQueryInformationProcess;

    int status;
    DWORD debugFlag=0;

    hmod = LoadLibrary(_T("ntdll.dll"));

    pZwQueryInformationProcess =(ZwQueryInformationProcess) GetProcAddress(hmod, "ZwQueryInformationProcess");


     if (pZwQueryInformationProcess == NULL) 
       return false;
   // status=(_NtQueryInformationProcess) ();
    status = pZwQueryInformationProcess((HANDLE )-1,(PROCESSINFOCLASS) 31, &debugFlag, 4, NULL); // 31 (0xf1)is the enum for DebugProcessFlags
  //  printf(_T("%08X\n"), debugFlag);

 //  if (debugFlag == 0x00000000) MessageBox(NULL, _T("Debugger Detected via ProcessDebugFlags"), _T("Debugger Detected"), MB_OK);
 //   if (debugFlag == 0x00000001) MessageBox(NULL, _T("No Debugger Detected"), _T("No Debugger"), MB_OK);



    return true;
}
void DisableWriteProtect( PULONG pOldAttr)
{
    ULONG uAttr;
    _asm
    {
        push eax;
        mov  eax, cr0;
        mov  uAttr, eax;
        and  eax, 0FFFEFFFFh; // CR0 16 BIT = 0
        mov  cr0, eax;
        pop  eax;
        cli;
    };
    *pOldAttr = uAttr; 
}
void checkallprocess(void)
{

HANDLE hSnapShot=CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS,0);

 PROCESSENTRY32 pe32;
 pe32.dwSize = sizeof(pe32);


int processID;
HANDLE hProcess;
processID=12;
LPCTSTR procesname =TEXT("OtherTestData");
BOOL bMore =Process32First(hSnapShot,&pe32);

   while (bMore)

   {
  // if(!strcmp(pe32.szExeFile,procesname))
   {
    if(pe32.th32ProcessID==processID)
    {
      printf("process name ：%s\n",pe32.szExeFile);
      hProcess=OpenProcess(PROCESS_ALL_ACCESS,TRUE,processID);
        TerminateProcess(hProcess,0);
      printf("process ID：%u\n\n",pe32.th32ProcessID);
    }
   }
     printf("process ID：%u\n\n",pe32.th32ProcessID);
   bMore = Process32Next(hSnapShot,&pe32);

   }



   CloseHandle(hSnapShot);




}
/////////////////////////////////////////////////////////////////
void SuspendProcess(DWORD dwProcessID)

{

         HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, dwProcessID);                  
         if (hSnapshot != INVALID_HANDLE_VALUE)

         {

                   THREADENTRY32 te;

                   ZeroMemory(&te, sizeof(te));

                   te.dwSize = sizeof(te);
                   BOOL bOK = Thread32First(hSnapshot, &te);  

                   for (; bOK; bOK = Thread32Next(hSnapshot, &te))

                   {
                           printf("thread ID：%u\n\n",te.th32OwnerProcessID);
                            if (te.th32OwnerProcessID == dwProcessID)          
                            {
                                     HANDLE hThread = OpenThread(THREAD_SUSPEND_RESUME, FALSE, te.th32ThreadID);
                                     if (hThread != NULL)
                                     {
                                           //    if (bSuspend)
                                               {
                                                        SuspendThread(hThread);
                                               }
                                          //     else
                                                        ResumeThread(hThread);
                                     }
                                   CloseHandle(hThread);
                            }
                   }

         }

         CloseHandle(hSnapshot);

}
/*
int get_hostname_by_ip(char* h , char* ip)
{
        struct hostent *he;
        struct in_addr **addr_list;
        int i;

        if ((he = gethostbyname(h)) == NULL) 
        {
                perror("gethostbyname");
                return 1;
        }
        addr_list = (struct in_addr **) he->h_addr_list;
        for(i = 0; addr_list[i] != NULL; i++) 
        {
                strcpy(ip , inet_ntoa(*addr_list[i]) );
                return 0;
        }

        return 1;
}
struct info
{
        char* h;
        int c;
};

void* thread_entry_point(void* i)
{
        info* in = (info*)i;
        client(in->h);
}

void client(char* h)
{
    int fd;
        char* ip = new char[20];
        int port = 80;
    struct sockaddr_in addr;
    char ch[]="aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        while(1)
        {
                fd = socket(AF_INET, SOCK_STREAM, 0);
                addr.sin_family=AF_INET;
                get_hostname_by_ip(h, ip);
                addr.sin_addr.s_addr=inet_addr(ip);
                addr.sin_port=htons(port);
                if(connect(fd, (struct sockaddr*)&addr, sizeof(addr)) < 0) 
                {
                        perror("error: can't connect to server\n");
                        return;
                }
                if(send(fd, ch, sizeof(ch), 0) < 0)
                {       
                        perror("error: can't send\n");
                }
                close(fd);
        }
}

void DDosattack(int argc, char** argv)
{

     int s = atoi(argv[2]);
        pthread_t t[s];
        info in = {argv[1], s};
        for(int i = 0; i < s; ++i)
        {
                pthread_create(&t[i], NULL, thread_entry_point, (void*)&in);
        }
        pthread_join(t[0], NULL);



}*/

 typedef struct _OBJECT_TYPE_INFORMATION {
      UNICODE_STRING TypeName;
       ULONG TotalNumberOfHandles;
       ULONG TotalNumberOfObjects;
   }OBJECT_TYPE_INFORMATION, *POBJECT_TYPE_INFORMATION;

   // Returned by the ObjectAllTypeInformation class
   // passed to NtQueryObject
   typedef struct _OBJECT_ALL_INFORMATION {
       ULONG NumberOfObjects;
       OBJECT_TYPE_INFORMATION ObjectTypeInformation[1];
   }OBJECT_ALL_INFORMATION, *POBJECT_ALL_INFORMATION;

// ObjectListCheck uses NtQueryObject to check the environments
// list of objects and more specifically for the number of
// debug objects. This function can cause an exception (although rarely)
// so either surround it in a try catch or __try __except block
// but that shouldn't happen unless one tinkers with the function
 bool  ObjectListCheck()

{
    typedef NTSTATUS(NTAPI *pNtQueryObject)
            (HANDLE, UINT, PVOID, ULONG, PULONG);

    POBJECT_ALL_INFORMATION pObjectAllInfo = NULL;
    void *pMemory = NULL;
    NTSTATUS Status;
    unsigned long Size = 0;

    // Get NtQueryObject
    pNtQueryObject NtQO = (pNtQueryObject)GetProcAddress( 
                GetModuleHandle( TEXT( "ntdll.dll" ) ),
                "NtQueryObject" );

    // Get the size of the list
    Status = NtQO(NULL, 3, //ObjectAllTypesInformation
                        &Size, 4, &Size);

    // Allocate room for the list
    pMemory = VirtualAlloc(NULL, Size, MEM_RESERVE | MEM_COMMIT, 
                    PAGE_READWRITE);

    if(pMemory == NULL)
        return false;

    // Now we can actually retrieve the list
    Status = NtQO((HANDLE)-1, 3, pMemory, Size, NULL);

    // Status != STATUS_SUCCESS
    if (Status != 0x00000000)
    {
        VirtualFree(pMemory, 0, MEM_RELEASE);
        return false;
    }

    // We have the information we need
    pObjectAllInfo = (POBJECT_ALL_INFORMATION)pMemory;

    unsigned char *pObjInfoLocation = 
        (unsigned char*)pObjectAllInfo->ObjectTypeInformation;

    ULONG NumObjects = pObjectAllInfo->NumberOfObjects;

    for(UINT i = 0; i < NumObjects; i++)
    {

        POBJECT_TYPE_INFORMATION pObjectTypeInfo =
            (POBJECT_TYPE_INFORMATION)pObjInfoLocation;

        // The debug object will always be present
        if (wcscmp(L"DebugObject", pObjectTypeInfo->TypeName.Buffer) == 0)
        {
            // Are there any objects?
            if (pObjectTypeInfo->TotalNumberOfObjects > 0)
            {
                VirtualFree(pMemory, 0, MEM_RELEASE);
                return true;
            }
            else
            {
                VirtualFree(pMemory, 0, MEM_RELEASE);
                return false;
            }
        }

        // Get the address of the current entries
        // string so we can find the end
        pObjInfoLocation = 
            (unsigned char*)pObjectTypeInfo->TypeName.Buffer;

        // Add the size
        pObjInfoLocation += 
                pObjectTypeInfo->TypeName.Length;

        // Skip the trailing null and alignment bytes
        ULONG tmp = ((ULONG)pObjInfoLocation) & -4;

        // Not pretty but it works
        pObjInfoLocation = ((unsigned char*)tmp) + 
                        sizeof(unsigned long);
    }

    VirtualFree(pMemory, 0, MEM_RELEASE);
    return true; 
}
   inline bool CheckDbgPresentCloseHandle()
  {
       HANDLE Handle = (HANDLE)0x8000;
       __try
       {
           CloseHandle(Handle);
       }
      __except(EXCEPTION_EXECUTE_HANDLER)
      {
          return true;
       }

       return false;
   }

int gensandbox_drive_size() {
    HANDLE drive;
    BOOL result;
    GET_LENGTH_INFORMATION size;
    DWORD lpBytesReturned;

    drive = CreateFile(_T("\\\\.\\PhysicalDrive0"), GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
    if (drive == INVALID_HANDLE_VALUE) {
        // Someone is playing tricks. Or not enough privileges.
        CloseHandle(drive);
        return FALSE;
    }
    result = DeviceIoControl(drive, IOCTL_DISK_GET_LENGTH_INFO, NULL, 0, &size,
    sizeof(GET_LENGTH_INFORMATION), &lpBytesReturned, NULL);
    CloseHandle(drive);
    if (result != 0) {
        if (size.Length.QuadPart / 1073741824 <= 60) /* <= 60 GB */
        return TRUE;
    }
    result = DeviceIoControl(drive, 0x2D1400, NULL, 0, &size,
    sizeof(GET_LENGTH_INFORMATION), &lpBytesReturned, NULL);
    CloseHandle(drive);
    return FALSE;
}
int gensandbox_drive_size2() {
    ULARGE_INTEGER total_bytes;

    if (GetDiskFreeSpaceExA("C:\\", NULL, &total_bytes, NULL))
    {
        if (total_bytes.QuadPart / 1073741824 <= 60) /* <= 60 GB */
        return TRUE;
    }
    return FALSE;
}  
void readpeb()
{
     long peb;
 __asm
 {  
     mov eax, fs:[30h]
   //  mov eax, byte [eax+2]
     test eax, eax
     mov peb,eax
  }
  peb++;
  int i =0 ;
  while (i<15)
  {
    i++;
  }
}
void MemVirtual(void)
  {
        
       UINT nNewSize = (UINT) ceil(1500 / 1024.0) * 1024;
        PBYTE pNewBuffer = (PBYTE) VirtualAlloc(NULL,nNewSize,MEM_COMMIT,PAGE_READWRITE);
         if (pNewBuffer)
         {
              
               ZeroMemory(pNewBuffer,1500);
               memcpy(pNewBuffer,_T("分配虚拟内存成功/r/n"),
                    sizeof(_T("分配虚拟内存成功/r/n")));
               OutputDebugString((LPWSTR)pNewBuffer);
              VirtualFree(pNewBuffer,0,MEM_RELEASE);
        }

  }
void TestCreateProcess(void)
{
 STARTUPINFO sInfo;
 PROCESS_INFORMATION pInfo;
 ZeroMemory( &sInfo, sizeof(sInfo) );
 sInfo.cb = sizeof(sInfo);
 sInfo.dwFlags = STARTF_USESHOWWINDOW;
 sInfo.wShowWindow = SW_SHOWNORMAL;

 ZeroMemory( &pInfo, sizeof(pInfo) );
 if( !::CreateProcess( _T("WinCpp.exe"),
 NULL,
 NULL,
 NULL,
 FALSE,
 0,
 NULL,
 NULL,
 &sInfo,
 &pInfo )
 )
 {
 const int nBufSize = 512;
 TCHAR chBuf[nBufSize];
 ZeroMemory(chBuf,nBufSize);

 wsprintf(chBuf,_T("CreateProcess failed (%d).n"), GetLastError() );
 OutputDebugString(chBuf);
 return;
 }
  WaitForSingleObject( pInfo.hProcess, INFINITE );
 CloseHandle( pInfo.hProcess );
 CloseHandle( pInfo.hThread );

}
/*
 typedef struct _MEMBLOCK
    {
        HANDLE hProc;
        unsigned char *addr;
        int size;
        unsigned char *buffer;
        struct _MEMBLOCK *next;

    } MEMBLOCK;
    MEMBLOCK* create_memblock (HANDLE hProc, MEMORY_BASIC_INFORMATION *meminfo)
    {    // used to create the membloc
        MEMBLOCK *mb = malloc(sizeof(MEMBLOCK));
        if (mb)
        {
            mb->hProc = hProc;
            mb->addr = meminfo->BaseAddress;
            mb->size = meminfo->RegionSize;
            mb->buffer = malloc(meminfo->RegionSize);
            mb->next = NULL;
        }
        return mb;
    }
    void free_memblock (MEMBLOCK *mb)
    {
        if (mb)
        {
            if (mb->buffer)
            {
                free (mb->buffer);
            }
            free (mb);
        }
    }*/
    unsigned int peek (HANDLE hProc, int data_size, unsigned int addr)
    {
    unsigned int val = 0;
    if (ReadProcessMemory (hProc, (void*)addr, &val, data_size, NULL) == 0)
    {
    printf ("peek failed\r\n");
    }
    return val;
    }
    char * getIePath()
    {
        
        char lszValue[MAX_PATH];
      // char *newValue = &lszValue + 1;
        char *strkey;
        HKEY hKey;
        LONG returnStatus;
        DWORD dwType = REG_SZ;
        DWORD dwSize = MAX_PATH;
        returnStatus = RegOpenKeyEx(HKEY_CLASSES_ROOT,TEXT("applications\\iexplore.exe\\shell\\open\\command"), 0L, KEY_READ, &hKey);
        if (returnStatus == ERROR_SUCCESS)
        {
            returnStatus = RegQueryValueExA(hKey, NULL, NULL, &dwType, (LPBYTE)&lszValue, &dwSize);
            if(returnStatus == ERROR_SUCCESS)
            {
                RegCloseKey(hKey);
                if( ( strkey=strstr(lszValue, "%1" ) ) !=NULL)
                    *(strkey=strkey-2)='\0';
                printf("iexplorer.exe path is %s", lszValue);
                // newValue was the easiest way I could find to remove the first char. I miss python
               return lszValue;
            }
            else
            {
            printf("ERROR: Registry IE Path not Found");
            }
        }
        else
        {
            printf("ERROR: Registry IE Path not Found");
        }
        RegCloseKey(hKey);
        return NULL;
    }
/*
 MEMBLOCK* create_scan ( unsigned int pid)
    {
        char path[MAX_PATH];
        MEMBLOCK *mb_list = NULL;
        MEMORY_BASIC_INFORMATION meminfo;
        unsigned char *addr = 0;
        STARTUPINFO si;
        PROCESS_INFORMATION pi;
        ZeroMemory(&si, sizeof(si));
        si.cb = sizeof(si);
        strcpy(path,getIePath());
        if(!CreateProcessA(path , NULL, NULL, NULL, FALSE, DEBUG_PROCESS, NULL, NULL, &si, &pi))
            printf("\nSorry! Broke on CreateProcess()\n\n");
        else
        {
            printf("\nDummy Process Started");
        }
        if (pi.hProcess)
        {
            while (1)
            {
                if (VirtualQueryEx(pi.hProcess, addr, &meminfo, sizeof(meminfo)) == 0)
                { // query addresses, reads all meomory including non-commited
                    break;
                }
                if (meminfo.Protect & PAGE_EXECUTE_READWRITE)
                {
                    MEMBLOCK *mb = create_memblock (pi.hProcess, &meminfo);
                    if (mb)
                    {
                        mb->next = mb_list;
                        mb_list = mb;
                    }
                }
                addr = ( unsigned char*)meminfo.BaseAddress + meminfo.RegionSize;
            }
        }
        return mb_list;
    }
    void free_scan (MEMBLOCK *mb_list)
    {
        CloseHandle(mb_list->hProc);
        while ( mb_list)
        {
            MEMBLOCK *mb = mb_list;
            mb_list = mb_list->next;
            free_memblock (mb);
        }
    }
    void dump_scan_info ( MEMBLOCK *mb_list)
    {
        MEMBLOCK *mb = mb_list;
        char *buffer = (char*) malloc(mb->size);
        while (mb)
        {
            char *buffer = (char*) malloc(mb->size);
            FILE *fp;
            char filename[15];
            sprintf(filename, "0x%08x.bin", mb->addr);
            fp=fopen(filename, "wb");
            printf ("\nSuspicious Memory Block:\nAddr: 0x%08x Size:%d\r\n", mb->addr, mb->size);
            if (ReadProcessMemory(mb->hProc,(void*)mb->addr, buffer, mb->size, NULL) != 0)
            {
                printf ("Dumping Memory at 0x%08x", mb->addr);
                fwrite(buffer,1, mb->size, fp);
                fclose(fp);
            }
            else
                printf("Error Could Not Dump Memory");
            mb = mb->next;
        }
    }*/
void testFindWindow()
{
    FindWindow(NULL,_T("Sysinternals") ); 

     if(FindWindow(NULL,_T("PEiD")))
   {
     printf("ollydbg Found \n");
   }  
    FindWindow(NULL,_T("WinDbgFrameClass"));
   if( FindWindow(NULL,_T("ollydbg")))
   {
     printf("ollydbg Found \n");
   }  
    FindWindow(NULL,_T( "dbg"));
    FindWindow(NULL,_T("WINDBG"));
    FindWindow(_T("Shell_TrayWnd"), NULL);  

}
void testLoadlib()
{
    if(LoadLibrary(_T( "VBoxHook.dll")))
   {
     printf("Sandbox Found \n");
   }  
    LoadLibrary(_T(" guard32.dll"));
    if(LoadLibrary(_T(" sbiedll.dll")))
   {
     printf("Sandbox Found \n");
   }  

    if(!LoadLibrary(_T("ntoskrnl.exe")))
    {
       printf("Sandbox Found \n");  
    }        
    //  if (hProc == NULL)  return EMULATOR_DETECTED;

}
void testCheckRemoteDebug()
{    BOOL bRes = FALSE;
    HANDLE hProcess = GetCurrentProcess();
    CheckRemoteDebuggerPresent(hProcess, &bRes);
    if (bRes)
    {
        //MessageBox(NULL, 
        //    TEXT("Oooo, Debugger Found!"),
        //    TEXT(">_<!!!"),
        //    MB_ICONWARNING);
        printf("debuger Found \n");
    }
} 
void testIsDebugPresent()
{
    if (!IsDebuggerPresent())  
        {  
         printf("debuger Found \n");
    }


}
void testAutorun()
{
TCHAR szPath[MAX_PATH];
GetModuleFileName(NULL,szPath,MAX_PATH);
HKEY newValue;
LPCWSTR test=_T("myprogram");
RegOpenKey(HKEY_CURRENT_USER,TEXT("Software\\Microsoft\\Windows\\CurrentVersion\\Run"),&newValue);
/*
//[HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Run]
[HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\RunOnce]
[HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\RunServices]
[HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\RunServicesOnce]
[HKEY_LOCAL_MACHINE\Software\Microsoft\Windows NT\CurrentVersion\Winlogon\Userinit]

[HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Run]
[HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\RunOnce]
[HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\RunServices]
[HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\RunServicesOnce]
[HKEY_CURRENT_USER\Software\Microsoft\Windows NT\CurrentVersion\Windows]
RegSetValueEx(newValue,test,0,REG_SZ,(LPBYTE)szPath,sizeof(szPath));*/
RegCloseKey(newValue);
}
void testCreateKey()
{



HKEY hKey;
    LPCTSTR sk = TEXT("SOFTWARE\\OtherTestSoftware");

    LONG openRes = RegCreateKeyEx(
            HKEY_LOCAL_MACHINE,
            sk,
            0,
            NULL,
            REG_OPTION_NON_VOLATILE,
            KEY_ALL_ACCESS,
            NULL,
            &hKey,
            NULL);

    if (openRes==ERROR_SUCCESS) {
        printf("Success creating key.\n");
    } else {
        printf("Error creating key.\n");
    }

    LPCTSTR value = TEXT("OtherTestSoftwareKey");
    LPCTSTR data =TEXT("OtherTestData");

    LONG setRes = RegSetValueEx (hKey, value, 0, REG_SZ, (LPBYTE)data, _tcslen(data)+1);

    if (setRes == ERROR_SUCCESS) {
        printf("Success writing to Registry.\n");
    } else {
        printf("Error writing to Registry.\n");
    }

    //RegDeleteKey(hKey, sk);

    LONG closeOut = RegCloseKey(hKey);

    if (closeOut == ERROR_SUCCESS) {
        printf("Success closing key.\n");
    } else {
        printf("Error closing key.\n");
    }
}
void testCreatMutex()
{

    HANDLE hMutex;
hMutex = OpenMutex(MUTEX_ALL_ACCESS, FALSE,_T( "sampleMutex"));
if(hMutex == NULL)
{
    hMutex = CreateMutex(NULL, FALSE,_T( "sampleMutex"));
}
}
void antivm_CountClipboardFormats()
{

    if (CountClipboardFormats() == 0) 
    {  
     printf("nothing in clipboard,vm detected \n");
   }
    else
    {
     printf("something in clipboard\n");
    }

}
void antivm_GetTickCount()
{
long entryTick = GetTickCount();
  if (entryTick <720500)
  {
      printf("system run less than minutes,vm detect\n");
  }
    printf("get tickcount,%d \n",entryTick);
}
void antivm_getmodulefilename()
{
LPWSTR pBuf;
//int bytes = GetModuleFileNameW(NULL, pBuf, MAX_PATH);

 TCHAR  buffer[MAX_PATH];
//  GetModuleFileName( NULL, buffer, MAX_PATH );
 //printf("my name is ,%s \n",buffer);

}
void antivm_getpos()
{

POINT point,end;
GetCursorPos(&point);
Sleep(9000);
GetCursorPos(&end);
if (point.x==end.x)

{
   printf("mouse is not moving ,vm detect \n");
}
}
void antivm_cpuid()
{
/*int eax;
int temp_1;
    __asm{
            xor eax, eax;
            cpuid
            mov temp_1,eax ;
            //cmp ecx, 0x444d4163 //* AMD CPU? *
            //jne b2not_detected
            //mov eax, 0x8fffffff/* query easter egg */
    /*        cpuid
            sub eax,temp_1;
            jecxz b2detected /* ECX value not filled */
    /*        b2not_detected: xor eax, eax; jmp b2exit
            b2detected: mov eax, 0x1
            b2exit: nop

    }

    if (eax)
        {
   printf("cpuid,vm detect \n");
    }
    */
    /*
    int CPUInfo[4]={-1};
    __asm cpuid(CPUInfo,1)
    if((CPUInfo[2]>>31)&1)
    {
      printf("cpuid check,vm detect \n");
    }
    else
    {
      printf("cpuid check,no vm detect \n");
    }
    //*/
}
void antivm_rtdsc()
{
//if (eax)
        {
   printf("rtdsc,vm detect \n");
    }

}
 /*bool KillProcess(TCHAR *pProcess)//
  { 
      HANDLE hSnapshot; 
      PROCESSENTRY32 lppe; 
      hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, NULL); 
      if (hSnapshot == NULL) 
          return false; 
     lppe.dwSize = sizeof(lppe); 
     if (!Process32First(hSnapshot, &lppe)) return false; 
     do 
     { 
         CString str;
         TRACE(lppe.szExeFile + str + _T("\n"));
         if(CString(lppe.szExeFile) == CString(pProcess)) 
         { 

             DWORD xCode; 
             HANDLE hProc; 
             hProc = OpenProcess(PROCESS_TERMINATE, false, lppe.th32ProcessID);   
             if(!GetExitCodeProcess(hProc, &xCode) ) 
             { 
                 TerminateProcess(hProc, xCode); 
             } 
         }   
     } 
     while (Process32Next(hSnapshot, &lppe)); 
     if (!CloseHandle(hSnapshot)) 
         return false; 
     return true; 
 }*/
void antivm_redpill()
{

    int flag;
      _asm
    {
     mov eax, 564d5868h ;//'VMXh'
    mov ecx, 0ah ;//get VMware version
  mov dx, 5658h ;//'VX'
 in eax, dx
 cmp ebx, 564d5868h ;//'/VMXh'
 je detected
 mov eax ,0;
detected:mov eax,1;
 mov flag,eax
    }
    if (flag==1)
       printf("redpill,vm detect \n");
    else
        printf("redpill,vm not detect \n");
}
inline int idtCheck ()
{
unsigned char m[6];
__asm sidt m;
 printf("IDTR: %2.2x %2.2x %2.2x %2.2x %2.2x %2.2x\n", m[0], m[1],
m[2], m[3], m[4], m[5]);
return (m[5]>0xd0) ? 1 : 0;
}
int gdtCheck()
{
unsigned char m[6];

__asm sgdt m;
 printf("GDTR: %2.2x %2.2x %2.2x %2.2x %2.2x %2.2x\n", m[0], m[1],
m[2], m[3], m[4], m[5]);
return (m[5]>0xd0) ? 1 : 0;
}
int ldtCheck()
{
unsigned char m[6];
__asm sldt m;
 printf("LDTR: %2.2x %2.2x %2.2x %2.2x %2.2x %2.2x\n", m[0], m[1],
m[2], m[3], m[4], m[5]);
return (m[0] != 0x00 && m[1] != 0x00) ? 1 : 0;
} 
void antivm_opcheck()
{


 if (idtCheck())
 printf("idt check,Virtual Machine detected.\n");
else
 printf("idt check.No vm detected.\n"); 
 if (gdtCheck())
 printf("gdt check,Virtual Machine detected.\n");
else
 printf("gdt check.No vm detected.\n"); 
if (ldtCheck())
 printf("ldt check,Virtual Machine detected.\n");
else
 printf("ldt check.No vm detected.\n"); 
}
int _tmain(int argc, _TCHAR* argv[])
{
    ///////////////////////////////////////////////anti vm and anti debug 
antidebug_ZwQueryInformationProcess();
//antidebug_ZwSetInformationThread();
//readpeb();
//CheckDbgPresentCloseHandle();
//ObjectListCheck()
//    KillProcess("python.exe");
gensandbox_drive_size() ;
gensandbox_drive_size2();
/////////////////////////////////////////////////////////////////////Just api test
getmodulehandle();
getusername();
//IsAdmin();
//leavingtime();
//PULONG *ulAttr;
//DisableWriteProtect(ulAttr);
checkallprocess();
SuspendProcess(773);
//DDosattack();
//////////////////////////////////////////////////Just for test ocelot sample
MemVirtual();//test VirtualAlloc
testFindWindow();
testLoadlib();
testCheckRemoteDebug();
testIsDebugPresent();
TestCreateProcess();
getIePath();//test for RegOpenKeyEx ,RegQueryValueExA
//testAutorun();
testCreateKey();
testCreatMutex();
antivm_CountClipboardFormats();
antivm_GetTickCount();
antivm_getmodulefilename();
antivm_getpos();
antivm_rtdsc();
antivm_cpuid();
antivm_redpill();
antivm_opcheck();

 //MEMBLOCK *scan = create_scan(0);
  //      if (scan)
        {
   //         dump_scan_info (scan);
    //        free_scan (scan);
        }
}
