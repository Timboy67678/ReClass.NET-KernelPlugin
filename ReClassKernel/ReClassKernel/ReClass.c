#include "ReClass.h"
#include "Dispatch.h"

PDEVICE_OBJECT ReClassDeviceObject = NULL;

NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath);
void ReClassUnload(PDRIVER_OBJECT DriverObject);
NTSTATUS ReClassHandleMajorFunction(PDEVICE_OBJECT DeviceObject, PIRP Irp);

#pragma alloc_text(INIT, DriverEntry)
#pragma alloc_text(PAGE, ReClassHandleMajorFunction)

void ReClassUnload(PDRIVER_OBJECT DriverObject)
{
	DPRINT("Driver unloaded");
	UNICODE_STRING dosLinkName = RECLASS_DOS_NAME;
	IoDeleteSymbolicLink(&dosLinkName);
	IoDeleteDevice(DriverObject->DeviceObject);
}

NTSTATUS ReClassHandleMajorFunction(PDEVICE_OBJECT DeviceObject, PIRP Irp)
{
	NTSTATUS status = STATUS_SUCCESS;
	BOOLEAN kernelModeRequest = Irp->RequestorMode == KernelMode;
	PIO_STACK_LOCATION ioStackLocation = IoGetCurrentIrpStackLocation(Irp);
	PVOID controlBuffer = Irp->AssociatedIrp.SystemBuffer;
	HANDLE callerProcessId = PsGetCurrentProcessId();

	if (ioStackLocation->MajorFunction == IRP_MJ_DEVICE_CONTROL)
	{
		ULONG ioctlCode = ioStackLocation->Parameters.DeviceIoControl.IoControlCode;
		ULONG inBufferSize = ioStackLocation->Parameters.DeviceIoControl.InputBufferLength;
		ULONG outBufferSize = ioStackLocation->Parameters.DeviceIoControl.OutputBufferLength;

		if (NT_SUCCESS(status = ReClassHandleDispatch(callerProcessId, ioctlCode, controlBuffer, inBufferSize, outBufferSize, kernelModeRequest)) && outBufferSize > 0)
			Irp->IoStatus.Information = outBufferSize;
	}

	Irp->IoStatus.Status = status;
	IoCompleteRequest(Irp, IO_NO_INCREMENT);
	return status;
}

NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath)
{
	UNREFERENCED_PARAMETER(RegistryPath);

	NTSTATUS status;
	UNICODE_STRING deviceName = RECLASS_DEVICE_NAME;
	UNICODE_STRING dosLinkName = RECLASS_DOS_NAME;

	DriverObject->DriverUnload = ReClassUnload;

	DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = ReClassHandleMajorFunction;
	DriverObject->MajorFunction[IRP_MJ_CREATE] = ReClassHandleMajorFunction;
	DriverObject->MajorFunction[IRP_MJ_CLOSE] = ReClassHandleMajorFunction;

	if (NT_SUCCESS(status = IoCreateDevice(DriverObject, 0, &deviceName, RECLASS_FILE_DEVICE_ID, 0, FALSE, &ReClassDeviceObject)))
		status = IoCreateSymbolicLink(&dosLinkName, &deviceName);

	if (NT_SUCCESS(status)) {
		DPRINT("Driver loaded");
		ClearFlag(ReClassDeviceObject->Flags, DO_DEVICE_INITIALIZING);
		SetFlag(ReClassDeviceObject->Flags, DO_BUFFERED_IO);
	} else DPRINT("Driver load failed: %X", status);

	return status;
}
