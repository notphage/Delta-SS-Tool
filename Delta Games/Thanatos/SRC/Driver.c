#include "ntos.h"

#define KDEVICE_SHORT_NAME L"Thanatos"
#define KDEVICE_TYPE 0x9999
#define KDEVICE_NAME (L"\\Device\\" KDEVICE_SHORT_NAME)
#define KCTL_CODE(x) CTL_CODE(KDEVICE_TYPE, 0x800 + x, METHOD_NEITHER, FILE_ANY_ACCESS)

#define OPENPROCESS KCTL_CODE(50)

PDRIVER_OBJECT driver_object;
PDEVICE_OBJECT device_object;

VOID DriverUnload(__in PDRIVER_OBJECT DriverObject);
NTSTATUS CreateCall(PDEVICE_OBJECT DeviceObject, PIRP irp);
NTSTATUS CloseCall(PDEVICE_OBJECT DeviceObject, PIRP irp);

NTSTATUS open_process(_Out_ PHANDLE process_handle, _In_ ACCESS_MASK desired_access, _In_ PCLIENT_ID client_id, _In_ KPROCESSOR_MODE access_mode)
{
	NTSTATUS status;
	CLIENT_ID clientId;
	PEPROCESS process;
	PETHREAD thread;
	HANDLE processHandle;

	if (access_mode != KernelMode)
	{
		__try
		{
			ProbeForWrite(process_handle, sizeof(HANDLE), sizeof(HANDLE));
			ProbeForRead(client_id, sizeof(CLIENT_ID), sizeof(ULONG));
			clientId = *client_id;
		}
		__except (EXCEPTION_EXECUTE_HANDLER)
		{
			return GetExceptionCode();
		}
	}
	else
	{
		clientId = *client_id;
	}

	// Use the thread ID if it was specified.
	if (clientId.UniqueThread)
	{
		status = PsLookupProcessThreadByCid(&clientId, &process, &thread);

		if (NT_SUCCESS(status))
			ObDereferenceObject(thread); // We don't actually need the thread.
	}
	else
		status = PsLookupProcessByProcessId(clientId.UniqueProcess, &process);

	if (!NT_SUCCESS(status))
		return status;

	// Always open in KernelMode to skip ordinary access checks.
	status = ObOpenObjectByPointer(
		process,
		0,
		NULL,
		desired_access,
		*PsProcessType,
		KernelMode,
		&processHandle
	);

	if (NT_SUCCESS(status))
	{
		if (access_mode != KernelMode)
		{
			__try
			{
				*process_handle = processHandle;
			}
			__except (EXCEPTION_EXECUTE_HANDLER)
			{
				status = GetExceptionCode();
			}
		}
		else
			*process_handle = processHandle;
	}

	ObDereferenceObject(process);

	return status;
}

// IOCTL Call Handler function
NTSTATUS IoControl(PDEVICE_OBJECT DeviceObject, PIRP Irp)
{
	NTSTATUS status;
	PIO_STACK_LOCATION stackLocation;
	PVOID originalInput;
	ULONG inputLength;
	ULONG ioControlCode;
	KPROCESSOR_MODE accessMode;
	UCHAR capturedInput[16 * sizeof(ULONG_PTR)];
	PVOID capturedInputPointer;

	UNREFERENCED_PARAMETER(DeviceObject);

#define VERIFY_INPUT_LENGTH \
    do { \
        /* Ensure at compile time that our local buffer fits this particular call. */ \
        C_ASSERT(sizeof(*input) <= sizeof(capturedInput)); \
        \
        if (inputLength != sizeof(*input)) \
        { \
            status = STATUS_INFO_LENGTH_MISMATCH; \
            goto ControlEnd; \
        } \
} while (0)

	stackLocation = IoGetCurrentIrpStackLocation(Irp);

	originalInput = stackLocation->Parameters.DeviceIoControl.Type3InputBuffer;
	inputLength = stackLocation->Parameters.DeviceIoControl.InputBufferLength;
	ioControlCode = stackLocation->Parameters.DeviceIoControl.IoControlCode;
	accessMode = Irp->RequestorMode;

	// Make sure we actually have input if the input length is non-zero.
	if (inputLength != 0 && !originalInput)
	{
		status = STATUS_INVALID_BUFFER_SIZE;
		goto ControlEnd;
	}

	// Make sure the caller isn't giving us a huge buffer. If they are, it can't be correct because
	// we have a compile-time check that makes sure our buffer can store the arguments for all the
	// calls.
	if (inputLength > sizeof(capturedInput))
	{
		status = STATUS_INVALID_BUFFER_SIZE;
		goto ControlEnd;
	}

	// Probe and capture the input buffer.
	if (accessMode != KernelMode)
	{
		__try
		{
			ProbeForRead(originalInput, inputLength, sizeof(UCHAR));
			memcpy(capturedInput, originalInput, inputLength);
		}
		__except (EXCEPTION_EXECUTE_HANDLER)
		{
			status = GetExceptionCode();
			goto ControlEnd;
		}
	}
	else
	{
		memcpy(capturedInput, originalInput, inputLength);
	}

	capturedInputPointer = capturedInput; // avoid casting below

	switch (ioControlCode)
	{
	case OPENPROCESS:
		{
			struct
			{
				PHANDLE proc_handle;
				ACCESS_MASK desired_access;
				PCLIENT_ID client_id;
			} *input = capturedInputPointer;

			VERIFY_INPUT_LENGTH;

			status = open_process(input->proc_handle, input->desired_access, input->client_id, accessMode);
		}
		break;
	default:
		status = STATUS_INVALID_DEVICE_REQUEST;
		break;
	}

	// Complete the request
ControlEnd:
	Irp->IoStatus.Status = status;
	Irp->IoStatus.Information = 0;
	IoCompleteRequest(Irp, IO_NO_INCREMENT);

	return status;
}

NTSTATUS DriverEntry(_In_ PDRIVER_OBJECT driver_object_, _In_ PUNICODE_STRING registry_path)
{
	UNREFERENCED_PARAMETER(registry_path);

	NTSTATUS status;
	UNICODE_STRING device_name;
	PDEVICE_OBJECT tmp_device_object;

	driver_object = driver_object_;

	// Create the device.
	RtlInitUnicodeString(&device_name, KDEVICE_NAME);

	status = IoCreateDevice(
		driver_object,
		0,
		&device_name,
		FILE_DEVICE_UNKNOWN,
		FILE_DEVICE_SECURE_OPEN,
		FALSE,
		&tmp_device_object
	);

	if (!NT_SUCCESS(status))
		return status;

	device_object = tmp_device_object;

	// Set up I/O.

	driver_object->MajorFunction[IRP_MJ_CREATE] = CreateCall;
	driver_object->MajorFunction[IRP_MJ_CLOSE] = CloseCall;
	driver_object->MajorFunction[IRP_MJ_DEVICE_CONTROL] = IoControl;
	driver_object->DriverUnload = DriverUnload;

	device_object->Flags |= DO_DIRECT_IO;
	device_object->Flags &= ~DO_DEVICE_INITIALIZING;

	DbgPrintEx(0, 0, "Driver loaded\n");

	return status;
}

VOID DriverUnload(__in PDRIVER_OBJECT DriverObject)
{
	UNREFERENCED_PARAMETER(DriverObject);

	IoDeleteDevice(device_object);

	DbgPrintEx(0, 0, "Driver unloaded\n");
}

NTSTATUS CreateCall(PDEVICE_OBJECT DeviceObject, PIRP irp)
{
	UNREFERENCED_PARAMETER(DeviceObject);

	irp->IoStatus.Status = STATUS_SUCCESS;
	irp->IoStatus.Information = 0;

	IoCompleteRequest(irp, IO_NO_INCREMENT);
	return STATUS_SUCCESS;
}

NTSTATUS CloseCall(PDEVICE_OBJECT DeviceObject, PIRP irp)
{
	UNREFERENCED_PARAMETER(DeviceObject);

	irp->IoStatus.Status = STATUS_SUCCESS;
	irp->IoStatus.Information = 0;

	IoCompleteRequest(irp, IO_NO_INCREMENT);
	return STATUS_SUCCESS;
}
