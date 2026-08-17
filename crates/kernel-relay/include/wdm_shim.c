/* SPDX-License-Identifier: MIT */
#include <ntddk.h>

PIO_STACK_LOCATION SspGetCurrentIrpStackLocation(PIRP irp)
{
    return IoGetCurrentIrpStackLocation(irp);
}

PVOID SspGetSystemBuffer(PIRP irp)
{
    return irp->AssociatedIrp.SystemBuffer;
}

VOID SspSetIoStatusAndComplete(PIRP irp, NTSTATUS status, ULONG_PTR information)
{
    irp->IoStatus.Status = status;
    irp->IoStatus.Information = information;
    IoCompleteRequest(irp, IO_NO_INCREMENT);
}

NTSTATUS SspGetDeviceIoControl(
    PIRP irp,
    ULONG *code,
    ULONG *input_length,
    ULONG *output_length)
{
    PIO_STACK_LOCATION stack = IoGetCurrentIrpStackLocation(irp);
    if (stack == NULL || code == NULL || input_length == NULL || output_length == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    *code = stack->Parameters.DeviceIoControl.IoControlCode;
    *input_length = stack->Parameters.DeviceIoControl.InputBufferLength;
    *output_length = stack->Parameters.DeviceIoControl.OutputBufferLength;
    return STATUS_SUCCESS;
}
