/* SPDX-License-Identifier: MIT */
#include <ntddk.h>

PIO_STACK_LOCATION SspGetCurrentIrpStackLocation(PIRP irp)
{
    return IoGetCurrentIrpStackLocation(irp);
}
