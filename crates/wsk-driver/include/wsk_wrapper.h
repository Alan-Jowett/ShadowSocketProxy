/* SPDX-License-Identifier: MIT */
/*
 * Bindgen root for the WSK driver boundary. Keep this wrapper checked in so
 * the generated ABI is tied to the reviewed header set.
 */
#pragma once

#include <ntddk.h>
#include "ws2.h"
#include <wsk.h>
