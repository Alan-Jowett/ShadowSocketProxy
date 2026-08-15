/* SPDX-License-Identifier: MIT */
/*
 * Narrow bindgen root for the WSK ABI. WDM entry points remain supplied by
 * the wdk/WDK-sys crates; this wrapper is only for WSK types and dispatches.
 */
#pragma once

#include <ntddk.h>
#include <ws2def.h>
#include <ws2ipdef.h>
#include <wsk.h>
