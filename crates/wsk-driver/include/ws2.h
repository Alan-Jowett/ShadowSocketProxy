/* SPDX-License-Identifier: MIT */
/*
 * Checked-in kernel-mode ws2.h compatibility wrapper.
 *
 * WSK consumes the shared Winsock definitions. The desktop SDK ships those
 * definitions as ws2def.h rather than as a standalone ws2.h.
 */
#pragma once
#include <ws2def.h>
