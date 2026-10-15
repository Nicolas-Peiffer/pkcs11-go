/*
 * mock.c — a stand-in PKCS #11 module for the interface-negotiation tests.
 *
 * SPDX-FileCopyrightText: Copyright (c) 2026 The Eclipse Foundation and pkcs11-go Authors
 * SPDX-License-Identifier: MIT
 *
 * It implements only what loading needs, C_GetFunctionList and
 * C_GetInterface; every function-list entry is NULL. The interfaces it offers
 * depend on how it is compiled:
 *
 *   (default)        default interface 3.0, version 3.2 available on request
 *   MOCK_DEFAULT_32  default interface 3.2, lookups by version refused
 *   MOCK_ONLY_30     a 3.0 interface only
 */

#include <string.h>

#include "platform.h"

static CK_FUNCTION_LIST list20 = {{2, 40}};
static CK_FUNCTION_LIST_3_0 list30 = {{3, 0}};
static CK_FUNCTION_LIST_3_2 list32 = {{3, 2}};

static CK_INTERFACE iface30 = {(CK_CHAR_PTR) "PKCS 11", &list30, 0};
static CK_INTERFACE iface32 = {(CK_CHAR_PTR) "PKCS 11", &list32, 0};

CK_RV C_GetFunctionList(CK_FUNCTION_LIST_PTR_PTR ppFunctionList) {
	if (ppFunctionList == NULL_PTR) {
		return CKR_ARGUMENTS_BAD;
	}
	*ppFunctionList = &list20;
	return CKR_OK;
}

static int is_version(CK_VERSION_PTR v, CK_BYTE major, CK_BYTE minor) {
	return v->major == major && v->minor == minor;
}

CK_RV C_GetInterface(CK_UTF8CHAR_PTR pInterfaceName, CK_VERSION_PTR pVersion,
                     CK_INTERFACE_PTR_PTR ppInterface, CK_FLAGS flags) {
	(void)flags;
	if (ppInterface == NULL_PTR) {
		return CKR_ARGUMENTS_BAD;
	}
	if (pInterfaceName != NULL_PTR && strcmp((const char *)pInterfaceName, "PKCS 11") != 0) {
		return CKR_ARGUMENTS_BAD;
	}
#if defined(MOCK_DEFAULT_32)
	if (pVersion != NULL_PTR) {
		return CKR_ARGUMENTS_BAD;
	}
	*ppInterface = &iface32;
#elif defined(MOCK_ONLY_30)
	if (pVersion != NULL_PTR && !is_version(pVersion, 3, 0)) {
		return CKR_ARGUMENTS_BAD;
	}
	*ppInterface = &iface30;
#else
	if (pVersion == NULL_PTR || is_version(pVersion, 3, 0)) {
		*ppInterface = &iface30;
	} else if (is_version(pVersion, 3, 2)) {
		*ppInterface = &iface32;
	} else {
		return CKR_ARGUMENTS_BAD;
	}
#endif
	return CKR_OK;
}
