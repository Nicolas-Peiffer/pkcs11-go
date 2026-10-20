/*
 * mock.c — a stand-in PKCS #11 module for the WaitForSlotEvent tests.
 *
 * SPDX-FileCopyrightText: Copyright (c) 2026 The Eclipse Foundation and pkcs11-go Authors
 * SPDX-License-Identifier: MIT
 *
 * A blocking C_WaitForSlotEvent parks until C_Finalize is called, which is how
 * the specification lets an application wake it, and then returns
 * CKR_CRYPTOKI_NOT_INITIALIZED. C_GetSlotList reports one slot while a wait is
 * parked and none otherwise, so a test can tell that the wait has started.
 */

#include <pthread.h>
#include <stddef.h>

#include "platform.h"

static pthread_mutex_t mu = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t woken = PTHREAD_COND_INITIALIZER;
static int initialized;
static int waiting;

static CK_RV Initialize(CK_VOID_PTR pInitArgs) {
	(void)pInitArgs;
	pthread_mutex_lock(&mu);
	initialized = 1;
	pthread_mutex_unlock(&mu);
	return CKR_OK;
}

static CK_RV Finalize(CK_VOID_PTR pReserved) {
	(void)pReserved;
	pthread_mutex_lock(&mu);
	initialized = 0;
	pthread_cond_broadcast(&woken);
	pthread_mutex_unlock(&mu);
	return CKR_OK;
}

static CK_RV GetSlotList(CK_BBOOL tokenPresent, CK_SLOT_ID_PTR pSlotList, CK_ULONG_PTR pulCount) {
	(void)tokenPresent;
	if (pulCount == NULL_PTR) {
		return CKR_ARGUMENTS_BAD;
	}
	pthread_mutex_lock(&mu);
	CK_ULONG n = waiting > 0 ? 1 : 0;
	pthread_mutex_unlock(&mu);
	if (pSlotList != NULL_PTR) {
		if (*pulCount < n) {
			*pulCount = n;
			return CKR_BUFFER_TOO_SMALL;
		}
		if (n > 0) {
			pSlotList[0] = 0;
		}
	}
	*pulCount = n;
	return CKR_OK;
}

static CK_RV WaitForSlotEvent(CK_FLAGS flags, CK_SLOT_ID_PTR pSlot, CK_VOID_PTR pReserved) {
	(void)pSlot;
	(void)pReserved;
	pthread_mutex_lock(&mu);
	if (!initialized) {
		pthread_mutex_unlock(&mu);
		return CKR_CRYPTOKI_NOT_INITIALIZED;
	}
	if (flags & CKF_DONT_BLOCK) {
		pthread_mutex_unlock(&mu);
		return CKR_NO_EVENT;
	}
	waiting++;
	while (initialized) {
		pthread_cond_wait(&woken, &mu);
	}
	waiting--;
	pthread_mutex_unlock(&mu);
	return CKR_CRYPTOKI_NOT_INITIALIZED;
}

static CK_FUNCTION_LIST list = {{2, 40}};

CK_RV C_GetFunctionList(CK_FUNCTION_LIST_PTR_PTR ppFunctionList) {
	if (ppFunctionList == NULL_PTR) {
		return CKR_ARGUMENTS_BAD;
	}
	list.C_Initialize = Initialize;
	list.C_Finalize = Finalize;
	list.C_GetSlotList = GetSlotList;
	list.C_WaitForSlotEvent = WaitForSlotEvent;
	*ppFunctionList = &list;
	return CKR_OK;
}
