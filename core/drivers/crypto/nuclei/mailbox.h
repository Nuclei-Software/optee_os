// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2024, Nuclei - All Rights Reserved
 */
#ifndef __NUCLEI_HSM_MAILBOX_H__
#define __NUCLEI_HSM_MAILBOX_H__

#include <string.h>
#include <stdint.h>

int8_t mailbox_avaliable_linked_num(void);
void mailbox_secure_service_host_send(uint32_t *data, uint8_t opcode, uint8_t mailbox_num);
void mailbox_secure_service_host_receive(uint32_t *data, int8_t mailbox_num);

#endif