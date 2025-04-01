// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2024, Nuclei - All Rights Reserved
 */
#include "nuclei_hsm_abi.h"
#include "mailbox.h"
#include <util.h>

#define debug(...) do{}while(0)

#define MAILBOX_BASE_ADDR_OFFSET                    0x2000
#define MAILBOX_AVALIABLE_MAX_NUM                   1
#define MAILBOX_SIZE_IN_BYTE                        256
#define TIMEOUT_CYCLE                               0x1fffffff

#define MAILBOX_RF_OPT_ACTIVE_HOST_N_OFS            6
#define MAILBOX_RF_OPT_ACTIVE_HOST_N                GENMASK_32(7,6)
#define MAILBOX_RF_OPT_MASTER_ID_OFS                12
#define MAILBOX_RF_OPT_MASTER_ID                    BIT(12)
#define MAILBOX_RF_OPT_MY_ID_OFS                    18
#define MAILBOX_RF_OPT_MY_ID                        BIT(18)

#define MAILBOX_RF_CSR_MBX0_IN_FULL                 BIT(0)
#define MAILBOX_RF_CSR_MBX0_OUT_FULL                BIT(1)
#define MAILBOX_RF_CSR_MBX0_LINK                    BIT(2)
#define MAILBOX_RF_CSR_MBX0_UNLINK                  BIT(3)
#define MAILBOX_RF_CSR_MBX0_UNLINK_AVAILABLE        BIT(3)

#define MAILBOX_RF_LINKID0_MBX0_LINK_ID             BIT(0)
#define MAILBOX_RF_LINKID0_OFFSET                   0x10
#define MAILBOX_RF_LOCKOUT0_OFFSET                  0x18

#define MAILBOX_RF_RESET_MBX0_OUT_EMPTY             BIT(1)
#define MAILBOX_RF_RESET_MBX0_UNLINK                BIT(3)

#define MAILBOX_LOCKOUT_REG(HANDLE, NUM)    (*(uint32_t *)((size_t)(HANDLE) + MAILBOX_RF_LOCKOUT0_OFFSET + (0x04*(NUM))))
#define MAILBOX_LINKID_REG(HANDLE, NUM)     (*(uint32_t *)((size_t)(HANDLE) + MAILBOX_RF_LINKID0_OFFSET + (0x04*(NUM))))

typedef struct {  /*!< MAILBOX Structure */
    volatile uint32_t  IP_VER;                                   /*!< Offset: 0x0 RW IP VER Register */
    volatile uint32_t  GIT_VER;                                  /*!< Offset: 0x4 RW GIT VER Register */
    volatile uint32_t  CSR;                                      /*!< Offset: 0x8 RW CSR Register */
    volatile uint32_t  RESET;                                    /*!< Offset: 0xc RW RESET Register */
    volatile uint32_t  LINKID0;                                  /*!< Offset: 0x10 RW LINKID0 Register */
    volatile uint32_t  LINKID1;                                  /*!< Offset: 0x14 RW LINKID1 Register */
    volatile uint32_t  LOCKOUT0;                                 /*!< Offset: 0x18 RW LOCKOUT0 Register */
    volatile uint32_t  LOCKOUT1;                                 /*!< Offset: 0x1C RW LOCKOUT1 Register */
    volatile uint32_t  LOCKOUT2;                                 /*!< Offset: 0x20 RW LOCKOUT2 Register */
    volatile uint32_t  LOCKOUT3;                                 /*!< Offset: 0x24 RW LOCKOUT3 Register */
    volatile uint32_t  LOCKOUT4;                                 /*!< Offset: 0x28 RW LOCKOUT4 Register */
    volatile uint32_t  LOCKOUT5;                                 /*!< Offset: 0x2C RW LOCKOUT5 Register */
    volatile uint32_t  LOCKOUT6;                                 /*!< Offset: 0x30 RW LOCKOUT6 Register */
    volatile uint32_t  LOCKOUT7;                                 /*!< Offset: 0x34 RW LOCKOUT7 Register */
    volatile uint32_t  INTEN;                                    /*!< Offset: 0x38 RW INTEN Register */
    volatile uint32_t  INTST;                                    /*!< Offset: 0x3c RW INTST Register */
    volatile uint32_t  RESERVECD16[7];                           /*!< Offset: 0x40 RO RESERVECD16[7] Register */
    volatile uint32_t  OPT;                                      /*!< Offset: 0x5c RW OPT Register */
} MAILBOX_TypeDef;



extern void* mailbox_base;

typedef enum {
    DISABLE = 0,
    ENABLE = !DISABLE
} EventStatus, ControlStatus, FunctionalState;

typedef enum {
    RESET = 0,
    SET = 1,
    MAX = 0X7FFFFFFF
} FlagStatus;

typedef enum {
    ERROR = 0,
    SUCCESS = !ERROR
} ErrStatus;

static __attribute__((unused)) uint32_t MAILBOX_GetIpVersion(MAILBOX_TypeDef* mailbox)
{
    return mailbox->IP_VER;
}

static __attribute__((unused)) uint32_t MAILBOX_GetGitVersion(MAILBOX_TypeDef* mailbox)
{
    return mailbox->GIT_VER;
}

static uint8_t MAILBOX_GetMasterId(MAILBOX_TypeDef* mailbox)
{
    uint32_t temp = 0;

    temp = mailbox->OPT & MAILBOX_RF_OPT_MASTER_ID;
    /* Return the master ID */
    return (temp >> MAILBOX_RF_OPT_MASTER_ID_OFS);
}

static FlagStatus MAILBOX_GetMbxOutFullStatus(MAILBOX_TypeDef* mailbox, uint8_t mbx_num)
{
    FlagStatus bitstatus = RESET;

    if ((mailbox->CSR & (MAILBOX_RF_CSR_MBX0_OUT_FULL << (4 * mbx_num))) != RESET) {
        /* output mailbox is full */
        bitstatus = SET;
    } else {
        /* output mailbox is not full */
        bitstatus = RESET;
    }

    /* Return the output mailbox full status */
    return bitstatus;
}

static uint8_t MAILBOX_GetMbxLinkedId(MAILBOX_TypeDef* mailbox, uint8_t mbx_num)
{
    uint32_t temp = 0;
    uint32_t offset = 0;

    offset = (8 * (mbx_num % 4));
    temp = MAILBOX_RF_LINKID0_MBX0_LINK_ID << offset;
    temp &= MAILBOX_LINKID_REG(mailbox, mbx_num/4);
    /* Return the host ID */
    return (temp >> offset);
}

static uint8_t MAILBOX_GetHostId(MAILBOX_TypeDef* mailbox)
{
    uint32_t temp = 0;

    temp = mailbox->OPT & MAILBOX_RF_OPT_MY_ID;
    /* Return the host ID */
    return (temp >> MAILBOX_RF_OPT_MY_ID_OFS);
}

static __attribute__((unused)) uint8_t MAILBOX_GetActivedHostNum(MAILBOX_TypeDef* mailbox)
{
    uint32_t temp = 0;

    temp = mailbox->OPT & MAILBOX_RF_OPT_ACTIVE_HOST_N;
    /* Return the number of actived host */
    return (temp >> MAILBOX_RF_OPT_ACTIVE_HOST_N_OFS);
}



/**
  * \brief  Return the status about which host is blocked from accessing specified mailbox.
  *
  * \param  mailbox the struct of MAILBOX peripheral
  * \param  host_id host id
  * \param  mbx_num the number of mailbox, range from 0 to (MAILBOX_AVALIABLE_MAX_NUM - 1)
  * \param  NewState lock or unlock the mailbox for host.
  *
  * \retval SET the host has right to access the specified mailbox
  * \retval RESET the host has not right to access the specified mailbox
  */
static FlagStatus MAILBOX_GetUnlockStatus(MAILBOX_TypeDef* mailbox, uint8_t host_id, uint8_t mbx_num)
{
    uint32_t temp = 0;
    temp = MAILBOX_LOCKOUT_REG(mailbox, mbx_num);
    if (temp & (BIT(0) << host_id)) {
        return RESET;
    } else {
        return SET;
    }
}

/**
  * \brief  Enable or disable which host is blocked from accessing specified mailbox.
  *
  * \param  mailbox the struct of MAILBOX peripheral
  * \param  host_id host id
  * \param  mbx_num the number of mailbox, range from 0 to (MAILBOX_AVALIABLE_MAX_NUM - 1)
  * \param  NewState lock or unlock the mailbox for host.
  *           \arg ENABLE: The host is blocked from accessing specified mailbox.
  *           \arg DISABLE: The host can link to the specified mailbox.
  */
static void MAILBOX_LockOutCtrl(MAILBOX_TypeDef* mailbox, uint8_t host_id, uint8_t mbx_num, FunctionalState NewState)
{
    uint32_t temp = 0;
    temp = MAILBOX_LOCKOUT_REG(mailbox, mbx_num);
    if (NewState != DISABLE) {
        temp |= (BIT(0) << host_id);
    } else {
        temp &= ~(BIT(0) << host_id);
    }
    switch (mbx_num) {
        case 0:
            mailbox->LOCKOUT0 = temp;
            break;
        default :
            break;
    }
}

/**
  * \brief  To link the specified mailbox.
  *
  * \param  mailbox the struct of MAILBOX peripheral
  * \param  mbx_num the number of mailbox, range from 0 to (MAILBOX_AVALIABLE_MAX_NUM - 1)
  */
static void MAILBOX_MbxLink(MAILBOX_TypeDef* mailbox, uint8_t mbx_num)
{
    mailbox->CSR |= (MAILBOX_RF_CSR_MBX0_LINK << (4 * mbx_num));
}

/**
  * \brief  Checks whether the specified mailbox has linked.
  *
  * \param  mailbox the struct of MAILBOX peripheral
  * \param  mbx_num the number of mailbox, range from 0 to (MAILBOX_AVALIABLE_MAX_NUM - 1)
  *
  * \retval SET The specified mailbox has linked
  * \retval RESET The specified mailbox has not linked
  */
static FlagStatus MAILBOX_GetMbxLinkStatus(MAILBOX_TypeDef* mailbox, uint8_t mbx_num)
{
    FlagStatus bitstatus = RESET;

    if ((mailbox->CSR & (MAILBOX_RF_CSR_MBX0_LINK << (4 * mbx_num))) != RESET) {
        /* mailbox is linked */
        bitstatus = SET;
    } else {
        /* mailbox is unlinked */
        bitstatus = RESET;
    }

    /* Return the mailbox link status */
    return bitstatus;
}

/**
  * \brief  Return the number of mailbox that is linked to link
  *
  * \param  mailbox the struct of MAILBOX peripheral
  *
  * \return mailbox number that is avaliable to link
  */
static uint8_t __attribute__((unused)) MAILBOX_GetLinkedMbxNum(MAILBOX_TypeDef* mailbox)
{
    for (int i = 0; i < MAILBOX_AVALIABLE_MAX_NUM; i++) {
        if (MAILBOX_GetMbxLinkStatus(mailbox, i) == SET) {
            return i;
        }
    }

    return -1;
}

/**
  * \brief  To unlink the specified mailbox.
  *
  * \param  mailbox the struct of MAILBOX peripheral
  * \param  mbx_num the number of mailbox, range from 0 to (MAILBOX_AVALIABLE_MAX_NUM - 1)
  */
static void MAILBOX_HostUnlinkMbx(MAILBOX_TypeDef* mailbox, uint8_t mbx_num)
{
    mailbox->CSR |= (MAILBOX_RF_CSR_MBX0_UNLINK << (4 * mbx_num));
}

/**
  * \brief  Checks whether the specified mailbox is avaliable to link.
  *
  * \param  mailbox the struct of MAILBOX peripheral
  * \param  mbx_num the number of mailbox, range from 0 to (MAILBOX_AVALIABLE_MAX_NUM - 1)
  *
  * \retval SET The specified mailbox can link to
  * \retval RESET The specified mailbox can not link to
  */
static FlagStatus MAILBOX_GetMbxUnlinkAlbStatus(MAILBOX_TypeDef* mailbox, uint8_t mbx_num)
{
    FlagStatus bitstatus = RESET;

    if ((mailbox->CSR & (MAILBOX_RF_CSR_MBX0_UNLINK_AVAILABLE << (4 * mbx_num))) != RESET) {
        /* mailbox is avaliable to link */
        bitstatus = SET;
    } else {
        /* mailbox is not avaliable to link */
        bitstatus = RESET;
    }

    /* Return the mailbox available to link status */
    return bitstatus;
}

/**
  * \brief  Return the number of mailbox that is avaliable to link
  *
  * \param  mailbox the struct of MAILBOX peripheral
  *
  * \return mailbox number that is avaliable to link
  */
static uint8_t MAILBOX_GetAlbToLinkMbxNum(MAILBOX_TypeDef* mailbox)
{
    for (int i = 0; i < MAILBOX_AVALIABLE_MAX_NUM; i++) {
        if (MAILBOX_GetMbxUnlinkAlbStatus(mailbox, i) == SET) {
            return i;
        }
    }

    return -1;
}
/**
  * \brief  To unlink the specified mailbox.
  *
  * \note   Only master host can unlink the mailbox.
  *
  * \param  mailbox the struct of MAILBOX peripheral
  * \param  mbx_num the number of mailbox, range from 0 to (MAILBOX_AVALIABLE_MAX_NUM - 1)
  */
static void __attribute__((unused)) MAILBOX_MastHostUnlinkMbx(MAILBOX_TypeDef* mailbox, uint8_t mbx_num)
{
    mailbox->RESET |= (MAILBOX_RF_RESET_MBX0_UNLINK << (4 * mbx_num));
}

/**
  * \brief  Set mbx_in_full bit in CSR register to 1.
  *
  * \note   After finish to write to mailbox in, means setting full status, or finish to read means clearing full status.
  *
  * \param  mailbox the struct of MAILBOX peripheral
  * \param  mbx_num the number of mailbox, range from 0 to (MAILBOX_AVALIABLE_MAX_NUM - 1)
  */
static void MAILBOX_SetMbxInFull(MAILBOX_TypeDef* mailbox, uint8_t mbx_num)
{
    mailbox->CSR |= (MAILBOX_RF_CSR_MBX0_IN_FULL << (4 * mbx_num));
}

/**
  * \brief  Set mbx_out_full bit in CSR register to 1.
  *
  * \note   After finish to write to mailbox out, means setting full status, or finish to read means clearing full status.
  *
  * \param  mailbox the struct of MAILBOX peripheral
  * \param  mbx_num the number of mailbox, range from 0 to (MAILBOX_AVALIABLE_MAX_NUM - 1)
  */
static void MAILBOX_SetMbxOutFull(MAILBOX_TypeDef* mailbox, uint8_t mbx_num)
{
    mailbox->CSR |= (MAILBOX_RF_CSR_MBX0_OUT_FULL << (4 * mbx_num));
}

/**
  * \brief  Checks whether the specified input mailbox is full.
  *
  * \param  mailbox the struct of MAILBOX peripheral
  * \param  mbx_num the number of mailbox, range from 0 to (MAILBOX_AVALIABLE_MAX_NUM - 1)
  *
  * \retval SET The specified input mailbox is full
  * \retval RESET The specified input mailbox is not full
  */
static FlagStatus MAILBOX_GetMbxInFullStatus(MAILBOX_TypeDef* mailbox, uint8_t mbx_num)
{
    FlagStatus bitstatus = RESET;

    if ((mailbox->CSR & (MAILBOX_RF_CSR_MBX0_IN_FULL << (4 * mbx_num))) != RESET) {
        /* input mailbox is full */
        bitstatus = SET;
    } else {
        /* input mailbox is not full */
        bitstatus = RESET;
    }

    /* Return the input mailbox full status */
    return bitstatus;
}

/**
  * \brief  Clear output mailbox full status
  *
  * \note   Only master host can clear it.
  *
  * \param  mailbox the struct of MAILBOX peripheral
  * \param  mbx_num the number of mailbox, range from 0 to (MAILBOX_AVALIABLE_MAX_NUM - 1)
  */
static __attribute__((unused)) void MAILBOX_MasterHostClearMbxOutFull(MAILBOX_TypeDef* mailbox, uint8_t mbx_num)
{
    mailbox->RESET |= (MAILBOX_RF_RESET_MBX0_OUT_EMPTY << (4 * mbx_num));
}

static ErrStatus MAILBOX_HostLinkToMbx(MAILBOX_TypeDef* mailbox, uint8_t mbx_num)
{
    uint8_t host_id = 0, master_id = 0;

    master_id = MAILBOX_GetMasterId(mailbox);
    host_id = MAILBOX_GetHostId(mailbox);

    if (master_id == host_id) {
        /* unlock, ensure has right to access */
        MAILBOX_LockOutCtrl(mailbox, host_id, mbx_num, DISABLE);
    } else {
        /* check whether has unlocked for accessing the specified mailbox */
        if (MAILBOX_GetUnlockStatus(mailbox, host_id, mbx_num) == RESET) {
            return ERROR;
        }
    }

    /* Check the specified mailbox whether is avaliable to link */
    if (RESET == MAILBOX_GetMbxUnlinkAlbStatus(mailbox, mbx_num)) {
        return ERROR;
    }

    /* Set to link */
    MAILBOX_MbxLink(mailbox, mbx_num);
    /* Ensure whether has linked */
    if (RESET == MAILBOX_GetMbxLinkStatus(mailbox, mbx_num)) {
        return ERROR;
    } else if (host_id != MAILBOX_GetMbxLinkedId(mailbox, mbx_num)) {
        return ERROR;
    } else {
        return SUCCESS;
    }
}

/**
  * \brief  Host writes data to input mailbox.
  *
  * \param  mailbox the struct of MAILBOX peripheral
  * \param  mbx_num the number of mailbox, range from 0 to (MAILBOX_AVALIABLE_MAX_NUM - 1)
  * \param  addr point to the input mailbox start address
  * \param  buf point to the buffer address
  * \param  len the length of word data
  */
static void MAILBOX_HostWriteDataToMailboxIn(MAILBOX_TypeDef* mailbox, uint8_t mbx_num, uint32_t *addr, uint32_t *buf, uint8_t len)
{
    uint8_t i = 0;

    /* Write data to input mailbox*/
    for (i = 0; i < len; i++) {
        addr[i] = buf[i];
    }
	asm volatile ("fence");
    /* Write 1 to set status */
    MAILBOX_SetMbxInFull(mailbox, mbx_num);
	asm volatile ("fence");
}

/**
  * \brief  Host read data from output mailbox.
  *
  * \param  mailbox the struct of MAILBOX peripheral
  * \param  mbx_num the number of mailbox, range from 0 to (MAILBOX_AVALIABLE_MAX_NUM - 1)
  * \param  addr point to the output mailbox start address
  * \param  buf point to the buffer address
  * \param  len the length of word data
  */
static void MAILBOX_HostReadDataFromMailboxOut(MAILBOX_TypeDef* mailbox, uint8_t mbx_num, uint32_t *addr, uint32_t *buf, uint8_t len)
{
    uint8_t i = 0;

    /* Write data to input mailbox*/
    for (i = 0; i < len; i++) {
        buf[i] = addr[i];
    }
    /* Write 1 to clear */
    MAILBOX_SetMbxOutFull(mailbox, mbx_num);
}

static uint8_t CheckMailboxInNotFullStatus(MAILBOX_TypeDef* pMailbox, uint8_t mbx_num, uint32_t timeout)
{
    uint32_t cnt = 0;
    while ((MAILBOX_GetMbxInFullStatus(pMailbox, mbx_num) == SET) && (cnt++ < timeout));
    if (cnt >= timeout) {
        return 0;
    }
    return 1;
}

static uint8_t CheckMailboxOutFullStatus(MAILBOX_TypeDef* pMailbox, uint8_t mbx_num, uint32_t timeout)
{
    uint32_t cnt = 0;
    while ((MAILBOX_GetMbxOutFullStatus(pMailbox, mbx_num) == RESET) && (cnt++ < timeout));
    if (cnt >= timeout) {
        return 0;
    }
    return 1;
}

static uint8_t CheckMailboxOutFreeStatus(MAILBOX_TypeDef* pMailbox, uint8_t mbx_num, uint32_t timeout)
{
    uint32_t cnt = 0;
    while ((MAILBOX_GetMbxOutFullStatus(pMailbox, mbx_num) == SET) && (cnt++ < timeout));
    if (cnt >= timeout) {
        return 0;
    }
    return 1;
}

/**
  * \brief  Get the avaliable linked mailbox number.
  *
  * \retval  -1 has no avaliable linked mailbox
  * \retval others the avaliable linked mailbox number.
  */
int8_t mailbox_avaliable_linked_num(void)
{
    int8_t mailbox_num = -1;
    /* Get mailbox number that is avaliable to link */
    mailbox_num = MAILBOX_GetAlbToLinkMbxNum(mailbox_base);
    if (-1 == mailbox_num) {
        debug(">>>>>>>>>>host has no unlinked mailbox!<<<<<<<<<<\r\n");
        return -1;
    }
    return mailbox_num;
}

/**
  * \brief  Send secure service command using the specified mailbox.
  *
  * \param  data point to send buf, according the opcode to chose
  *     \arg the address of acryp_in_token_t struct variable
  *     \arg the address of mailbox_cryp_cmd_in_token struct variable
  *     \arg the address of boot_in_token_t struct variable
  *     \arg the address of mailbox_hash_cmd_in_token struct variable
  *     \arg the address of efuse_in_token_t struct variable
  * \param  opcode select the secure service items
  *     \arg SECURE_SERVICE_OPCODE_HASH: hash
  *     \arg SECURE_SERVICE_OPCODE_CRYP: cryp
  *     \arg SECURE_SERVICE_OPCODE_ACRYP: acryp
  *     \arg SECURE_SERVICE_OPCODE_EFUSE: efuse
  *     \arg SECURE_SERVICE_OPCODE_BOOT: boot firmware
  * \param  mailbox_num mailbox number
  */
void mailbox_secure_service_host_send(uint32_t *data, uint8_t opcode, uint8_t mailbox_num)
{
    uint32_t wBuf[60] = {0};
    uint32_t mailbox_addr = 0;

    mailbox_addr = ((uint32_t)(size_t)mailbox_base + MAILBOX_BASE_ADDR_OFFSET + mailbox_num*MAILBOX_SIZE_IN_BYTE);

    /* Link to mailbox */
    if (ERROR == MAILBOX_HostLinkToMbx(mailbox_base, mailbox_num)) {
        debug(">>>>>>>>>>host link to mailbox fail!<<<<<<<<<<\r\n");
        return;
    }

    switch (opcode) {
        case SECURE_SERVICE_OPCODE_HASH:
            memcpy(wBuf, data, sizeof(mailbox_hash_cmd_in_token));
            break;
        case SECURE_SERVICE_OPCODE_CRYP:
            memcpy(wBuf, data, sizeof(mailbox_cryp_cmd_in_token));
            break;
        case SECURE_SERVICE_OPCODE_ACRYP:
            memcpy(wBuf, data, sizeof(acryp_in_token_t));
            break;
        default:
            break;
    }

    /* Write command to mailbox */
    MAILBOX_HostWriteDataToMailboxIn(mailbox_base, mailbox_num, (uint32_t *)(size_t)(mailbox_addr), wBuf, 60);
    if (0 == CheckMailboxInNotFullStatus(mailbox_base, mailbox_num, TIMEOUT_CYCLE)) {
        debug(">>>>>>>>>>wait kernel to read command out timeout!<<<<<<<<<<\r\n");
        return;
    }
    debug("Host write done!\r\n");
}

/**
  * \brief  Receive secure service back-command using the specified mailbox.
  *
  * \param  data point to receive buf, the detail reference to communication protocol
  * \param  mailbox_num mailbox number
  */
void mailbox_secure_service_host_receive(uint32_t *data, int8_t mailbox_num)
{
    uint32_t mailbox_addr = 0;

    mailbox_addr = ((uint32_t)(size_t)mailbox_base + MAILBOX_BASE_ADDR_OFFSET + mailbox_num*MAILBOX_SIZE_IN_BYTE);

    /* host read from mailbox */
    if (0 == CheckMailboxOutFullStatus(mailbox_base, mailbox_num, TIMEOUT_CYCLE)) {
        debug(">>>>>>>>>>wait kernel to write command timeout!<<<<<<<<<<\r\n");
        return;
    }
    MAILBOX_HostReadDataFromMailboxOut(mailbox_base, mailbox_num, (uint32_t *)(size_t)(mailbox_addr), data, 32);
    if (0 == CheckMailboxOutFreeStatus(mailbox_base, mailbox_num, TIMEOUT_CYCLE)) {
        debug(">>>>>>>>>>host read command fail!<<<<<<<<<<\r\n");
        return;
    }
    /* unlink mailbox */
    MAILBOX_HostUnlinkMbx(mailbox_base, mailbox_num);
    while (MAILBOX_GetMbxLinkStatus(mailbox_base, mailbox_num) == SET);
}
