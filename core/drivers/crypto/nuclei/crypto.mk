# CFG_NUCLEI_HSM_CRYPTO_DRIVER, when enabled, embeds
#       NUCLEI_HSM HW cryptographic support and OP-TEE Crypto Driver.
# CFG_NUCLEI_HSM_CRYP, when enabled, embeds
#       NUCLEI_HSM CRYP module support,
#       CIPHER Crypto Driver,
#       AUTHENC Crypto Driver.

ifeq ($(CFG_NUCLEI_HSM_CRYPTO),y)

$(call force,CFG_CRYPTO_DRIVER,y)
CFG_CRYPTO_DRIVER_DEBUG ?= 0

endif # CFG_NUCLEI_HSM_CRYPTO_DRIVER
