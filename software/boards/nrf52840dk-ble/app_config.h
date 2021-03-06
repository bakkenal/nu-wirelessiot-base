// application-specific configuration
// augments the base configuration in sdk/<SDK>/config/<IC>/config/sdk_config.h

#pragma once

#define SIMPLE_BLE_ENABLED 1

#define BLE_ADVERTISING_ENABLED 1
#define NRF_BLE_CONN_PARAMS_ENABLED 1
#define NRF_BLE_GATT_ENABLED 1
#define NRF_BLE_QWR_ENABLED 1
#define BLE_ECS_ENABLED 1

#define BLE_LBS_ENABLED 1
#define BLE_NUS_ENABLED 1

#define NRF_CRYPTO_ENABLED 1
#define NRF_CRYPTO_ALLOCATOR 0

#define NRF_CRYPTO_CC310_AES_ENABLED 1
#define NRF_CRYPTO_CC310_AES_AEAD_ENABLED 1
#define NRF_CRYPTO_CC310_CHACHA_POLY_AEAD_ENABLED 1

#define NRF_CRYPTO_BACKEND_CC310_ENABLED 1
#define NRF_CRYPTO_BACKEND_CC310_RNG_ENABLED 1
#define NRF_CRYPTO_BACKEND_CC310_ECC_SECP256R1_ENABLED 1
#define NRF_CRYPTO_BACKEND_CC310_BL_ENABLED 0
#define NRF_CRYPTO_BACKEND_CC310_BL_ECC_SECP256R1_ENABLED 1
#define NRF_CRYPTO_BACKEND_CC310_BL_HASH_AUTOMATIC_RAM_BUFFER_ENABLED 0
#define NRF_CRYPTO_BACKEND_CC310_BL_HASH_AUTOMATIC_RAM_BUFFER_ENABLED 0
#define NRF_CRYPTO_BACKEND_CC310_ECC_SECP160R2_ENABLED 1
#define NRF_CRYPTO_BACKEND_CC310_ECC_SECP192R1_ENABLED 1
#define NRF_CRYPTO_BACKEND_CC310_ECC_SECP224R1_ENABLED 1
#define NRF_CRYPTO_BACKEND_CC310_ECC_SECP384R1_ENABLED 1
#define NRF_CRYPTO_BACKEND_CC310_ECC_SECP521R1_ENABLED 1
#define NRF_CRYPTO_BACKEND_CC310_ECC_SECP160K1_ENABLED 1
#define NRF_CRYPTO_BACKEND_CC310_ECC_SECP192K1_ENABLED 1
#define NRF_CRYPTO_BACKEND_CC310_ECC_SECP224K1_ENABLED 1
#define NRF_CRYPTO_BACKEND_CC310_ECC_SECP256K1_ENABLED 1
#define NRF_CRYPTO_BACKEND_CC310_ECC_CURVE25519_ENABLED 1
#define NRF_CRYPTO_BACKEND_CC310_ECC_ED25519_ENABLED 1
#define NRF_CRYPTO_BACKEND_CC310_HASH_SHA256_ENABLED 1
#define NRF_CRYPTO_BACKEND_CC310_HASH_SHA512_ENABLED 1
#define NRF_CRYPTO_BACKEND_CC310_HMAC_SHA256_ENABLED 1
#define NRF_CRYPTO_BACKEND_CC310_HMAC_SHA512_ENABLED 1
#define NRF_CRYPTO_BACKEND_CC310_BL_HASH_AUTOMATIC_RAM_BUFFER_SIZE 4096
#define NRF_CRYPTO_BACKEND_CC310_BL_INTERRUPTS_ENABLED 1
#define NRF_CRYPTO_BACKEND_CC310_ECC_SECP384R1_ENABLED 1
#define NRF_CRYPTO_BACKEND_CC310_RNG_ENABLED 1
#define NRF_CRYPTO_BACKEND_MBEDTLS_ECC_SECP256R1_ENABLED 1
#define NRF_CRYPTO_BACKEND_CC310_AES_CBC_ENABLED 1
#define NRF_CRYPTO_BACKEND_CC310_AES_CTR_ENABLED 1
#define NRF_CRYPTO_BACKEND_CC310_AES_ECB_ENABLED 1
#define NRF_CRYPTO_BACKEND_CC310_AES_CBC_MAC_ENABLED 1
#define NRF_CRYPTO_BACKEND_CC310_AES_CMAC_ENABLED 1
#define NRF_CRYPTO_BACKEND_CC310_AES_CCM_ENABLED 1
#define NRF_CRYPTO_BACKEND_CC310_AES_CCM_STAR_ENABLED 1
#define NRF_CRYPTO_BACKEND_CC310_INTERRUPTS_ENABLED 1

#define NRF_CRYPTO_RNG_STATIC_MEMORY_BUFFERS_ENABLED 1
#define NRF_CRYPTO_RNG_AUTO_INIT_ENABLED 1

#define RTC2_ENABLED 1
#define RTC_ENABLED 1

#define GPIOTE_ENABLED 1
#define GPIOTE_CONFIG_NUM_OF_LOW_POWER_EVENTS 4
#define NRFX_GPIOTE_ENABLED 1

#define NRFX_RNG_ENABLED 1
#define NRFX_RNG_CONFIG_ERROR_CORRECTION 1
#define NRFX_RNG_CONFIG_IRQ_PRIORITY 6
#define RNG_ENABLED 1
#define RNG_CONFIG_ERROR_CORRECTION 1
#define RNG_CONFIG_POOL_SIZE 64
#define RNG_CONFIG_IRQ_PRIORITY 6

#define NRFX_SAADC_ENABLED 1
#define SAADC_ENABLED 1
#define SAADC_CONFIG_LP_MODE 1

#define NRFX_SPIM_ENABLED 1
#define NRFX_SPIM1_ENABLED 1
#define NRFX_SPI_ENABLED 1
#define NRFX_SPI1_ENABLED 1
#define SPI_ENABLED 1
#define SPI1_ENABLED 1

#define APP_SDCARD_ENABLED 1

#define NRF_CLOCK_ENABLED 1
#define NRFX_CLOCK_ENABLED 1

#define NRFX_TIMER_ENABLED 1
#define NRFX_TIMER0_ENABLED 1
#define NRFX_TIMER1_ENABLED 1
#define TIMER_ENABLED 1
#define TIMER_DEFAULT_CONFIG_BIT_WIDTH 3
#define TIMER0_ENABLED 1
#define TIMER1_ENABLED 1
#define APP_TIMER_ENABLED 1
#define APP_TIMER_KEEPS_RTC_ACTIVE 1

#define NRFX_UARTE_ENABLED 1
#define NRFX_UART_ENABLED 1
#define UART_ENABLED 1
#define UART0_ENABLED 1
#define APP_UART_ENABLED 1
#define HCI_UART_TX_PIN 6
#define HCI_UART_RX_PIN 8

#define NRFX_TWIM_ENABLED 1
#define NRFX_TWI_ENABLED 1
#define TWI_ENABLED 1
#define TWI0_ENABLED 1
#define TWI0_USE_EASY_DMA 1
#define NRF_TWI_MNGR_ENABLED 1

#define APP_FIFO_ENABLED 1
#define APP_SCHEDULER_ENABLED 1

#define CRC16_ENABLED 1

#define NRF_FSTORAGE_ENABLED 1
#define FDS_ENABLED 1
#define FDS_VIRTUAL_PAGES 10
#define FDS_OP_QUEUE_SIZE 10

#define MEM_MANAGER_ENABLED 1
#define MEMORY_MANAGER_SMALL_BLOCK_COUNT 128
#define MEMORY_MANAGER_SMALL_BLOCK_SIZE 32
#define MEMORY_MANAGER_MEDIUM_BLOCK_COUNT 64
#define MEMORY_MANAGER_MEDIUM_BLOCK_SIZE 64
#define MEMORY_MANAGER_LARGE_BLOCK_COUNT 32
#define MEMORY_MANAGER_LARGE_BLOCK_SIZE 128
#define MEMORY_MANAGER_XLARGE_BLOCK_COUNT 8
#define MEMORY_MANAGER_XLARGE_BLOCK_SIZE 256
#define MEMORY_MANAGER_XXLARGE_BLOCK_COUNT 4
#define MEMORY_MANAGER_XXLARGE_BLOCK_SIZE 2048
#define MEMORY_MANAGER_XSMALL_BLOCK_COUNT 0
#define MEMORY_MANAGER_XSMALL_BLOCK_SIZE 64
#define MEMORY_MANAGER_XXSMALL_BLOCK_COUNT 0
#define MEMORY_MANAGER_XXSMALL_BLOCK_SIZE 32

#define NRF_BALLOC_ENABLED 1
#define NRF_MEMOBJ_ENABLED 1
#define NRF_QUEUE_ENABLED 1


#define NRF_QUEUE_ENABLED 1

#define NRF_PWR_MGMT_ENABLED 1
#define NRF_PWR_MGMT_CONFIG_FPU_SUPPORT_ENABLED 1

#define RETARGET_ENABLED 0

#define BUTTON_ENABLED 1

#define NRFX_PWM_ENABLED 1
#define NRFX_PWM0_ENABLED 1
#define NRFX_PWM1_ENABLED 1
#define NRFX_PWM2_ENABLED 1
#define PWM_ENABLED 1
#define PWM0_ENABLED 1
#define PWM1_ENABLED 1
#define PWM2_ENABLED 1
#define APP_PWM_ENABLED 1
#define LOW_POWER_PWM_ENABLED 1
#define NRFX_PPI_ENABLED 1
#define PPI_ENABLED 1

#define NRF_SECTION_ITER_ENABLED 1

#define NRF_LOG_ENABLED 1
#define NRF_LOG_BACKEND_UART_ENABLED 0
#define NRF_LOG_BACKEND_RTT_ENABLED 1
#define NRF_LOG_USES_RTT 1
#define NRF_LOG_DEFERRED 0
#define NRF_LOG_STR_PUSH_BUFFER_SIZE 128

#define HARDFAULT_HANDLER_ENABLED 1
#define HARDFAULT_HANDLER_GDB_PSP_BACKTRACE 0

#define NRF_SERIAL_ENABLED 1

#define NRF_SDH_ENABLED 1
#define NRF_SDH_BLE_ENABLED 1
#define NRF_SDH_BLE_GAP_DATA_LENGTH 251
#define NRF_SDH_BLE_PERIPHERAL_LINK_COUNT 1
#define NRF_SDH_BLE_GATT_MAX_MTU_SIZE 247
#define NRF_SDH_BLE_VS_UUID_COUNT 10
#define NRF_SDH_SOC_ENABLED 1
