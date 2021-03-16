// BLE Advertisement Raw app
//
// Sends a BLE advertisement with raw bytes

#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>

#include "simple_ble.h"

#include "nrf52840dk.h"

#include "nrf.h"
#include "nrf_drv_clock.h"
#include "nrf_delay.h"

#include "nrf_drv_power.h"

#include "app_error.h"
#include "app_util.h"

#include "nrf_log.h"
#include "nrf_log_ctrl.h"
#include "nrf_log_default_backends.h"

#include "boards.h"

#include "nrf_crypto.h"
#include "nrf_crypto_error.h"
#include "mem_manager.h"

#include "counter.h"

#if NRF_MODULE_ENABLED(NRF_CRYPTO)
/**@file
 * @defgroup AES_CBC_MAC_example main.c
 *
 * @{
 *
 */


// Intervals for advertising and connections
static simple_ble_config_t ble_config = {
        // c0:98:e5:4e:xx:xx
        .platform_id       = 0x4E,   // used as 4th octect in device BLE address
        .device_id         = 0xAABB, // must be unique on each device you program!
        .adv_name          = "mashed potato", // used in advertisements if there is room
        .adv_interval      = MSEC_TO_UNITS(1000, UNIT_0_625_MS),
        .min_conn_interval = MSEC_TO_UNITS(500, UNIT_1_25_MS),
        .max_conn_interval = MSEC_TO_UNITS(1000, UNIT_1_25_MS),
};

//crypto stuff

#define AES_MAC_SIZE                            (16)

#define NRF_CRYPTO_EXAMPLE_AES_MAX_TEXT_SIZE    (100)

#define AES_ERROR_CHECK(error)  \
    do {            \
        if (error)  \
        {           \
            NRF_LOG_RAW_INFO("\r\nError = 0x%x\r\n%s\r\n",           \
                             (error),                                \
                             nrf_crypto_error_string_get(error));    \
            return; \
        }           \
    } while (0);

/* Maximum allowed key = 256 bit */
static uint8_t m_key[32] = {'N', 'O', 'R', 'D', 'I', 'C', ' ',
                            'S', 'E', 'M', 'I', 'C', 'O', 'N', 'D', 'U', 'C', 'T', 'O', 'R',
                            'A', 'E', 'S', '&', 'M', 'A', 'C', ' ', 'T', 'E', 'S', 'T'};

/* Below text is used as plain text for MAC calculation. Its length must be multiple of 16 bytes
   to use NRF_CRYPTO_AES library. */
static char m_plain_text[NRF_CRYPTO_EXAMPLE_AES_MAX_TEXT_SIZE] =
{
    "Example string demonstrating AES CBC_MAC. Text is 64 bytes long."
};

// global mac because these functions are dumb
uint8_t	mac[AES_MAC_SIZE];

static void text_print(char const* p_label, char const * p_text, size_t len)
{
    printf("----%s (length: %u) ----\r\n", p_label, len);
    NRF_LOG_FLUSH();
    for(size_t i = 0; i < len; i++)
    {
        printf("%c", p_text[i]);
        NRF_LOG_FLUSH();
    }
    printf("\r\n");
    printf("---- %s end ----\r\n\r\n", p_label);
    NRF_LOG_FLUSH();
}

static void hex_text_print(char const* p_label, char const * p_text, size_t len)
{
    printf("---- %s (length: %u) ----\r\n", p_label, len);
    NRF_LOG_FLUSH();

    // Handle partial line (left)
    for (size_t i = 0; i < len; i++)
    {
        if (((i & 0xF) == 0) && (i > 0))
        {
            printf("\r\n");
            NRF_LOG_FLUSH();
        }

        printf("%02x ", p_text[i]);
        NRF_LOG_FLUSH();
    }
    printf("\r\n");
    printf("---- %s end ----\r\n\r\n", p_label);
    NRF_LOG_FLUSH();
}

static void plain_text_print(void)
{
    size_t len = strlen(m_plain_text);

    text_print("Plain text", m_plain_text, len);
    hex_text_print("Plain text (hex)", m_plain_text, len);
}

static void mac_print(uint8_t const * p_buff, uint8_t mac_size)
{
    printf("printing actual mac\r\n");
    for(int i = 0; i < mac_size; i++){
        printf("%x ", p_buff[i]);
    }
    printf("\r\n");
}

static void crypt_cbc_mac(void)
{
    uint8_t     iv[NRF_CRYPTO_MBEDTLS_AES_IV_SIZE];
    ret_code_t  ret_val;
    size_t      len_in;
    size_t      len_out;

    nrf_crypto_aes_context_t cbc_mac_128_ctx;

    memset(mac, 0, sizeof(mac));

 //   plain_text_print();

    /* Init cbc_mac context */
    ret_val = nrf_crypto_aes_init(&cbc_mac_128_ctx,
                                  &g_nrf_crypto_aes_cbc_mac_128_info,
                                  NRF_CRYPTO_MAC_CALCULATE);
    AES_ERROR_CHECK(ret_val);

    /* Set encryption key */
    ret_val = nrf_crypto_aes_key_set(&cbc_mac_128_ctx, m_key);
    AES_ERROR_CHECK(ret_val);

    /* Set IV */
    memset(iv, 0, sizeof(iv));

    ret_val = nrf_crypto_aes_iv_set(&cbc_mac_128_ctx, iv);
    AES_ERROR_CHECK(ret_val);

    len_in  = strlen(m_plain_text);
    len_out = sizeof(mac);

    /* Calculate MAC */
    ret_val = nrf_crypto_aes_finalize(&cbc_mac_128_ctx,
                                      (uint8_t *)m_plain_text,
                                      len_in,
                                      (uint8_t *)mac,
                                      &len_out);
    AES_ERROR_CHECK(ret_val);

    ret_val = nrf_crypto_aes_uninit(&cbc_mac_128_ctx);
    AES_ERROR_CHECK(ret_val);

//    mac_print(mac, len_out);
}


/*******************************************************************************
 *   State for this application
 ******************************************************************************/
// Main application state
simple_ble_app_t* simple_ble_app;


int main(void) {

  printf("Board started. Initializing BLE: \n");
  // Setup BLE
  simple_ble_app = simple_ble_init(&ble_config);

  printf("AES_CBC_MAC started.\r\n\r\n");
  printf("starting timer \n");
  counter_init(); 
  counter_start();

  // get MAC
  ret_code_t ret;

  APP_ERROR_CHECK(NRF_LOG_INIT(NULL));
  NRF_LOG_DEFAULT_BACKENDS_INIT();

  nrf_drv_clock_lfclk_request(NULL);

  ret = nrf_crypto_init();
  APP_ERROR_CHECK(ret);

  for(int x = 0; x < 100000; x++){
  	crypt_cbc_mac();
  }

  counter_stop();
  uint32_t time = counter_get();
  printf("timer was %lu milliseconds\n", time);
}

/** @} */
#endif // NRF_MODULE_ENABLED(NRF_CRYPTO)
