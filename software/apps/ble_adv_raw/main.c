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
 * @defgroup AES_CBC_with_padding main.c
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
#define NRF_CRYPTO_EXAMPLE_AES_MAX_TEXT_SIZE 120


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
                            'A', 'E', 'S', ' ', 'C', 'B', 'C', ' ', 'T', 'E', 'S', 'T'};

static char encrypted_text[NRF_CRYPTO_EXAMPLE_AES_MAX_TEXT_SIZE];


/* Below text is used as plain text for encryption and decryption in AES CBC mode with padding. */
static char m_plain_text[] =
{
    "Example string to demonstrate AES CBC mode with padding. This text has 85 characters."
};

static void text_print(char const* p_label, char const * p_text, size_t len)
{
    NRF_LOG_RAW_INFO("----%s (len: %u) ----\r\n", p_label, len);
    NRF_LOG_FLUSH();
    for(size_t i = 0; i < len; i++)
    {
        NRF_LOG_RAW_INFO("%c", p_text[i]);
        NRF_LOG_FLUSH();
    }
    NRF_LOG_RAW_INFO("\r\n");
    NRF_LOG_RAW_INFO("---- %s end ----\r\n\r\n", p_label);
    NRF_LOG_FLUSH();
}

static void hex_text_print(char const* p_label, char const * p_text, size_t len)
{
    NRF_LOG_RAW_INFO("---- %s (len: %u) ----\r\n", p_label, len);
    NRF_LOG_FLUSH();

    // Handle partial line (left)
    for (size_t i = 0; i < len; i++)
    {
        if (((i & 0xF) == 0) && (i > 0))
        {
            NRF_LOG_RAW_INFO("\r\n");
            NRF_LOG_FLUSH();
        }

        NRF_LOG_RAW_INFO("%02x ", p_text[i]);
        NRF_LOG_FLUSH();
    }
    NRF_LOG_RAW_INFO("\r\n");
    NRF_LOG_RAW_INFO("---- %s end ----\r\n\r\n", p_label);
    NRF_LOG_FLUSH();
}

static void plain_text_print(void)
{
    text_print("Plain text", m_plain_text, strlen(m_plain_text));
    hex_text_print("Plain text (hex)", m_plain_text, strlen(m_plain_text));
}

static void encrypted_text_print(char const * p_text, size_t encrypted_len)
{
    hex_text_print("Encrypted text (hex)", p_text, encrypted_len);
}

static void encrypt_cbc(void)
{
    uint8_t     iv[16];
    ret_code_t  ret_val;
    size_t      len_in;
    size_t      len_out;

    static nrf_crypto_aes_context_t cbc_encr_128_ctx; // AES CBC encryption context

    plain_text_print();

    memset(encrypted_text,  0, sizeof(encrypted_text));

        //
    // Encryption phase
    //

    /* Init encryption context for 128 bit key and PKCS7 padding mode */
    ret_val = nrf_crypto_aes_init(&cbc_encr_128_ctx,
                                  &g_nrf_crypto_aes_cbc_128_pad_pkcs7_info,
                                  NRF_CRYPTO_ENCRYPT);
    AES_ERROR_CHECK(ret_val);

    /* Set key for encryption context - only first 128 key bits will be used */
    ret_val = nrf_crypto_aes_key_set(&cbc_encr_128_ctx, m_key);
    AES_ERROR_CHECK(ret_val);

    memset(iv, 0, sizeof(iv));
    /* Set IV for encryption context */

    ret_val = nrf_crypto_aes_iv_set(&cbc_encr_128_ctx, iv);
    AES_ERROR_CHECK(ret_val);

    len_in = strlen(m_plain_text);
    len_out = sizeof(encrypted_text);

    /* Encrypt text
       When padding is selected m_encrypted_text buffer shall be at least 16 bytes larger
       than text_len. */
    ret_val = nrf_crypto_aes_finalize(&cbc_encr_128_ctx,
                                      (uint8_t *)m_plain_text,
                                      len_in,
                                      (uint8_t *)encrypted_text,
                                      &len_out);
    AES_ERROR_CHECK(ret_val);

    // print the encrypted text
    encrypted_text_print(encrypted_text, len_out);

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

  printf("AES_CBC started.\r\n\r\n");
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

#if NRF_CRYPTO_BACKEND_MBEDTLS_ENABLED
  ret = nrf_mem_init();
  APP_ERROR_CHECK(ret);
#endif
  encrypt_cbc();

  
  counter_stop();
  uint32_t time = counter_get();
  printf("timer was %lu milliseconds\n", time);

  // Start Advertising
  uint8_t advertisement[NRF_CRYPTO_EXAMPLE_AES_MAX_TEXT_SIZE];
  memcpy(advertisement, encrypted_text, sizeof(encrypted_text));
  
  printf("printing advertisement\r\n");
  for(int x = 0; x < NRF_CRYPTO_EXAMPLE_AES_MAX_TEXT_SIZE; x++){
  	printf("%x ", advertisement[x]);
  }

  // stuff for regular raw ble advertisements
  simple_ble_adv_raw(advertisement,  20);
  printf("Started BLE advertisements\n");

  while(1) {
    power_manage();
  }
}

/** @} */
#endif // NRF_MODULE_ENABLED(NRF_CRYPTO)
