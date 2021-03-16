// BLE Scanning app
//
// Receives BLE advertisements

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

// crypto stuff

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

/* Below text is used as plain text for encryption and decryption in AES CBC mode with padding. */
static char m_plain_text[] =
{
    "Example string to demonstrate AES CBC mode with padding. This text has 85 characters."
};

static char decrypted_text[NRF_CRYPTO_EXAMPLE_AES_MAX_TEXT_SIZE];
static char encrypted_text[NRF_CRYPTO_EXAMPLE_AES_MAX_TEXT_SIZE];

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

static void decrypted_text_print(char const * p_text, size_t decrypted_len)
{
    text_print("Decrypted text", p_text, decrypted_len);
    hex_text_print("Decrypted text (hex)", p_text, decrypted_len);
}

static void encrypted_text_print(char const * p_text, size_t encrypted_len)
{
    hex_text_print("Encrypted text (hex)", p_text, encrypted_len);
}

static void decrypt_cbc(void)
{
    uint8_t     iv[16];
    ret_code_t  ret_val;
    size_t      len_out;
        
    static nrf_crypto_aes_context_t cbc_decr_128_ctx; // AES CBC decryption context

    memset(decrypted_text,  0, sizeof(decrypted_text));

    //
    // Decryption phase
    //

//    printf("decryption started!\r\n");
    /* Init decryption context for 128 bit key and PKCS7 padding mode */
    ret_val = nrf_crypto_aes_init(&cbc_decr_128_ctx,
                                  &g_nrf_crypto_aes_cbc_128_pad_pkcs7_info,
                                  NRF_CRYPTO_DECRYPT);
    AES_ERROR_CHECK(ret_val);

//    printf("init finished!\r\n");
    /* Set key for decryption context - only first 128 key bits will be used */
    ret_val = nrf_crypto_aes_key_set(&cbc_decr_128_ctx, m_key);
    AES_ERROR_CHECK(ret_val);

    memset(iv, 0, sizeof(iv));
    /* Set IV for decryption context */

    ret_val = nrf_crypto_aes_iv_set(&cbc_decr_128_ctx, iv);
    AES_ERROR_CHECK(ret_val);

    len_out = sizeof(encrypted_text);
    size_t encryption_size = 120;
    while(encrypted_text[encryption_size-1] == 0x00){
    	encryption_size -= 1;
    }
//    printf("encryption size is %d\r\n", encryption_size);
//    encrypted_text_print(encrypted_text, len_out);
//    printf("starting decryption!\r\n");

    /* Decrypt text */
    ret_val = nrf_crypto_aes_finalize(&cbc_decr_128_ctx,
                                      (uint8_t *)encrypted_text,
                                      encryption_size,
                                      (uint8_t *)decrypted_text,
                                      &len_out);
    AES_ERROR_CHECK(ret_val);
//    printf("decryption finished!\r\n\r\n");
    /* trim padding */
    decrypted_text[len_out] = '\0';

//    decrypted_text_print(decrypted_text, len_out);
    
    NRF_LOG_FLUSH();
}

// BLE configuration
// This is mostly irrelevant since we are scanning only
static simple_ble_config_t ble_config = {
        // BLE address is c0:98:e5:4e:00:02
        .platform_id       = 0x4E,    // used as 4th octet in device BLE address
        .device_id         = 0x0002,  // used as the 5th and 6th octet in the device BLE address, you will need to change this for each device you have
        .adv_name          = "CS397/497", // irrelevant in this example
        .adv_interval      = MSEC_TO_UNITS(1000, UNIT_0_625_MS), // send a packet once per second (minimum is 20 ms)
        .min_conn_interval = MSEC_TO_UNITS(500, UNIT_1_25_MS), // irrelevant if advertising only
        .max_conn_interval = MSEC_TO_UNITS(1000, UNIT_1_25_MS), // irrelevant if advertising only
};
simple_ble_app_t* simple_ble_app;

int checks[6] = {0,0,0,0,0,0};

// Callback handler for advertisement reception
void ble_evt_adv_report(ble_evt_t const* p_ble_evt) {

  // extract the fields we care about
  ble_gap_evt_adv_report_t const* adv_report = &(p_ble_evt->evt.gap_evt.params.adv_report);
  uint8_t const* ble_addr = adv_report->peer_addr.addr; // array of 6 bytes of the address
  uint8_t* adv_buf = adv_report->data.p_data; // array of up to 31 bytes of advertisement payload data
  uint16_t adv_len = adv_report->data.len; // length of advertisement payload data
  
  // get packet, process
  if(*(ble_addr + 5) == 0xc0 && *(ble_addr + 4) == 0x98){
	
	int packetNumber =  adv_buf[6];
  	if(checks[packetNumber] != 1){
		printf("found %d\r\n", packetNumber);
		for(int x = 0; x < 20; x++){
		 	encrypted_text[x + 20*packetNumber] = (char) adv_buf[9 + x];
		}
		checks[packetNumber] = 1;

		if(checks[0] == 1 && checks[1] == 1 && checks[2] == 1 && checks[3] == 1 && checks[4] == 1 && checks[5] == 1){
			printf("all packets received!\r\n");
			printf("starting timer\r\n");
			counter_init();
			counter_start();
			ret_code_t ret;

        		APP_ERROR_CHECK(NRF_LOG_INIT(NULL));
        		NRF_LOG_DEFAULT_BACKENDS_INIT();
		
        		NRF_LOG_FLUSH();
	
	        	nrf_drv_clock_lfclk_request(NULL);
	
	        	ret = nrf_crypto_init();
	        	APP_ERROR_CHECK(ret);
	
	       		#if NRF_CRYPTO_BACKEND_MBEDTLS_ENABLED
	       		    ret = nrf_mem_init();
	       	     	    APP_ERROR_CHECK(ret);
	       	 	#endif
			for(int i = 0; i < 1000; i++){
		        decrypt_cbc();
			}
			counter_stop();
			int time = counter_get();
			printf("timer was %d * 30.517 microseconds\r\n", time);
		}
	}
  }
}
int main(void) {

  // Setup BLE
  // Note: simple BLE is our own library. You can find it in `nrf5x-base/lib/simple_ble/`
  printf("starting scanning\r\n");
  simple_ble_app = simple_ble_init(&ble_config);
  advertising_stop();

  // Start scanning
  scanning_start();

  // go into low power mode
  while(1) {
    power_manage();
  }
}



