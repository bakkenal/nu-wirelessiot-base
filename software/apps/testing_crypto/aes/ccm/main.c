#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <ctype.h>

#include "nrf52840dk.h"

#include "boards.h"

#include "nrf_crypto.h"
#include "nrf_crypto_error.h"
#include "mem_manager.h"

#include "counter.h"

#include "nrf_drv_power.h"

#include "app_error.h"
#include "app_util.h"

#include "nrf_log.h"
#include "nrf_log_ctrl.h"
#include "nrf_log_default_backends.h"

#include "nrf.h"
#include "nrf_drv_clock.h"
#include "nrf_delay.h"

#if NRF_MODULE_ENABLED(NRF_CRYPTO)
/**@file
 * @defgroup AES_CCM_example main.c
 *
 * @{
 *
 */

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

/* Below text is used as plain text for encryption, decryption and MAC calculation. */
static char m_plain_text[NRF_CRYPTO_EXAMPLE_AES_MAX_TEXT_SIZE] =
{
    "Example string used to demonstrate basic usage of AES CCM mode."
};

static char m_encrypted_text[NRF_CRYPTO_EXAMPLE_AES_MAX_TEXT_SIZE];
static char m_decrypted_text[NRF_CRYPTO_EXAMPLE_AES_MAX_TEXT_SIZE];

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

static void decrypted_text_print(char const * p_text, size_t decrypted_len)
{
    text_print("Decrypted text", p_text, decrypted_len);
    hex_text_print("Decrypted text (hex)", p_text, decrypted_len);
}

static void mac_print(uint8_t const * p_buff, uint8_t mac_size)
{
    hex_text_print("MAC (hex)", (char const*)p_buff, mac_size);
}

static void crypt_ccm(void)
{
    uint32_t    len;
    ret_code_t  ret_val;

    static uint8_t     mac[AES_MAC_SIZE];
    static uint8_t     nonce[13];
    static uint8_t     adata[] = {0xAA, 0xBB, 0xCC, 0xDD};

    static nrf_crypto_aead_context_t ccm_ctx;

    memset(mac,   0, sizeof(mac));
    memset(nonce, 0, sizeof(nonce));

//    plain_text_print();

    len = strlen((char const *)m_plain_text);

    /* Init encrypt and decrypt context */
    ret_val = nrf_crypto_aead_init(&ccm_ctx,
                                   &g_nrf_crypto_aes_ccm_128_info,
                                   m_key);
    AES_ERROR_CHECK(ret_val);

    /* encrypt and tag text */
    ret_val = nrf_crypto_aead_crypt(&ccm_ctx,
                                    NRF_CRYPTO_ENCRYPT,
                                    nonce,
                                    sizeof(nonce),
                                    adata,
                                    sizeof(adata),
                                    (uint8_t *)m_plain_text,
                                    len,
                                    (uint8_t *)m_encrypted_text,
                                    mac,
                                    sizeof(mac));
    AES_ERROR_CHECK(ret_val);

//    encrypted_text_print(m_encrypted_text, len);
//    mac_print(mac, sizeof(mac));

    /* decrypt text */
    ret_val = nrf_crypto_aead_crypt(&ccm_ctx,
                                    NRF_CRYPTO_DECRYPT,
                                    nonce,

                                    sizeof(nonce),
                                    adata,
                                    sizeof(adata),
                                    (uint8_t *)m_encrypted_text,
                                    len,
                                    (uint8_t *)m_decrypted_text,
                                    mac,
                                    sizeof(mac));
    AES_ERROR_CHECK(ret_val);

    ret_val = nrf_crypto_aead_uninit(&ccm_ctx);
    AES_ERROR_CHECK(ret_val);

//    decrypted_text_print(m_decrypted_text, len);

}

// insert crypto-related stuff here

int main(void){
	printf("program starting!");
	counter_init();
	counter_start();

	// crypto stuff
	ret_code_t ret;
	
    	APP_ERROR_CHECK(NRF_LOG_INIT(NULL));
    	NRF_LOG_DEFAULT_BACKENDS_INIT();

	NRF_LOG_FLUSH();
	
    	ret = nrf_drv_clock_init();
    	APP_ERROR_CHECK(ret);
    	nrf_drv_clock_lfclk_request(NULL);

    	ret = nrf_crypto_init();
    	APP_ERROR_CHECK(ret);

    	ret = nrf_mem_init();
    	APP_ERROR_CHECK(ret);

	for(int x = 0; x < 100000; x++){
		crypt_ccm();
	}
	// end, get time
	counter_stop();
	int time = counter_get();
	printf("timer was %d * 30.517 microseconds\n", time);
}

/** @} */
#endif // NRF_MODULE_ENABLED(NRF_CRYPTO)


