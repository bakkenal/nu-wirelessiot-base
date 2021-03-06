// BLE Advertisement Raw app
//
// Sends a BLE advertisement with raw bytes

#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>

#include "simple_ble.h"
#include "nrf52840dk.h"
#include "nrf_crypto.h"


// Intervals for advertising and connections
static simple_ble_config_t ble_config = {
        // c0:98:e5:4e:xx:xx
        .platform_id       = 0x4E,   // used as 4th octect in device BLE address
        .device_id         = 0xAABB, // must be unique on each device you program!
        .adv_name          = "mashPotat", // used in advertisements if there is room
        .adv_interval      = MSEC_TO_UNITS(1000, UNIT_0_625_MS),
        .min_conn_interval = MSEC_TO_UNITS(500, UNIT_1_25_MS),
        .max_conn_interval = MSEC_TO_UNITS(1000, UNIT_1_25_MS),
};

/*******************************************************************************
 *   State for this application
 ******************************************************************************/
// Main application state
simple_ble_app_t* simple_ble_app;


int main(void) {

  printf("Board started. Initializing BLE: \n");

  // Setup BLE
  // Note: simple BLE is our own library. You can find it in `nrf5x-base/lib/simple_ble/`
  simple_ble_app = simple_ble_init(&ble_config);

  // Start Advertising
  // two bytes, specify flags type, specify flags, three bytes, manufacturer type, 0x0965(asahi kasei), name, 13 bytes, name's bytes
  uint8_t ble_data[BLE_GAP_ADV_SET_DATA_SIZE_MAX] = {0x02, 0x01, 0x06, 0x03, 0xff, 0x65, 0x09, 0x0E, 0x09, 0x6d, 0x61, 0x73, 0x68, 0x65, 0x64, 0x20, 0x70, 0x6f, 0x74, 0x61, 0x74, 0x6f};

  uint8_t dataSize = 22;
  size_t dataOutSize = 22;

  uint8_t tempKey[128] = {};
  uint8_t encryptedData[dataSize];
  ret_code_t err_code;
  nrf_crypto_aes_info_t const * p_ecb_info;
  p_ecb_info = &g_nrf_crypto_aes_ecb_128_info;


  err_code = nrf_crypto_aes_crypt(	NULL,
		  			p_ecb_info,
					NRF_CRYPTO_ENCRYPT,
					tempKey,
					NULL,
					ble_data,
					dataSize,
					encryptedData,
					&dataOutSize);

// stuff for eddystone packets
//  char url_str[] = "google.com";
//  simple_ble_es_with_name(url_str);

  // stuff for regular raw ble advertisements
  if(err_code == NRF_SUCCESS){
  	simple_ble_adv_raw(encryptedData, dataSize);
  }
  else{
	  printf("problem encrypting data!");
  }
  printf("Started BLE advertisements\n");
  fwrite(encryptedData, dataSize, 1, stdout);

  while(1) {
    power_manage();
  }
}


