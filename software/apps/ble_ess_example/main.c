// BLE Service example app
//
// Creates a BLE environmental sensing service

#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>

#include "nrf_delay.h"
#include "nrf_gpio.h"
#include "simple_ble.h"

#include "nrf52840dk.h"

// Intervals for advertising and connections
static simple_ble_config_t ble_config = {
  // c0:98:e5:4e:xx:xx
  .platform_id       = 0x4E,    // used as 4th octect in device BLE address
  .device_id         = 0xAABB,
  .adv_name          = "CS397/497", // used in advertisements if there is room
  .adv_interval      = MSEC_TO_UNITS(1000, UNIT_0_625_MS),
  .min_conn_interval = MSEC_TO_UNITS(500, UNIT_1_25_MS),
  .max_conn_interval = MSEC_TO_UNITS(1000, UNIT_1_25_MS),
};

static simple_ble_service_t environmental_sensing_service = {{
  .uuid128 = {0xFB,0x34,0x9B,0x5F,0x80,0x00,0x00,0x80,
              0x00,0x10,0x00,0x00,0x1A,0x18,0x00,0x00}
}};

static simple_ble_char_t Elevation = {.uuid16 = 0x2A6C};
static simple_ble_char_t Pressure = {.uuid16 = 0x2A6D};
static simple_ble_char_t Humidity = {.uuid16 = 0x2A6F};
static simple_ble_char_t Rainfall = {.uuid16 = 0x2A78};
static simple_ble_char_t Windchill = {.uuid16 = 0x2A79};
static int32_t elevationNum = 1000 & 0xFFFFFF;
static uint32_t pressureNum = 30;
static uint16_t humidityNum = 74;
static uint16_t rainfallNum = 5;
static int8_t windchillNum = 5;

/*******************************************************************************
 *   State for this application
 ******************************************************************************/
// Main application state
simple_ble_app_t* simple_ble_app;

void ble_evt_write(ble_evt_t const* p_ble_evt) {
  printf("Got write to a characteristic!\n");
}

int main(void) {

  printf("Board started. Initializing BLE: \n");

  // Setup BLE
  simple_ble_app = simple_ble_init(&ble_config);

  simple_ble_add_service(&environmental_sensing_service);
  simple_ble_add_characteristic(1, 0, 1, 0,
	24,(uint8_t*)&elevationNum,
	&environmental_sensing_service, &Elevation);
  simple_ble_add_characteristic(1, 0, 1, 0,
        sizeof(pressureNum),(uint8_t*)&pressureNum,
        &environmental_sensing_service, &Pressure);
  simple_ble_add_characteristic(1, 0, 1, 0,
        sizeof(humidityNum),(uint8_t*)&humidityNum,
        &environmental_sensing_service, &Humidity);
  simple_ble_add_characteristic(1, 0, 1, 0,
        sizeof(rainfallNum),(uint8_t*)&rainfallNum,
        &environmental_sensing_service, &Rainfall);
  simple_ble_add_characteristic(1, 0, 1, 0,
        sizeof(windchillNum),(uint8_t*)&windchillNum,
        &environmental_sensing_service, &Windchill);

  // Start Advertising
  simple_ble_adv_only_name();

  while(1) {
    power_manage();
  }
}

