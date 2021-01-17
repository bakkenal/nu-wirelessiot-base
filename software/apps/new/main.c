#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>

#include "app_error.h"
#include "nrf.h"
#include "nrf_delay.h"
#include "nrfx_gpiote.h"
#include "nrf_gpio.h"
#include "nrf_log.h"
#include "nrf_log_ctrl.h"
#include "nrf_log_default_backends.h"
#include "nrf_pwr_mgmt.h"
#include "nrf_serial.h"

// Pin configurations
#include "nrf52840dk.h"

int main(void){
  // initialize
  ret_code_t error_code = NRF_SUCCESS;

  nrf_gpio_cfg_output(LED1);
  nrf_gpio_cfg_output(LED2);
  nrf_gpio_cfg_output(LED3);
  nrf_gpio_cfg_output(LED4);
  nrf_gpio_pin_set(LED1);
  nrf_gpio_pin_set(LED2);
  nrf_gpio_pin_set(LED3);
  nrf_gpio_pin_set(LED4);
  nrf_gpio_cfg_input(BUTTON1, NRF_GPIO_PIN_PULLUP);
  nrf_gpio_cfg_input(BUTTON2, NRF_GPIO_PIN_PULLUP);
  nrf_gpio_cfg_input(BUTTON3, NRF_GPIO_PIN_PULLUP);
  nrf_gpio_cfg_input(BUTTON4, NRF_GPIO_PIN_PULLUP);

  // initialize RTT library
  error_code = NRF_LOG_INIT(NULL);
  APP_ERROR_CHECK(error_code);
  NRF_LOG_DEFAULT_BACKENDS_INIT();
  printf("Log initialized!\n");

  // creating flags so the print statements dont go nuts
  int button1, button2, button3, button4 = 0;

  // Enter main loop.
  while (1) {
    if (nrf_gpio_pin_read(BUTTON1)) {
     	nrf_gpio_pin_set(LED1);
	button1 = 0;
    } else {
      nrf_gpio_pin_clear(LED1);
      	if(button1 == 0){
		printf("button 1 pressed!\n");
		button1 = 1;
	}
    }

    if (nrf_gpio_pin_read(BUTTON2)) {
        nrf_gpio_pin_set(LED2);
	button2 = 0;
    } else {
	if(button2 == 0){
                printf("button 2 pressed!\n");
                button2 = 1;
        }
	nrf_gpio_pin_clear(LED2);
    }

    if (nrf_gpio_pin_read(BUTTON3)) {
      	nrf_gpio_pin_set(LED3);
	button3 = 0;
    } else {
	if(button3 == 0){
		printf("button 3 pressed!\n");
		button3 = 1;
	}
      nrf_gpio_pin_clear(LED3);
    }

    if (nrf_gpio_pin_read(BUTTON4)) {
        nrf_gpio_pin_set(LED4);
	button4 = 0;
    } else {
	if(button4 == 0){
		printf("button 4 pressed!\n");
		button4 = 1;
	}
      nrf_gpio_pin_clear(LED4);
    }
  }
}
