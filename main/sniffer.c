#include <stdio.h>
#include <string.h>
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "freertos/event_groups.h"
#include "esp_system.h"
#include "esp_wifi.h"
#include "esp_event.h"
#include "esp_log.h"
#include "nvs_flash.h"
#include <ds1307.h>

#include "lwip/err.h"
#include "lwip/sys.h"

#define maxCh 13 // max Channel -> US = 11, EU = 13, Japan = 14
const char *TAG = "sniffer";
const wifi_promiscuous_filter_t filt = { // Idk what this does
    .filter_mask = WIFI_PROMIS_FILTER_MASK_MGMT | WIFI_PROMIS_FILTER_MASK_DATA};
const int default_TTL = 60; // tempo maximo que um dispositivo e considerado online
i2c_dev_t dev;

typedef struct
{
    char mac[13];
    int ttl;
    int rssi;
    bool state;
    struct tm criado;
    struct tm offline;
} Device;

Device devices[255];

int listcount = 0;

int curChannel = 1;

void purge()
{
    for (int i = 0; i < listcount; i++)
    {
        if (devices[i].state)
        {
            devices[i].ttl--;

            if (devices[i].ttl == 0)
            {
                devices[i].state = false;
                ds1307_get_time(&dev, &devices[i].offline);
            }
        }
    }
}

bool compair_mac(char mac1[13], char mac2[13])
{
    bool ok = true;

    for (int i = 0; i < 12; i++)
    {
        if (mac1[i] != mac2[i])
        {
            ok = false;
            break;
        }
    }

    return ok;
}

void sniffer(void *buf, wifi_promiscuous_pkt_type_t type)
{                                                              // This is where packets end up after they get sniffed
    wifi_promiscuous_pkt_t *p = (wifi_promiscuous_pkt_t *)buf; // Dont know what these 3 lines do
    int len = p->rx_ctrl.sig_len;

    if (len < 0)
    {
        ESP_LOGI(TAG, "Receuved 0");
        return;
    }

    // uint8_t mac[6];

    char mac[13];

    sprintf(mac, "%02X%02X%02X%02X%02X%02X", p->payload[10],
            p->payload[11], p->payload[12], p->payload[13], p->payload[14], p->payload[15]);
    /*
        for (int i = 0; i < 6; i++)
        {
            mac[i] = p->payload[i + 10];
        }
    */
    bool novo = true;

    for (uint8_t i = 0; i < listcount; i++)
    {
        if (compair_mac(devices[i].mac, mac))
        {
            devices[i].ttl = default_TTL;
            devices[i].rssi = p->rx_ctrl.rssi;
            if (!devices[i].state)
            {
                devices[i].state = true;
            }

            novo = false;
            break;
        }
    }

    if (novo)
    {
        for (int i = 0; i < 12; i++)
        {
            devices[listcount].mac[i] = mac[i];
        }
        devices[listcount].state = true;
        devices[listcount].ttl = default_TTL;
        devices[listcount].rssi = p->rx_ctrl.rssi;
        ds1307_get_time(&dev, &devices[listcount].criado);
        listcount++;

        if (listcount == 255)
        {
            ESP_LOGI(TAG, "Lista completa");
            listcount = 0;
        }
    }
}

void app_main(void)
{

    esp_err_t ret = nvs_flash_init();
    if (ret == ESP_ERR_NVS_NO_FREE_PAGES || ret == ESP_ERR_NVS_NEW_VERSION_FOUND)
    {
        ESP_ERROR_CHECK(nvs_flash_erase());
        ret = nvs_flash_init();
    }
    ESP_ERROR_CHECK(ret);

    wifi_init_config_t cfg = WIFI_INIT_CONFIG_DEFAULT();

    esp_wifi_init(&cfg);
    esp_wifi_set_storage(WIFI_STORAGE_RAM);
    esp_wifi_set_mode(WIFI_MODE_NULL);
    esp_wifi_start();
    esp_wifi_set_promiscuous(true);
    esp_wifi_set_promiscuous_filter(&filt);
    esp_wifi_set_promiscuous_rx_cb(&sniffer);
    esp_wifi_set_channel(curChannel, WIFI_SECOND_CHAN_NONE);

    ESP_ERROR_CHECK(i2cdev_init());

    memset(&dev, 0, sizeof(i2c_dev_t));

    ESP_ERROR_CHECK(ds1307_init_desc(&dev, 0, 34, 33));

    // setup datetime: 2018-04-11 00:52:10
    struct tm time = {
        .tm_year = 123, // since 1900 (2018 - 1900)
        .tm_mon = 3,    // 0-based
        .tm_mday = 22,
        .tm_hour = 23,
        .tm_min = 18,
        .tm_sec = 10};
    // ESP_ERROR_CHECK(ds1307_set_time(&dev, &time));

    while (1)
    {
        if (curChannel > maxCh)
        {
            curChannel = 1;
        }
        esp_wifi_set_channel(curChannel, WIFI_SECOND_CHAN_NONE);

        ESP_LOGI(TAG, "Numero de dispositivos na area: %d", listcount);

        ESP_LOGI(TAG, "Dispositivos: \n");

        for (int i = 0; i < listcount; i++)
        {
            printf("MAC: %s, TTL: %d, estado: %d, rssi: %d, conectado em: %02d:%02d:%02d", devices[i].mac, devices[i].ttl,
                   devices[i].state, devices[i].rssi, devices[i].criado.tm_hour, devices[i].criado.tm_min, devices[i].criado.tm_sec);
            if (devices[i].state)
            {
                printf(";\n");
            }
            else
            {
                printf(" desconectado em: %02d:%02d:%02d;\n", devices[i].offline.tm_hour, devices[i].offline.tm_min, devices[i].offline.tm_sec);
            }
        }

        ESP_LOGI("", "-----------------------\n");

        purge();
        vTaskDelay(pdMS_TO_TICKS(1000));
        curChannel++;
    }
}
