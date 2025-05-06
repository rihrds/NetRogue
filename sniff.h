#ifndef SNIFF_H
#define SNIFF_H

#include <stdbool.h>
#include <stdint.h>

#include "helper.h"

int sniff(int raw_socket, uint8_t *packet_buffer, bool (*filter)(uint8_t *, ap_info), ap_info ap_info, int listen_limit);

#endif