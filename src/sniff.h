#ifndef SNIFF_H
#define SNIFF_H

#include <stdbool.h>
#include <stdint.h>

int sniff(int raw_socket, uint8_t *packet_buffer, bool (*filter)(uint8_t *), int listen_limit);

#endif