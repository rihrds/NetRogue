#ifndef ATTACK_H
#define ATTACK_H

#include "helper.h"

int owe_asso_resp_replay_attack(int raw_socket, const ap_info *ap, const intf_info *intf);
int owe_asso_resp_code_attack(int raw_socket, const ap_info *ap, const intf_info *intf);
int owe_asso_req_attack(int raw_socket, const ap_info *ap);

#endif