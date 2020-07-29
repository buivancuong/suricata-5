//
// Created by cuongbv on 29/07/2020.
//

#ifndef SURICATA_5_0_3_CHECKIP_H
#define SURICATA_5_0_3_CHECKIP_H

#include "util-pages.h"

typedef struct CheckIpData_ {
    char text[MQ_TEXT_LENGTH];                    /**< seq to match */
} CheckIpData;

void CheckIpRegister(void);
#endif //SURICATA_5_0_3_CHECKIP_H
