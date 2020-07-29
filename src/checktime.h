//
// Created by cuongbv on 29/07/2020.
//

#ifndef SURICATA_5_0_3_CHECKTIME_H
#define SURICATA_5_0_3_CHECKTIME_H

#include "util-pages.h"

typedef struct CheckTimeData_ {
    char text[MQ_TEXT_LENGTH];                    /**< seq to match */
} CheckTimeData;

void CheckTimeRegister(void);
#endif //SURICATA_5_0_3_CHECKTIME_H
