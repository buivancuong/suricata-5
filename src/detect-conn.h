//
// Created by cuongbv on 29/07/2020.
//

#ifndef SURICATA_5_0_3_DETECT_CONN_H
#define SURICATA_5_0_3_DETECT_CONN_H

#include "util-pages.h"

typedef struct DetectConnData_ {
    char text[MQ_TEXT_LENGTH];                    /**< seq to match */
} DetectConnData;

/**
 * \brief Registration function for ack: keyword
 */
void DetectConnRegister(void);
#endif //SURICATA_5_0_3_DETECT_CONN_H
