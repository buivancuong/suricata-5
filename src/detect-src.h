//
// Created by cuongbv on 29/07/2020.
//

#ifndef SURICATA_5_0_3_DETECT_SRC_H
#define SURICATA_5_0_3_DETECT_SRC_H

#include "util-pages.h"

typedef struct DetectSrcData_ {
    char text[MQ_TEXT_LENGTH];                    /**< seq to match */
} DetectSrcData;

/**
 * \brief Registration function for ack: keyword
 */
void DetectSrcRegister(void);
#endif //SURICATA_5_0_3_DETECT_SRC_H
