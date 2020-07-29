//
// Created by cuongbv on 29/07/2020.
//

#ifndef SURICATA_5_0_3_DETECT_DST_H
#define SURICATA_5_0_3_DETECT_DST_H

#include "util-pages.h"

typedef struct DetectDstData_ {
    char text[MQ_TEXT_LENGTH];                    /**< seq to match */
} DetectDstData;

/**
 * \brief Registration function for ack: keyword
 */
void DetectDstRegister(void);
#endif //SURICATA_5_0_3_DETECT_DST_H
