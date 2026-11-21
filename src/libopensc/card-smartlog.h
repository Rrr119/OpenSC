#ifndef CARD_SMARTLOG_H
#define CARD_SMARTLOG_H

#include "libopensc/opensc.h"
#include "libopensc/pkcs15.h"

#define SMARTLOG_CLA 0x00
#define SMARTLOG_KEY_ID 0x01
#define SMARTLOG_PIN_REFERENCE 0x01

struct smartlog_pin_policy {
	int card_type;
	size_t min_length;
	size_t max_length;
	int max_tries;
	unsigned int pin_type;
	unsigned int flags;
};

const struct smartlog_pin_policy *smartlog_get_pin_policy(int card_type);

#endif
