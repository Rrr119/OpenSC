/*
 * card-smartlog.c: Support for SmartLog PKI smart cards used for
 * interactive logon and network authentication.
 *
 * The SmartLog applet is a JavaCard ISO 7816-4 application exposing an
 * RSA authentication key, an X.509 certificate and a single user PIN.
 * Three card profiles are currently supported, which only differ by ATR
 * and by the enforced PIN policy.
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <string.h>

#include "internal.h"
#include "log.h"
#include "pkcs15.h"
#include "card-smartlog.h"

static const struct sc_card_operations *iso_ops = NULL;

static struct sc_card_operations smartlog_ops;
static struct sc_card_driver smartlog_drv = {
	"SmartLog PKI card",
	"smartlog",
	&smartlog_ops,
	NULL, 0, NULL
};

static const struct sc_atr_table smartlog_atrs[] = {
	{"3b:d2:18:00:81:31:fe:58:53:4d:4c:31", NULL, NULL, SC_CARD_TYPE_SMARTLOG_V1, 0, NULL},
	{"3b:d2:18:00:81:31:fe:58:53:4d:4c:32", NULL, NULL, SC_CARD_TYPE_SMARTLOG_V2, 0, NULL},
	{"3b:d2:18:00:81:31:fe:58:53:4d:4c:33", NULL, NULL, SC_CARD_TYPE_SMARTLOG_V3, 0, NULL},
	{NULL, NULL, NULL, 0, 0, NULL}
};

/* Per-card PIN policy.  The policy is enforced before any VERIFY/CHANGE
 * PIN APDU is sent to the card so that invalid PINs are rejected locally. */

static const struct smartlog_pin_policy smartlog_pin_policies[] = {
	{ SC_CARD_TYPE_SMARTLOG_V1, 4, 8,  3, SC_PKCS15_PIN_TYPE_BCD,
		SC_PKCS15_PIN_FLAG_NEEDS_PADDING | SC_PKCS15_PIN_FLAG_INITIALIZED },
	{ SC_CARD_TYPE_SMARTLOG_V2, 6, 12, 3, SC_PKCS15_PIN_TYPE_ASCII_NUMERIC,
		SC_PKCS15_PIN_FLAG_CASE_SENSITIVE | SC_PKCS15_PIN_FLAG_INITIALIZED },
	{ SC_CARD_TYPE_SMARTLOG_V3, 8, 16, 5, SC_PKCS15_PIN_TYPE_ASCII_NUMERIC,
		SC_PKCS15_PIN_FLAG_CASE_SENSITIVE | SC_PKCS15_PIN_FLAG_INITIALIZED },
};

const struct smartlog_pin_policy *smartlog_get_pin_policy(int card_type)
{
	size_t i;

	for (i = 0; i < sizeof(smartlog_pin_policies) / sizeof(smartlog_pin_policies[0]); i++) {
		if (smartlog_pin_policies[i].card_type == card_type)
			return &smartlog_pin_policies[i];
	}
	return NULL;
}

static int smartlog_match_card(sc_card_t *card)
{
	int type = 0;

	if (_sc_match_atr(card, smartlog_atrs, &type) < 0)
		return 0;

	sc_log(card->ctx, "SmartLog PKI card (profile %d)", type);
	return 1;
}

static int smartlog_get_serialnr(sc_card_t *card)
{
	sc_apdu_t apdu;
	u8 rbuf[SC_MAX_APDU_BUFFER_SIZE];
	int r;

	sc_format_apdu(card, &apdu, SC_APDU_CASE_2_SHORT, 0xCA, 0x01, 0x81);
	apdu.resp = rbuf;
	apdu.resplen = sizeof(rbuf);
	apdu.le = 256;

	r = sc_transmit_apdu(card, &apdu);
	LOG_TEST_RET(card->ctx, r, "APDU transmit failed");
	if (apdu.sw1 != 0x90 || apdu.sw2 != 0x00)
		return SC_ERROR_INTERNAL;
	if (apdu.resplen > SC_MAX_SERIALNR)
		return SC_ERROR_INTERNAL;

	memcpy(card->serialnr.value, rbuf, apdu.resplen);
	card->serialnr.len = apdu.resplen;
	return SC_SUCCESS;
}

static int smartlog_init(sc_card_t *card)
{
	const unsigned long flags = SC_ALGORITHM_RSA_PAD_PKCS1 | SC_ALGORITHM_RSA_HASH_NONE;
	const struct smartlog_pin_policy *policy;
	int r;

	SC_FUNC_CALLED(card->ctx, SC_LOG_DEBUG_VERBOSE);

	if (_sc_match_atr(card, smartlog_atrs, &card->type) < 0)
		LOG_FUNC_RETURN(card->ctx, SC_ERROR_WRONG_CARD);

	card->name = "SmartLog PKI card";
	card->cla = SMARTLOG_CLA;

	policy = smartlog_get_pin_policy(card->type);
	if (policy == NULL)
		LOG_FUNC_RETURN(card->ctx, SC_ERROR_WRONG_CARD);
	card->max_pin_len = policy->max_length;

	card->caps |= SC_CARD_CAP_ISO7816_PIN_INFO;

	r = smartlog_get_serialnr(card);
	LOG_TEST_RET(card->ctx, r, "Error reading serial number.");

	r = _sc_card_add_rsa_alg(card, 2048, flags, 0);
	LOG_FUNC_RETURN(card->ctx, r);
}

static int smartlog_check_pin_policy(sc_card_t *card, const struct sc_pin_cmd_data *data)
{
	const struct smartlog_pin_policy *policy;
	const struct sc_pin_cmd_pin *pin;
	size_t pin_len;

	if (card == NULL || data == NULL)
		return SC_ERROR_INVALID_ARGUMENTS;

	policy = smartlog_get_pin_policy(card->type);
	if (policy == NULL)
		return SC_ERROR_WRONG_CARD;

	pin = &data->pin1;
	pin_len = pin->len;
	if (pin_len == 0 && pin->data == NULL)
		return SC_SUCCESS; /* PIN-pad readers enforce the policy on the reader */

	if (pin_len < policy->min_length || pin_len > policy->max_length) {
		sc_log(card->ctx, "PIN length %zu does not match policy (%zu-%zu)",
			pin_len, policy->min_length, policy->max_length);
		return SC_ERROR_INVALID_ARGUMENTS;
	}

	if (policy->pin_type == SC_PKCS15_PIN_TYPE_ASCII_NUMERIC) {
		size_t i;
		for (i = 0; i < pin_len; i++) {
			if (pin->data[i] < '0' || pin->data[i] > '9') {
				sc_log(card->ctx, "PIN must contain digits only");
				return SC_ERROR_INVALID_ARGUMENTS;
			}
		}
	}

	return SC_SUCCESS;
}

static int smartlog_pin_cmd(sc_card_t *card, struct sc_pin_cmd_data *data)
{
	int r;

	SC_FUNC_CALLED(card->ctx, SC_LOG_DEBUG_VERBOSE);

	if (data == NULL)
		return SC_ERROR_INVALID_ARGUMENTS;

	if (data->cmd == SC_PIN_CMD_VERIFY || data->cmd == SC_PIN_CMD_CHANGE) {
		r = smartlog_check_pin_policy(card, data);
		LOG_TEST_RET(card->ctx, r, "PIN rejected by SmartLog PIN policy");
		if (data->cmd == SC_PIN_CMD_CHANGE) {
			struct sc_pin_cmd_data check = *data;
			check.pin1 = data->pin2;
			r = smartlog_check_pin_policy(card, &check);
			LOG_TEST_RET(card->ctx, r, "New PIN rejected by SmartLog PIN policy");
		}
	}

	if (data->pin_reference <= 0)
		data->pin_reference = SMARTLOG_PIN_REFERENCE;

	return iso_ops->pin_cmd(card, data);
}

static int smartlog_logout(sc_card_t *card)
{
	sc_path_t path;

	sc_format_path("3F00", &path);
	return sc_select_file(card, &path, NULL);
}

struct sc_card_driver *sc_get_smartlog_driver(void)
{
	if (iso_ops == NULL)
		iso_ops = sc_get_iso7816_driver()->ops;
	smartlog_ops = *iso_ops;
	smartlog_ops.match_card = smartlog_match_card;
	smartlog_ops.init = smartlog_init;
	smartlog_ops.pin_cmd = smartlog_pin_cmd;
	smartlog_ops.logout = smartlog_logout;
	return &smartlog_drv;
}
