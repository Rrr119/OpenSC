/*
 * PKCS#15 emulation layer for SmartLog PKI smart cards.
 *
 * The emulation exposes the on-card authentication certificate and RSA
 * private key through the standard PKCS#15 layer, which makes the card
 * usable through the existing OpenSC PKCS#11 module without any changes
 * to the PKCS#11 code.
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

#include <stdlib.h>
#include <string.h>

#include "common/compat_strlcpy.h"

#include "internal.h"
#include "log.h"
#include "pkcs15.h"
#include "card-smartlog.h"

#define SMARTLOG_PIN_AUTH_ID 0x01

static int smartlog_is_supported(int card_type)
{
	return card_type == SC_CARD_TYPE_SMARTLOG_V1
		|| card_type == SC_CARD_TYPE_SMARTLOG_V2
		|| card_type == SC_CARD_TYPE_SMARTLOG_V3;
}

static int sc_pkcs15emu_smartlog_init(sc_pkcs15_card_t *p15card)
{
	sc_card_t *card = p15card->card;
	const struct smartlog_pin_policy *policy;
	struct sc_pkcs15_auth_info pin_info;
	struct sc_pkcs15_object pin_obj;
	struct sc_pkcs15_cert_info cert_info;
	struct sc_pkcs15_object cert_obj;
	struct sc_pkcs15_prkey_info prkey_info;
	struct sc_pkcs15_object prkey_obj;
	char *serial;
	size_t sn_len;
	int r;

	policy = smartlog_get_pin_policy(card->type);
	if (policy == NULL)
		return SC_ERROR_WRONG_CARD;

	set_string(&p15card->tokeninfo->label, "SmartLog PKI card");
	set_string(&p15card->tokeninfo->manufacturer_id, "SmartLog");

	sn_len = card->serialnr.len;
	if (sn_len > 0) {
		serial = malloc(2 * sn_len + 1);
		if (serial == NULL)
			return SC_ERROR_OUT_OF_MEMORY;
		sc_bin_to_hex(card->serialnr.value, sn_len, serial, 2 * sn_len + 1, 0);
		p15card->tokeninfo->serial_number = serial;
	}

	p15card->tokeninfo->flags = SC_PKCS15_TOKEN_READONLY;

	/* PIN object carrying the per-card PIN policy. */
	memset(&pin_info, 0, sizeof(pin_info));
	memset(&pin_obj, 0, sizeof(pin_obj));

	pin_info.auth_id.len = 1;
	pin_info.auth_id.value[0] = SMARTLOG_PIN_AUTH_ID;
	pin_info.auth_type = SC_PKCS15_PIN_AUTH_TYPE_PIN;
	pin_info.attrs.pin.reference = SMARTLOG_PIN_REFERENCE;
	pin_info.attrs.pin.flags = policy->flags;
	pin_info.attrs.pin.type = policy->pin_type;
	pin_info.attrs.pin.min_length = policy->min_length;
	pin_info.attrs.pin.max_length = policy->max_length;
	pin_info.max_tries = policy->max_tries;

	strlcpy(pin_obj.label, "User PIN", sizeof(pin_obj.label));
	pin_obj.flags = policy->flags;
	sc_format_path("3F00", &pin_info.path);

	r = sc_pkcs15emu_add_pin_obj(p15card, &pin_obj, &pin_info);
	LOG_TEST_RET(card->ctx, r, "Error adding PIN.");

	/* X.509 authentication certificate used for logon. */
	memset(&cert_info, 0, sizeof(cert_info));
	memset(&cert_obj, 0, sizeof(cert_obj));

	cert_info.id.len = 1;
	cert_info.id.value[0] = SMARTLOG_PIN_AUTH_ID;
	sc_format_path("3f0050154301", &cert_info.path);
	strlcpy(cert_obj.label, "Authentication certificate", sizeof(cert_obj.label));

	r = sc_pkcs15emu_add_x509_cert(p15card, &cert_obj, &cert_info);
	LOG_TEST_RET(card->ctx, r, "Error adding certificate.");

	/* RSA private key bound to the user PIN. */
	memset(&prkey_info, 0, sizeof(prkey_info));
	memset(&prkey_obj, 0, sizeof(prkey_obj));

	prkey_info.id.len = 1;
	prkey_info.id.value[0] = SMARTLOG_PIN_AUTH_ID;
	prkey_info.native = 1;
	prkey_info.key_reference = SMARTLOG_KEY_ID;
	prkey_info.modulus_length = 2048;
	prkey_info.usage = SC_PKCS15_PRKEY_USAGE_SIGN
		| SC_PKCS15_PRKEY_USAGE_DECRYPT
		| SC_PKCS15_PRKEY_USAGE_ENCRYPT;
	sc_format_path("3f005015", &prkey_info.path);

	strlcpy(prkey_obj.label, "Authentication key", sizeof(prkey_obj.label));
	prkey_obj.auth_id.len = 1;
	prkey_obj.auth_id.value[0] = SMARTLOG_PIN_AUTH_ID;
	prkey_obj.flags = SC_PKCS15_CO_FLAG_PRIVATE;

	r = sc_pkcs15emu_add_rsa_prkey(p15card, &prkey_obj, &prkey_info);
	LOG_TEST_RET(card->ctx, r, "Error adding private key.");

	LOG_FUNC_RETURN(card->ctx, SC_SUCCESS);
}

int sc_pkcs15emu_smartlog_init_ex(sc_pkcs15_card_t *p15card, struct sc_aid *aid)
{
	(void) aid;

	if (p15card == NULL || p15card->card == NULL)
		return SC_ERROR_WRONG_CARD;

	if (!smartlog_is_supported(p15card->card->type))
		return SC_ERROR_WRONG_CARD;

	return sc_pkcs15emu_smartlog_init(p15card);
}
