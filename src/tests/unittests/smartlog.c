/*
 * smartlog.c: Unit tests for the SmartLog PKI card driver
 *
 * The tests cover the three supported card profiles (V1, V2 and V3):
 *   1. ATR based card matching,
 *   2. the per-card PIN policy enforced by the driver,
 *   3. the PKCS#15 emulation used by the PKCS#11 module.
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

#include "torture.h"

#include "libopensc/opensc.h"
#include "libopensc/cards.h"
#include "libopensc/pkcs15.h"
#include "libopensc/pkcs15-syn.h"

#include "libopensc/sc.c"
#include "libopensc/card-smartlog.c"
#include "libopensc/pkcs15-smartlog.c"

struct profile {
	int card_type;
	const char *atr_hex;
	size_t pin_min;
	size_t pin_max;
	int max_tries;
};

static const struct profile profiles[] = {
	{ SC_CARD_TYPE_SMARTLOG_V1, "3b:d2:18:00:81:31:fe:58:53:4d:4c:31", 4, 8,  3 },
	{ SC_CARD_TYPE_SMARTLOG_V2, "3b:d2:18:00:81:31:fe:58:53:4d:4c:32", 6, 12, 3 },
	{ SC_CARD_TYPE_SMARTLOG_V3, "3b:d2:18:00:81:31:fe:58:53:4d:4c:33", 8, 16, 5 },
};

static sc_context_t *ctx = NULL;

static int setup_context(void **state)
{
	(void) state;
	return sc_establish_context(&ctx, "smartlog-test");
}

static int teardown_context(void **state)
{
	(void) state;
	if (ctx != NULL)
		sc_release_context(ctx);
	ctx = NULL;
	return 0;
}

static sc_card_t *new_card(const struct profile *profile)
{
	sc_card_t *card = calloc(1, sizeof(sc_card_t));
	size_t atr_len = SC_MAX_ATR_SIZE;

	assert_non_null(card);
	card->ctx = ctx;

	sc_hex_to_bin(profile->atr_hex, card->atr.value, &atr_len);
	card->atr.len = (strlen(profile->atr_hex) + 1) / 3;
	card->type = profile->card_type;

	return card;
}

static void torture_driver_registered(void **state)
{
	sc_card_driver_t *driver = sc_get_smartlog_driver();

	(void) state;
	assert_non_null(driver);
	assert_string_equal(driver->short_name, "smartlog");
	assert_non_null(driver->ops);
	assert_non_null(driver->ops->match_card);
	assert_non_null(driver->ops->init);
	assert_non_null(driver->ops->pin_cmd);
}

static void torture_match_atr(void **state)
{
	sc_card_driver_t *driver = sc_get_smartlog_driver();
	size_t i;

	(void) state;
	for (i = 0; i < sizeof(profiles) / sizeof(profiles[0]); i++) {
		sc_card_t *card = new_card(&profiles[i]);

		assert_int_equal(driver->ops->match_card(card), 1);
		free(card);
	}
}

static void torture_match_unknown_atr(void **state)
{
	sc_card_driver_t *driver = sc_get_smartlog_driver();
	struct profile unknown = profiles[0];
	sc_card_t *card;

	(void) state;
	unknown.atr_hex = "3b:d2:18:00:81:31:fe:58:53:4d:4c:ff";
	card = new_card(&unknown);

	assert_int_equal(driver->ops->match_card(card), 0);
	free(card);
}

static void torture_pin_too_short(void **state)
{
	sc_card_driver_t *driver = sc_get_smartlog_driver();
	size_t i;

	(void) state;
	for (i = 0; i < sizeof(profiles) / sizeof(profiles[0]); i++) {
		sc_card_t *card = new_card(&profiles[i]);
		struct sc_pin_cmd_data data;
		u8 pin[] = "123"; /* shorter than every profile's minimum */

		memset(&data, 0, sizeof(data));
		data.cmd = SC_PIN_CMD_VERIFY;
		data.pin1.data = pin;
		data.pin1.len = strlen((char *) pin);

		assert_int_equal(driver->ops->pin_cmd(card, &data), SC_ERROR_INVALID_ARGUMENTS);
		free(card);
	}
}

static void torture_pin_too_long(void **state)
{
	sc_card_driver_t *driver = sc_get_smartlog_driver();
	size_t i;

	(void) state;
	for (i = 0; i < sizeof(profiles) / sizeof(profiles[0]); i++) {
		sc_card_t *card = new_card(&profiles[i]);
		struct sc_pin_cmd_data data;
		u8 pin[32];

		memset(pin, '9', sizeof(pin));
		memset(&data, 0, sizeof(data));
		data.cmd = SC_PIN_CMD_VERIFY;
		data.pin1.data = pin;
		data.pin1.len = profiles[i].pin_max + 1;

		assert_true(data.pin1.len <= sizeof(pin));
		assert_int_equal(driver->ops->pin_cmd(card, &data), SC_ERROR_INVALID_ARGUMENTS);
		free(card);
	}
}

static void torture_pin_numeric_only(void **state)
{
	sc_card_driver_t *driver = sc_get_smartlog_driver();
	size_t i;

	(void) state;
	/* every SmartLog profile requires an all-digit PIN */
	for (i = 0; i < sizeof(profiles) / sizeof(profiles[0]); i++) {
		sc_card_t *card = new_card(&profiles[i]);
		struct sc_pin_cmd_data data;
		u8 pin[] = "12a45678";

		memset(&data, 0, sizeof(data));
		data.cmd = SC_PIN_CMD_VERIFY;
		data.pin1.data = pin;
		data.pin1.len = strlen((char *) pin);

		if (data.pin1.len >= profiles[i].pin_min && data.pin1.len <= profiles[i].pin_max)
			assert_int_equal(driver->ops->pin_cmd(card, &data), SC_ERROR_INVALID_ARGUMENTS);
		free(card);
	}
}

static void torture_pin_null_arguments(void **state)
{
	sc_card_driver_t *driver = sc_get_smartlog_driver();
	struct profile profile = profiles[1];
	sc_card_t *card = new_card(&profile);

	(void) state;
	assert_int_equal(driver->ops->pin_cmd(card, NULL), SC_ERROR_INVALID_ARGUMENTS);
	free(card);
}

static void torture_pin_accepted_by_policy(void **state)
{
	size_t i;

	(void) state;
	for (i = 0; i < sizeof(profiles) / sizeof(profiles[0]); i++) {
		sc_card_t *card = new_card(&profiles[i]);
		struct sc_pin_cmd_data data;
		u8 pin[16];

		memset(pin, '7', sizeof(pin));
		memset(&data, 0, sizeof(data));
		data.cmd = SC_PIN_CMD_VERIFY;
		data.pin1.data = pin;
		/* a valid PIN has the minimum length of this profile */
		data.pin1.len = profiles[i].pin_min;

		assert_int_equal(smartlog_check_pin_policy(card, &data), SC_SUCCESS);
		free(card);
	}
}

static void torture_pinpad_skips_local_policy(void **state)
{
	struct profile profile = profiles[2];
	sc_card_t *card = new_card(&profile);
	struct sc_pin_cmd_data data;

	(void) state;
	memset(&data, 0, sizeof(data));
	data.cmd = SC_PIN_CMD_VERIFY;
	/* PIN-pad readers supply no PIN data: the length check must be skipped */
	data.pin1.data = NULL;
	data.pin1.len = 0;

	assert_int_equal(smartlog_check_pin_policy(card, &data), SC_SUCCESS);
	free(card);
}

static void torture_pin_policy_lookup(void **state)
{
	size_t i;

	(void) state;
	for (i = 0; i < sizeof(profiles) / sizeof(profiles[0]); i++) {
		const struct smartlog_pin_policy *policy =
			smartlog_get_pin_policy(profiles[i].card_type);

		assert_non_null(policy);
		assert_int_equal(policy->min_length, profiles[i].pin_min);
		assert_int_equal(policy->max_length, profiles[i].pin_max);
		assert_int_equal(policy->max_tries, profiles[i].max_tries);
	}
	assert_null(smartlog_get_pin_policy(SC_CARD_TYPE_UNKNOWN));
}

static void torture_emulator_wrong_card(void **state)
{
	sc_pkcs15_card_t *p15card = sc_pkcs15_card_new();

	(void) state;
	assert_non_null(p15card);

	assert_int_equal(sc_pkcs15emu_smartlog_init_ex(NULL, NULL), SC_ERROR_WRONG_CARD);

	p15card->card = NULL;
	assert_int_equal(sc_pkcs15emu_smartlog_init_ex(p15card, NULL), SC_ERROR_WRONG_CARD);

	sc_pkcs15_card_free(p15card);
}

static void torture_emulator_profiles(void **state)
{
	size_t i;

	(void) state;
	for (i = 0; i < sizeof(profiles) / sizeof(profiles[0]); i++) {
		sc_pkcs15_card_t *p15card = sc_pkcs15_card_new();
		sc_card_t *card = new_card(&profiles[i]);
		sc_pkcs15_object_t *objects[8] = {0};
		struct sc_pkcs15_auth_info *pin_info;
		int count;

		assert_non_null(p15card);
		p15card->card = card;
		card->serialnr.len = 4;
		memcpy(card->serialnr.value, "\x01\x02\x03\x04", 4);

		assert_int_equal(sc_pkcs15emu_smartlog_init_ex(p15card, NULL), SC_SUCCESS);

		assert_string_equal(p15card->tokeninfo->label, "SmartLog PKI card");
		assert_non_null(p15card->tokeninfo->serial_number);

		count = sc_pkcs15_get_objects(p15card, SC_PKCS15_TYPE_AUTH_PIN, objects, 8);
		assert_int_equal(count, 1);
		pin_info = (struct sc_pkcs15_auth_info *) objects[0]->data;
		assert_int_equal(pin_info->attrs.pin.min_length, profiles[i].pin_min);
		assert_int_equal(pin_info->attrs.pin.max_length, profiles[i].pin_max);
		assert_int_equal(pin_info->max_tries, profiles[i].max_tries);

		count = sc_pkcs15_get_objects(p15card, SC_PKCS15_TYPE_CERT_X509, objects, 8);
		assert_int_equal(count, 1);

		count = sc_pkcs15_get_objects(p15card, SC_PKCS15_TYPE_PRKEY_RSA, objects, 8);
		assert_int_equal(count, 1);

		sc_pkcs15_card_free(p15card);
		free(card);
	}
}

int main(void)
{
	const struct CMUnitTest tests[] = {
		cmocka_unit_test(torture_driver_registered),
		cmocka_unit_test_setup_teardown(torture_match_atr, setup_context, teardown_context),
		cmocka_unit_test_setup_teardown(torture_match_unknown_atr, setup_context, teardown_context),
		cmocka_unit_test_setup_teardown(torture_pin_too_short, setup_context, teardown_context),
		cmocka_unit_test_setup_teardown(torture_pin_too_long, setup_context, teardown_context),
		cmocka_unit_test_setup_teardown(torture_pin_numeric_only, setup_context, teardown_context),
		cmocka_unit_test_setup_teardown(torture_pin_null_arguments, setup_context, teardown_context),
		cmocka_unit_test_setup_teardown(torture_pin_accepted_by_policy, setup_context, teardown_context),
		cmocka_unit_test_setup_teardown(torture_pinpad_skips_local_policy, setup_context, teardown_context),
		cmocka_unit_test_setup_teardown(torture_pin_policy_lookup, setup_context, teardown_context),
		cmocka_unit_test(torture_emulator_wrong_card),
		cmocka_unit_test_setup_teardown(torture_emulator_profiles, setup_context, teardown_context),
	};

	return cmocka_run_group_tests(tests, NULL, NULL);
}
