/*
* Copyright 2019 Tresys Technology, LLC
*
* Licensed under the Apache License, Version 2.0 (the "License");
* you may not use this file except in compliance with the License.
* You may obtain a copy of the License at
*
*    http://www.apache.org/licenses/LICENSE-2.0
*
* Unless required by applicable law or agreed to in writing, software
* distributed under the License is distributed on an "AS IS" BASIS,
* WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
* See the License for the specific language governing permissions and
* limitations under the License.
*/

#include <check.h>
#include <stdlib.h>

#include "../src/check_hooks.h"

int check_called;
int check2_called;

struct check_result * example_check(const struct check_data *check_data, const struct policy_node *node);
struct check_result * example_check2(const struct check_data *check_data, const struct policy_node *node);
struct check_result * returns_blank_result(const struct check_data *check_data, const struct policy_node *node);

struct check_result * example_check(__attribute__((unused)) const struct check_data *check_data,
				  __attribute__((unused)) const struct policy_node *node) {
	check_called = 1;
	return (struct check_result *) NULL;
}

struct check_result * example_check2(__attribute__((unused)) const struct check_data *check_data,
				  __attribute__((unused)) const struct policy_node *node) {
	check2_called = 1;
	return (struct check_result *) NULL;
}

struct check_result * returns_blank_result(__attribute__((unused)) const struct check_data *check_data,
                                        __attribute__((unused)) const struct policy_node *node) {
	return calloc(1, sizeof(struct check_result));
}

START_TEST (test_add_check) {
	struct checks *ck = calloc(1, sizeof(struct checks));

	check_called = 0;

	ck_assert_int_eq(SELINT_SUCCESS, add_check(NODE_AV_RULE, ck, "E-999", example_check));

	ck_assert_ptr_nonnull(ck->check_nodes[NODE_AV_RULE]);
	ck_assert_ptr_null(ck->check_nodes[NODE_FC_ENTRY]);
	ck_assert_ptr_null(ck->check_nodes[NODE_ERROR]);

	ck_assert_int_eq(SELINT_SUCCESS, add_check(NODE_TT_RULE, ck, "E-999", example_check));

	ck_assert_ptr_nonnull(ck->check_nodes[NODE_AV_RULE]);
	ck_assert_ptr_nonnull(ck->check_nodes[NODE_TT_RULE]);
	ck_assert_ptr_null(ck->check_nodes[NODE_FC_ENTRY]);
	ck_assert_ptr_null(ck->check_nodes[NODE_ERROR]);

	ck_assert_int_eq(SELINT_SUCCESS, add_check(NODE_DECL, ck, "E-999", example_check));
	ck_assert_int_eq(SELINT_SUCCESS, add_check(NODE_INTERFACE_DEF, ck, "E-999", example_check));
	ck_assert_int_eq(SELINT_SUCCESS, add_check(NODE_TEMP_DEF, ck, "E-999", example_check));
	ck_assert_int_eq(SELINT_SUCCESS, add_check(NODE_IF_CALL, ck, "E-999", example_check));

	ck_assert_ptr_nonnull(ck->check_nodes[NODE_DECL]);
	ck_assert_ptr_nonnull(ck->check_nodes[NODE_INTERFACE_DEF]);
	ck_assert_ptr_nonnull(ck->check_nodes[NODE_TEMP_DEF]);
	ck_assert_ptr_nonnull(ck->check_nodes[NODE_IF_CALL]);
	ck_assert_ptr_null(ck->check_nodes[NODE_FC_ENTRY]);
	ck_assert_ptr_null(ck->check_nodes[NODE_ERROR]);

	ck_assert_int_eq(SELINT_SUCCESS, add_check(NODE_FC_ENTRY, ck, "E-999", example_check));

	ck_assert_ptr_nonnull(ck->check_nodes[NODE_AV_RULE]);
	ck_assert_ptr_nonnull(ck->check_nodes[NODE_FC_ENTRY]);
	ck_assert_ptr_null(ck->check_nodes[NODE_ERROR]);

	ck_assert_ptr_eq(ck->check_nodes[NODE_FC_ENTRY]->check_function, example_check);

	ck_assert_int_eq(SELINT_SUCCESS, add_check(NODE_ERROR, ck, "E-999", example_check));
	ck_assert_ptr_nonnull(ck->check_nodes[NODE_ERROR]);

	ck_assert_int_eq(0, check_called);

	free_checks(ck);

}
END_TEST

START_TEST (test_call_checks) {
	struct checks *ck = malloc(sizeof(struct checks));
	memset(ck, 0, sizeof(struct checks));

	check_called = 0;
	check2_called = 0;
	ck_assert_int_eq(SELINT_SUCCESS, add_check(NODE_AV_RULE, ck, "E-999", example_check));

	struct policy_node *node = calloc(1, sizeof(struct policy_node));
	node->flavor = NODE_AV_RULE;

	ck_assert_int_eq(SELINT_SUCCESS, call_checks(ck, NULL, node));

	ck_assert_int_eq(1, check_called);
	ck_assert_int_eq(0, check2_called);

	check_called = 0;
	ck_assert_int_eq(SELINT_SUCCESS, add_check(NODE_AV_RULE, ck, "E-999", example_check2));

	ck_assert_int_eq(SELINT_SUCCESS, call_checks(ck, NULL, node));

	ck_assert_int_eq(0, ck->check_nodes[NODE_AV_RULE]->issues_found);
	ck_assert_int_eq(0, ck->check_nodes[NODE_AV_RULE]->next->issues_found);

	ck_assert_int_eq(1, check_called);
	ck_assert_int_eq(1, check2_called);

	node->flavor = NODE_TT_RULE;
	check_called = 0;
	check2_called = 0;

	ck_assert_int_eq(SELINT_SUCCESS, call_checks(ck, NULL, node));

	ck_assert_int_eq(0, ck->check_nodes[NODE_AV_RULE]->issues_found);
	ck_assert_int_eq(0, ck->check_nodes[NODE_AV_RULE]->next->issues_found);

	ck_assert_int_eq(0, check_called);
	ck_assert_int_eq(0, check2_called);

	free_policy_node(node);
	free_checks(ck);

}
END_TEST

START_TEST (test_disable_check) {
	struct checks *ck = calloc(1, sizeof(struct checks));

	check_called = 0;
	ck_assert_int_eq(SELINT_SUCCESS, add_check(NODE_AV_RULE, ck, "E-999", example_check));

	struct policy_node *node = calloc(1, sizeof(struct policy_node));
	node->flavor = NODE_AV_RULE;

	ck_assert_int_eq(SELINT_SUCCESS, call_checks(ck, NULL, node));
	ck_assert_int_eq(1, check_called);

	check_called = 0;

	node->exceptions = strdup("E-999\n");

	ck_assert_int_eq(SELINT_SUCCESS, call_checks(ck, NULL, node));
	ck_assert_int_eq(0, check_called);

	free_policy_node(node);
	free_checks(ck);

}
END_TEST

START_TEST (test_is_valid_check) {
	ck_assert_int_eq(1, is_valid_check("W-001"));
	ck_assert_int_eq(1, is_valid_check("W-005"));
	ck_assert_int_eq(0, is_valid_check("W-107"));
	ck_assert_int_eq(0, is_valid_check("foobar"));
	ck_assert_int_eq(1, is_valid_check("C-001"));
	ck_assert_int_eq(1, is_valid_check("S-001"));
	ck_assert_int_eq(1, is_valid_check("E-001"));
	ck_assert_int_eq(1, is_valid_check("F-001"));
	ck_assert_int_eq(0, is_valid_check("Y-001"));
	ck_assert_int_eq(0, is_valid_check("C-101"));
}
END_TEST

START_TEST (test_increment_issues) {
	struct checks *ck = calloc(1, sizeof(struct checks));
	ck_assert_int_eq(SELINT_SUCCESS, add_check(NODE_AV_RULE, ck, "E-999", returns_blank_result));

	struct check_data *data = calloc(1, sizeof(struct check_data));
	data->filename = strdup("example.te");

	ck_assert_int_eq(0, ck->check_nodes[NODE_AV_RULE]->issues_found);

	struct policy_node *node = calloc(1, sizeof(struct policy_node));
	node->flavor = NODE_AV_RULE;

	ck_assert_int_eq(SELINT_SUCCESS, call_checks(ck, data, node));
	ck_assert_int_eq(1, ck->check_nodes[NODE_AV_RULE]->issues_found);

	ck_assert_int_eq(SELINT_SUCCESS, call_checks(ck, data, node));
	ck_assert_int_eq(2, ck->check_nodes[NODE_AV_RULE]->issues_found);

	free_policy_node(node);
	free(data->filename);
	free(data);
	free_checks(ck);
}
END_TEST

static Suite *check_hooks_suite(void) {
	Suite *s;
	TCase *tc_core;

	s = suite_create("Check_hooks");

	tc_core = tcase_create("Core");

	tcase_add_test(tc_core, test_add_check);
	tcase_add_test(tc_core, test_call_checks);
	tcase_add_test(tc_core, test_disable_check);
	tcase_add_test(tc_core, test_is_valid_check);
	tcase_add_test(tc_core, test_increment_issues);
	suite_add_tcase(s, tc_core);

	return s;
}

int main(void) {

	int number_failed = 0;
	Suite *s;
	SRunner *sr;

	s = check_hooks_suite();
	sr = srunner_create(s);
	srunner_run_all(sr, CK_NORMAL);
	number_failed = srunner_ntests_failed(sr);
	srunner_free(sr);

	return (number_failed == 0)? 0 : -1;
}
