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

#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <libgen.h>

#include "color.h"
#include "runner.h"
#include "fc_checks.h"
#include "if_checks.h"
#include "te_checks.h"
#include "parse_fc.h"
#include "parse.h"
#include "util.h"
#include "startup.h"

#define CHECK_ENABLED(cid) is_check_enabled(cid, config_enabled_checks, config_disabled_checks, cl_enabled_checks, cl_disabled_checks, only_enabled)

struct policy_node *parse_one_file(const char *filename, enum node_flavor flavor)
{

	char *copy = strdup(filename);
	char *mod_name = basename(copy);
	mod_name[strlen(mod_name) - 3] = '\0'; // Remove suffix
	set_current_module_name(mod_name);
	free(copy);

	FILE *f = fopen(filename, "r");
	if (!f) {
		printf("%sError%s: Failed to open %s: %s\n", color_error(), color_reset(), filename, strerror(errno));
		return NULL;
	}

	struct policy_node *ast = yyparse_wrapper(f, filename, flavor);
	fclose(f);

	// dont run cleanup_parsing until everything is done because it frees the maps
	return ast;
}

int is_check_enabled(const char *check_name,
                     const struct string_list *config_enabled_checks,
                     const struct string_list *config_disabled_checks,
                     const struct string_list *cl_enabled_checks,
                     const struct string_list *cl_disabled_checks,
                     int only_enabled)
{

	int is_enabled = check_name[0] == 'X' ? 0 : 1;     // default to enabled, except for extra checks

	if (only_enabled) {
		// if only_enabled is true, we only want to enable checks that are
		// explicitly enabled in the cl_enabled_checks. So change the default
		// enabled state to disabled, and skip all other checks except for the
		// enabled checks.
		is_enabled = 0;
	} else {
		if (str_in_sl(check_name, config_disabled_checks)) {
			is_enabled = 0;
		}

		if (str_in_sl(check_name, config_enabled_checks)) {
			is_enabled = 1;
		}

		if (str_in_sl(check_name, cl_disabled_checks)) {
			is_enabled = 0;
		}
	}

	if (str_in_sl(check_name, cl_enabled_checks)) {
		is_enabled = 1;
	}

	return is_enabled;
}

struct checks *register_checks(char level,
                               const struct string_list *config_enabled_checks,
                               const struct string_list *config_disabled_checks,
                               const struct string_list *cl_enabled_checks,
                               const struct string_list *cl_disabled_checks,
                               int only_enabled)
{

	struct checks *ck = malloc(sizeof(struct checks));

	memset(ck, 0, sizeof(struct checks));

	if (CHECK_ENABLED("X-001")) {
		add_check(NODE_INTERFACE_DEF, ck, "X-001",
			  check_unused_interface);
		add_check(NODE_TEMP_DEF, ck, "X-001",
			  check_unused_interface);
	}

	switch (level) {
	case 'C':
		if (CHECK_ENABLED("C-001")) {
			add_check(NODE_TE_FILE, ck, "C-001",
			          check_te_order);
			add_check(NODE_DECL, ck, "C-001",
			          check_te_order);
			add_check(NODE_AV_RULE, ck, "C-001",
			          check_te_order);
			add_check(NODE_XAV_RULE, ck, "C-001",
			          check_te_order);
			add_check(NODE_IF_CALL, ck, "C-001",
			          check_te_order);
			add_check(NODE_TT_RULE, ck, "C-001",
			          check_te_order);
			add_check(NODE_CLEANUP, ck, "C-001",
			          check_te_order);
		}
		if (CHECK_ENABLED("C-004")) {
			add_check(NODE_INTERFACE_DEF, ck, "C-004",
			          check_interface_definitions_have_comment);
			add_check(NODE_TEMP_DEF, ck, "C-004",
			          check_interface_definitions_have_comment);
		}
		if (CHECK_ENABLED("C-005")) {
			add_check(NODE_AV_RULE, ck, "C-005",
			          check_unordered_perms);
			add_check(NODE_XAV_RULE, ck, "C-005",
			          check_unordered_perms);
			add_check(NODE_DECL, ck, "C-005",
			          check_unordered_perms);
		}
		if (CHECK_ENABLED("C-006")) {
			add_check(NODE_REQUIRE, ck, "C-006",
			          check_unordered_declaration_in_require);
			add_check(NODE_GEN_REQ, ck, "C-006",
			          check_unordered_declaration_in_require);
		}
		if (CHECK_ENABLED("C-007")) {
			add_check(NODE_AV_RULE, ck, "C-007",
			          check_no_self);
			add_check(NODE_XAV_RULE, ck, "C-007",
			          check_no_self);
		}
		// FALLTHRU
	case 'S':
		if (CHECK_ENABLED("S-001")) {
			add_check(NODE_REQUIRE, ck, "S-001", check_require_block);
			add_check(NODE_GEN_REQ, ck, "S-001", check_require_block);
		}
		if (CHECK_ENABLED("S-002")) {
			add_check(NODE_FC_ENTRY, ck, "S-002",
			          check_file_context_types_in_mod);
		}
		if (CHECK_ENABLED("S-003")) {
			add_check(NODE_SEMICOLON, ck, "S-003",
			          check_useless_semicolon);
		}
		if (CHECK_ENABLED("S-004")) {
			add_check(NODE_IF_CALL, ck, "S-004",
			          check_if_calls_template);
		}
		if (CHECK_ENABLED("S-005")) {
			add_check(NODE_DECL, ck, "S-005",
			          check_decl_in_if);
		}
		if (CHECK_ENABLED("S-006")) {
			add_check(NODE_HEADER, ck, "S-006",
			          check_bare_module_statement);
		}
		if (CHECK_ENABLED("S-007")) {
			add_check(NODE_FC_ENTRY, ck, "S-007",
			          check_gen_context_no_range);
		}
		if (CHECK_ENABLED("S-008")) {
			add_check(NODE_GEN_REQ, ck, "S-008",
			          check_unquoted_gen_require_block);
		}
		if (CHECK_ENABLED("S-009")) {
			add_check(NODE_AV_RULE, ck, "S-009",
			          check_perm_macro_class_mismatch);
		}
		if (CHECK_ENABLED("S-010")) {
			add_check(NODE_AV_RULE, ck, "S-010",
			          check_perm_macro_available);
		}
		// FALLTHRU
	case 'W':
		if (CHECK_ENABLED("W-001")) {
			add_check(NODE_AV_RULE, ck, "W-001", check_no_explicit_declaration);
			add_check(NODE_XAV_RULE, ck, "W-001", check_no_explicit_declaration);
			add_check(NODE_IF_CALL, ck, "W-001", check_no_explicit_declaration);
			add_check(NODE_TT_RULE, ck, "W-001", check_no_explicit_declaration);
			add_check(NODE_RT_RULE, ck, "W-001", check_no_explicit_declaration);
			add_check(NODE_ROLE_ALLOW, ck, "W-001", check_no_explicit_declaration);
			add_check(NODE_ROLE_TYPES, ck, "W-001", check_no_explicit_declaration);
			add_check(NODE_ALIAS, ck, "W-001", check_no_explicit_declaration);
			add_check(NODE_TYPE_ALIAS, ck, "W-001", check_no_explicit_declaration);
			add_check(NODE_TYPE_ATTRIBUTE, ck, "W-001", check_no_explicit_declaration);
			add_check(NODE_ROLE_ATTRIBUTE, ck, "W-001", check_no_explicit_declaration);
			add_check(NODE_PERMISSIVE, ck, "W-001", check_no_explicit_declaration);
			add_check(NODE_DECL, ck, "W-001", check_no_explicit_declaration);
		}
		if (CHECK_ENABLED("W-002")) {
			add_check(NODE_AV_RULE, ck, "W-002", check_name_used_but_not_required_in_if);
			add_check(NODE_XAV_RULE, ck, "W-002", check_name_used_but_not_required_in_if);
			add_check(NODE_IF_CALL, ck, "W-002", check_name_used_but_not_required_in_if);
			add_check(NODE_TT_RULE, ck, "W-002", check_name_used_but_not_required_in_if);
			add_check(NODE_RT_RULE, ck, "W-002", check_name_used_but_not_required_in_if);
			add_check(NODE_ROLE_ALLOW, ck, "W-002", check_name_used_but_not_required_in_if);
			add_check(NODE_ROLE_TYPES, ck, "W-002", check_name_used_but_not_required_in_if);
			add_check(NODE_ALIAS, ck, "W-002", check_name_used_but_not_required_in_if);
			add_check(NODE_TYPE_ALIAS, ck, "W-002", check_name_used_but_not_required_in_if);
			add_check(NODE_TYPE_ATTRIBUTE, ck, "W-002", check_name_used_but_not_required_in_if);
			add_check(NODE_ROLE_ATTRIBUTE, ck, "W-002", check_name_used_but_not_required_in_if);
			add_check(NODE_PERMISSIVE, ck, "W-002", check_name_used_but_not_required_in_if);
			add_check(NODE_DECL, ck, "W-002", check_name_used_but_not_required_in_if);
		}
		if (CHECK_ENABLED("W-003")) {
			add_check(NODE_DECL, ck, "W-003",
			          check_name_required_but_not_used_in_if);
		}
		if (CHECK_ENABLED("W-004")) {
			add_check(NODE_FC_ENTRY, ck, "W-004", check_file_context_regex);
		}
		if (CHECK_ENABLED("W-005")) {
			add_check(NODE_IF_CALL, ck, "W-005",
			          check_module_if_call_in_optional);
		}
		if (CHECK_ENABLED("W-006")) {
			add_check(NODE_IF_CALL, ck, "W-006",
			          check_empty_if_call_arg);
		}
		if (CHECK_ENABLED("W-007")) {
			add_check(NODE_IF_CALL, ck, "W-007",
			          check_space_if_call_arg);
		}
		if (CHECK_ENABLED("W-008")) {
			add_check(NODE_AV_RULE, ck, "W-008",
			          check_risky_allow_perm);
		}
		if (CHECK_ENABLED("W-009")) {
			add_check(NODE_HEADER, ck, "W-009",
			          check_module_file_name_mismatch);
		}
		if (CHECK_ENABLED("W-010")) {
			add_check(NODE_IF_CALL, ck, "W-010",
				  check_unknown_interface_call);
		}
		if (CHECK_ENABLED("W-011")) {
			add_check(NODE_DECL, ck, "W-011",
				  check_required_declaration_own);
		}
		// FALLTHRU
	case 'E':
		if (CHECK_ENABLED("E-002")) {
			add_check(NODE_ERROR, ck, "E-002",
			          check_file_context_error_nodes);
		}
		if (CHECK_ENABLED("E-003")) {
			add_check(NODE_FC_ENTRY, ck, "E-003", check_file_context_users);
		}
		if (CHECK_ENABLED("E-004")) {
			add_check(NODE_FC_ENTRY, ck, "E-004", check_file_context_roles);
		}
		if (CHECK_ENABLED("E-005")) {
			add_check(NODE_FC_ENTRY, ck, "E-005",
			          check_file_context_types_exist);
		}
		if (CHECK_ENABLED("E-006")) {
			add_check(NODE_DECL, ck, "E-006",
				check_declaration_interface_nameclash);
		}
		if (CHECK_ENABLED("E-007") && check_unknown_permission_condition()) {
			add_check(NODE_AV_RULE, ck, "E-007",
				  check_unknown_permission);
		}
		if (CHECK_ENABLED("E-008") && check_unknown_class_condition()) {
			add_check(NODE_AV_RULE, ck, "E-008", check_unknown_class);
			add_check(NODE_RT_RULE, ck, "E-008", check_unknown_class);
			add_check(NODE_TT_RULE, ck, "E-008", check_unknown_class);
		}
		if (CHECK_ENABLED("E-009")) {
			add_check(NODE_OPTIONAL_POLICY, ck, "E-009", check_empty_block);
			add_check(NODE_GEN_REQ, ck, "E-009", check_empty_block);
			add_check(NODE_REQUIRE, ck, "E-009", check_empty_block);
		}
		if (CHECK_ENABLED("E-010")) {
			add_check(NODE_M4_SIMPLE_MACRO, ck, "E-010",
				  check_stray_word);
		}
	case 'F':
		break;
	default:
		free(ck);
		return NULL;
	}

	return ck;
}

enum selint_error parse_all_files_in_list(struct policy_file_list *files, enum node_flavor flavor)
{

	struct policy_file_node *current = files->head;

	while (current) {
		print_if_verbose("Parsing %s\n", current->file->filename);
		current->file->ast = parse_one_file(current->file->filename, flavor);
		if (!current->file->ast) {
			return SELINT_PARSE_ERROR;
		}
		current = current->next;
	}

	return SELINT_SUCCESS;

}

enum selint_error parse_all_fc_files_in_list(struct policy_file_list *files,
                                             const struct string_list *custom_fc_macros)
{

	struct policy_file_node *current = files->head;

	while (current) {
		print_if_verbose("Parsing fc file %s\n", current->file->filename);
		current->file->ast = parse_fc_file(current->file->filename, custom_fc_macros);
		if (!current->file->ast) {
			return SELINT_PARSE_ERROR;
		}
		current = current->next;
	}

	return SELINT_SUCCESS;
}

enum selint_error run_checks_on_one_file(struct checks *ck,
                                         const struct check_data *data,
                                         const struct policy_node *head)
{
	const struct policy_node *current = head;

	while (current) {
		enum selint_error res = call_checks(ck, data, current);
		if (res != SELINT_SUCCESS) {
			return res;
		}

		current = dfs_next(current);
	}

	// Give checks a change to clean up state
	struct policy_node cleanup;
	memset(&cleanup, 0, sizeof(struct policy_node));
	cleanup.flavor = NODE_CLEANUP;

	return call_checks(ck, data, &cleanup);
}

enum selint_error run_all_checks(struct checks *ck, enum file_flavor flavor,
                                 struct policy_file_list *files,
                                 const struct config_check_data *ccd)
{

	struct policy_file_node *file = files->head;

	struct check_data data;

	data.flavor = flavor;

	while (file) {
		{
			char *copy = strdup(file->file->filename);
			data.filename = strdup(basename(copy));
			free(copy);
		}
		data.mod_name = strdup(data.filename);
		data.config_check_data = ccd;

		char *suffix_ptr = strrchr(data.mod_name, '.');

		*suffix_ptr = '\0';

		enum selint_error res =
			run_checks_on_one_file(ck, &data, file->file->ast);
		if (res != SELINT_SUCCESS) {
			return res;
		}

		free(data.filename);
		free(data.mod_name);

		file = file->next;

	}

	return SELINT_SUCCESS;
}

enum selint_error run_analysis(struct checks *ck,
                               struct policy_file_list *te_files,
                               struct policy_file_list *if_files,
                               struct policy_file_list *fc_files,
                               struct policy_file_list *context_te_files,
                               struct policy_file_list *context_if_files,
                               const struct string_list *custom_fc_macros,
                               const struct config_check_data *ccd)
{

	enum selint_error res;

	res = parse_all_files_in_list(if_files, NODE_IF_FILE);
	if (res != SELINT_SUCCESS) {
		goto out;
	}

	// We parse all the context files for the side effects of parsing (populating
	// the hash tables), and to mark the transform interfaces.  Then we only
	// run checks on the non-context files
	res = parse_all_files_in_list(context_if_files, NODE_IF_FILE);
	if (res != SELINT_SUCCESS) {
		goto out;
	}

	// Make temporary joined list to mark ALL transform interfaces
	struct policy_file_list *all_if_files = calloc(1, sizeof(struct policy_file_list));
	if (if_files->tail) {
		// Only concatenate if if_files contains files
		all_if_files->head = if_files->head;
		if_files->tail->next = context_if_files->head;
	} else {
		// If both are empty, just having an empty list is fine
		all_if_files->head = context_if_files->head;
	}

	all_if_files->tail = context_if_files->tail;

	mark_transform_interfaces(all_if_files);

	// Restore
	if (if_files->tail) {
		if_files->tail->next = NULL;
	}
	free(all_if_files);

	res = parse_all_files_in_list(context_te_files, NODE_TE_FILE);
	if (res != SELINT_SUCCESS) {
		goto out;
	}

	res = parse_all_files_in_list(te_files, NODE_TE_FILE);
	if (res != SELINT_SUCCESS) {
		goto out;
	}

	res = parse_all_fc_files_in_list(fc_files, custom_fc_macros);
	if (res != SELINT_SUCCESS) {
		goto out;
	}

	res = run_all_checks(ck, FILE_TE_FILE, te_files, ccd);
	if (res != SELINT_SUCCESS) {
		goto out;
	}

	res = run_all_checks(ck, FILE_IF_FILE, if_files, ccd);
	if (res != SELINT_SUCCESS) {
		goto out;
	}

	res = run_all_checks(ck, FILE_FC_FILE, fc_files, ccd);
	if (res != SELINT_SUCCESS) {
		goto out;
	}

out:
	cleanup_parsing();

	return res;
}

void display_run_summary(const struct checks *ck)
{
	printf("Found the following issue counts:\n");
	display_check_issue_counts(ck);
}
