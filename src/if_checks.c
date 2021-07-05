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

#include <stddef.h>
#include <stdlib.h>
#include <string.h>

#include "if_checks.h"
#include "tree.h"
#include "maps.h"
#include "util.h"

#define NOT_REQ_MESSAGE "%s %s is used in interface but not required"

struct check_result *check_unused_interface(__attribute__((unused)) const struct
                                            check_data *data,
                                            const struct
                                            policy_node *node)
{
	if (node->flavor != NODE_INTERFACE_DEF && node->flavor != NODE_TEMP_DEF) {
		return alloc_internal_error(
			"Unused interface check called on non interface definition entry");
	}

	const char *if_name = node->data.str;

	if (is_used_if(if_name)) {
		return NULL;
	}

	return make_check_result('X', X_ID_UNUSED_IF, "Interface %s is unused", if_name);
}

struct check_result *check_interface_definitions_have_comment(__attribute__((unused)) const struct
                                                              check_data *data,
                                                              const struct
                                                              policy_node *node)
{
	if (node->flavor != NODE_INTERFACE_DEF && node->flavor != NODE_TEMP_DEF) {
		return alloc_internal_error(
			"Interface comment check called on non interface definition entry");
	}

	if (!(node->prev) || node->prev->flavor != NODE_COMMENT) {
		return make_check_result('C', C_ID_IF_COMMENT,
		                         "No comment before interface definition for %s",
		                         node->data.str);

	} else {
		return NULL;
	}
}

static int compare_declaration_flavors(enum decl_flavor a, enum decl_flavor b, const struct config_check_data *config)
{
	if (a == b) {
		return 0;
	}

	for (unsigned short i = 0; i < (sizeof config->order_requires / sizeof *config->order_requires); ++i) {
		if (a == config->order_requires[i]) {
			return -1;
		}
		if (b == config->order_requires[i]) {
			return 1;
		}
	}

	// should never happen
	return 0;
}

static int compare_declarations(const struct declaration_data *a, const struct declaration_data *b, const struct config_check_data *config)
{
	int r = compare_declaration_flavors(a->flavor, b->flavor, config);
	if (r != 0) {
		return r;
	}

	if (!config->ordering_requires_same_flavor) {
		// ordering names of the same flavor is disabled in the config file
		return -1;
	}

	// ignore _t suffix, e.g. sort ssh_t before ssh_exec_t
	const char *a_ptr = a->name;
	const char *b_ptr = b->name;
	while (*a_ptr && *b_ptr) {
		if ((unsigned char)*a_ptr != (unsigned char)*b_ptr) {
			break;
		}

		++a_ptr;
		++b_ptr;
	}

	if (*a_ptr == 't' && !*(a_ptr + 1) && a_ptr != a->name && *(a_ptr - 1) == '_') {
		--a_ptr;
	}

	if (*b_ptr == 't' && !*(b_ptr + 1) && b_ptr != b->name && *(b_ptr - 1) == '_') {
		--b_ptr;
	}

	return (unsigned char)*a_ptr - (unsigned char)*b_ptr;
}

struct check_result *check_unordered_declaration_in_require(const struct
                                                            check_data *data,
                                                            const struct
                                                            policy_node *node)
{
	if (node->flavor != NODE_REQUIRE && node->flavor != NODE_GEN_REQ) {
		return alloc_internal_error(
			"Unordered declaration in require check called on non require node");
	}

	const struct policy_node *child = node->first_child;
	if (!child || child->flavor != NODE_START_BLOCK) {
		return alloc_internal_error(
			"No start-block node in require block");
	}

	child = child->next;
	if (!child) {
		return make_check_result('C', C_ID_UNORDERED_REQ,
					 "Empty require block");
	}

	const struct declaration_data *prev_decl_data = NULL;
	for (const struct policy_node *cur = child; cur; cur = cur->next) {
		if (cur->flavor != NODE_DECL) {
			return alloc_internal_error(
				"Non declaration node in require block");
		}

		const struct declaration_data *decl_data = cur->data.d_data;

		if (prev_decl_data) {
			const int compare = compare_declarations(prev_decl_data, decl_data, data->config_check_data);

			if (compare > 0) {
				return make_check_result('C', C_ID_UNORDERED_REQ,
							 "Unordered declaration in require block (%s %s before %s %s)",
							 decl_flavor_to_string(prev_decl_data->flavor),
							 prev_decl_data->name,
							 decl_flavor_to_string(decl_data->flavor),
							 decl_data->name);
			}

			if (compare == 0) {
				return make_check_result('C', C_ID_UNORDERED_REQ,
							 "Repeated declaration in require block (%s %s)",
							 decl_flavor_to_string(decl_data->flavor),
							 decl_data->name);
			}
		}

		prev_decl_data = decl_data;
	}

	return NULL;
}

struct check_result *check_if_calls_template(const struct
                                             check_data *data,
                                             const struct
                                             policy_node *node)
{
	if (data->flavor != FILE_IF_FILE) {
		return NULL;
	}

	const struct policy_node *parent = node->parent;
	while (parent &&
	       (parent->flavor != NODE_INTERFACE_DEF && parent->flavor != NODE_TEMP_DEF)) {
		parent = parent->parent;
	}

	if (!parent) {
		return NULL;
	}

	const char *call_name = node->data.ic_data->name;

	if (parent->flavor == NODE_INTERFACE_DEF && look_up_in_template_map(call_name)) {
		return make_check_result('S',
					 S_ID_IF_CALLS_TEMPL,
					 "interface %s calls template %s",
					 parent->data.str,
					 call_name);
	}

	return NULL;
}

struct check_result *check_decl_in_if(const struct
                                      check_data *data,
                                      const struct
                                      policy_node *node)
{
	if (data->flavor != FILE_IF_FILE) {
		return NULL;
	}

	const struct policy_node *parent = node->parent;
	while (parent &&
	       (parent->flavor != NODE_INTERFACE_DEF && parent->flavor != NODE_TEMP_DEF)) {
		// ignore declarations in require blocks
		if (parent->flavor == NODE_GEN_REQ || parent->flavor == NODE_REQUIRE) {
			return NULL;
		}

		parent = parent->parent;
	}

	// only check interfaces
	if (!parent || parent->flavor != NODE_INTERFACE_DEF) {
		return NULL;
	}

	return make_check_result('S',
				 S_ID_DECL_IN_IF,
				 "Declaration of %s in interface",
				 node->data.d_data->name);
}

struct check_result *check_unquoted_gen_require_block(__attribute__((unused)) const struct
                                                      check_data *data,
                                                      const struct
                                                      policy_node *node)
{
	if (node->data.gr_data->unquoted) {
		return make_check_result('S', S_ID_UNQUOTE_GENREQ,
					 "Gen require block unquoted");
	}

	return NULL;
}

struct check_result *check_name_used_but_not_required_in_if(const struct
                                                            check_data *data,
                                                            const struct
                                                            policy_node *node)
{
	if (data->flavor != FILE_IF_FILE) {
		return NULL;
	}

	const struct policy_node *cur = node;

	struct string_list *names_in_current_node = get_names_in_node(node);

	if (!names_in_current_node) {
		return NULL;
	}

	while (cur) {
		if (cur->flavor == NODE_INTERFACE_DEF || cur->flavor == NODE_TEMP_DEF) {
			break;
		}
		cur = cur->parent;
	}

	if (!cur) {
		free_string_list(names_in_current_node);
		return NULL;
	}
	// In a template or interface, and cur is a pointer to the definition node

	cur = cur->first_child;

	struct string_list *names_required = NULL;
	struct string_list *names_required_tail = NULL;

	while (cur && cur != node) {
	       if (cur->flavor == NODE_GEN_REQ
	           || cur->flavor == NODE_REQUIRE) {
			if (!names_required) {
				names_required = get_names_required(cur);
				names_required_tail = names_required;
			} else {
				names_required_tail->next = get_names_required(cur);
			}
			while (names_required_tail && names_required_tail->next) {
				names_required_tail = names_required_tail->next;
			}
		}

		cur = dfs_next(cur); // The normal case is that the gen_require block
		                     // is at the top level, but it could be nested,
		                     // for example in an ifdef
	}

	const struct string_list *name_node = names_in_current_node;
	/* In declarations skip the first name, which is the new declared type */
	if (node->flavor == NODE_DECL) {
		name_node = name_node->next;
	}
	const char *flavor = NULL;

	while (name_node) {
		if (!str_in_sl(name_node->string, names_required)) {
			if (0 == strcmp(name_node->string, "system_r")) {
				// system_r is required by default in all modules
				// so that is an exception that shouldn't be warned
				// about.
				name_node = name_node->next;
				continue;
			}
			if (look_up_in_decl_map(name_node->string, DECL_TYPE)) {
				flavor = "Type";
			} else
			if (look_up_in_decl_map
			            (name_node->string, DECL_ATTRIBUTE)) {
				flavor = "Attribute";
			} else
			if (look_up_in_decl_map
			            (name_node->string, DECL_ATTRIBUTE_ROLE)) {
				flavor = "Role Attribute";
			} else
			if (look_up_in_decl_map
			            (name_node->string, DECL_ROLE)) {
				flavor = "Role";
			} else {
				// This is a string we don't recognize.  Other checks and/or
				// the compiler catch invalid bare words
				name_node = name_node->next;
				continue;
			}

			struct check_result *res =
				make_check_result('W', W_ID_NO_REQ, NOT_REQ_MESSAGE,
				                  flavor, name_node->string);
			free_string_list(names_in_current_node);
			free_string_list(names_required);
			return res;
		}
		name_node = name_node->next;
	}

	free_string_list(names_in_current_node);
	free_string_list(names_required);

	return NULL;
}

struct check_result *check_name_required_but_not_used_in_if(const struct
                                                            check_data *data,
                                                            const struct
                                                            policy_node *node)
{
	if (data->flavor != FILE_IF_FILE) {
		return NULL;
	}

	struct declaration_data *dd = node->data.d_data;

	const char *flavor = "";

	if (dd->flavor == DECL_TYPE) {
		flavor = "Type";
	} else if (dd->flavor == DECL_ATTRIBUTE) {
		flavor = "Attribute";
	} else if (dd->flavor == DECL_ATTRIBUTE_ROLE) {
		flavor = "Role Attribute";
	} else if (dd->flavor == DECL_ROLE) {
		flavor = "Role";
	} else {
		return NULL;
	}

	const struct policy_node *cur = node;
	const struct policy_node *req_block_node = NULL;
	while (cur->parent && cur->flavor != NODE_INTERFACE_DEF
	       && cur->flavor != NODE_TEMP_DEF) {
		if (cur->flavor == NODE_GEN_REQ || cur->flavor == NODE_REQUIRE) {
			req_block_node = cur;
		}
		cur = cur->parent;
	}

	if ((cur->flavor != NODE_INTERFACE_DEF && cur->flavor != NODE_TEMP_DEF)
	    || !req_block_node) {
		// This check only applies to nodes in require blocks in interfaces
		return NULL;
	}

	// ignore interfaces with the ending '_stub'; used in Refpolicy as optional block decider
	if (cur->flavor == NODE_INTERFACE_DEF &&
	    ends_with(cur->data.str, strlen(cur->data.str), "_stub", strlen("_stub"))) {
		return NULL;
	}

	struct string_list *names_to_check = get_names_in_node(node);
	if (!names_to_check) {
		// This should never happen
		return alloc_internal_error(
			"Declaration with no declared items");
	}

	cur = req_block_node;

	cur = cur->next;

	struct string_list *sl_end = NULL;
	struct string_list *sl_head = NULL;

	int depth = 0;

	while (cur) {
		struct string_list *names_used = get_names_in_node(cur);
		if (names_used) {
			if (!sl_head) {
				sl_head = sl_end = names_used;
			} else {
				sl_end->next = names_used;
			}

			while (sl_end->next) {
				sl_end = sl_end->next;
			}
		}

		if (cur->first_child) {
			cur = cur->first_child;
			depth++;
		} else if (cur->next) {
			cur = cur->next;
		} else {
			while (cur->parent && depth > 0) {
				cur = cur->parent;
				depth--;
				if (cur->next) {
					break;
				}
			}
			cur = cur->next;
		}
	}

	const struct string_list *name_node = names_to_check;

	struct check_result *res = NULL;

	while (name_node) {
		if (!str_in_sl(name_node->string, sl_head)) {
			res = make_check_result('W',
			                        W_ID_UNUSED_REQ,
			                        "%s %s is listed in require block but not used in interface",
			                        flavor,
			                        name_node->string);
			break;
		}
		name_node = name_node->next;
	}

	free_string_list(sl_head);
	free_string_list(names_to_check);
	return res;
}

struct check_result *check_required_declaration_own(const struct
                                                    check_data *data,
                                                    const struct
                                                    policy_node *node)
{
	if (data->flavor != FILE_IF_FILE) {
		return NULL;
	}

	const char *name = node->data.d_data->name;
	const enum decl_flavor flavor = node->data.d_data->flavor;

	// ignore class, permission and user declarations
	if (flavor == DECL_CLASS || flavor == DECL_PERM || flavor == DECL_USER) {
		return NULL;
	}

	// TODO: handle templated declarations
	if (name[0] == '$') {
		return NULL;
	}

	// only check declarations in require blocks
	if (!is_in_require(node)) {
		return NULL;
	}

	const char *modname_orig_decl = look_up_in_decl_map(name, flavor);
	if (!modname_orig_decl) {
		return make_check_result('W',
			                 W_ID_IF_DECL_NOT_OWN,
			                 "Definition of declared %s %s not found in any module",
			                 decl_flavor_to_string(flavor),
			                 name);
	}

	if (0 == strcmp(modname_orig_decl, data->mod_name)) {
		return NULL;
	}

	// ignore roles declared in kernel module: common in refpolicy
	if (flavor == DECL_ROLE && 0 == strcmp(modname_orig_decl, "kernel")) {
		return NULL;
	}

	return make_check_result('W',
			         W_ID_IF_DECL_NOT_OWN,
			         "Definition of declared %s %s not found in own module, but in module %s",
			         decl_flavor_to_string(flavor),
			         name,
			         modname_orig_decl);
}
