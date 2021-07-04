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

#include "tree.h"
#include "maps.h"
#include "selint_error.h"

enum selint_error insert_policy_node_child(struct policy_node *parent,
                                           enum node_flavor flavor,
                                           union node_data data, unsigned int lineno)
{

	if (parent == NULL) {
		return SELINT_BAD_ARG;
	}

	struct policy_node *to_insert = malloc(sizeof(struct policy_node));
	if (!to_insert) {
		return SELINT_OUT_OF_MEM;
	}

	to_insert->parent = parent;
	to_insert->next = NULL;
	to_insert->first_child = NULL;
	to_insert->flavor = flavor;
	to_insert->data = data;
	to_insert->exceptions = NULL;
	to_insert->lineno = lineno;

	if (parent->first_child == NULL) {
		parent->first_child = to_insert;
		to_insert->prev = NULL;
	} else {

		struct policy_node *cur = parent->first_child;

		while (cur->next != NULL) {
			cur = cur->next;
		}

		cur->next = to_insert;
		to_insert->prev = cur;

	}

	return SELINT_SUCCESS;
}

enum selint_error insert_policy_node_next(struct policy_node *prev,
                                          enum node_flavor flavor,
                                          union node_data data, unsigned int lineno)
{

	if (prev == NULL) {
		return SELINT_BAD_ARG;
	}

	struct policy_node *to_insert = malloc(sizeof(struct policy_node));
	if (!to_insert) {
		return SELINT_OUT_OF_MEM;
	}

	prev->next = to_insert;

	to_insert->parent = prev->parent;
	to_insert->next = NULL;
	to_insert->first_child = NULL;
	to_insert->flavor = flavor;
	to_insert->data = data;
	to_insert->prev = prev;
	to_insert->exceptions = NULL;
	to_insert->lineno = lineno;

	return SELINT_SUCCESS;
}

int is_template_call(const struct policy_node *node)
{
	if (node == NULL || node->data.ic_data == NULL) {
		return 0;
	}

	if (node->flavor != NODE_IF_CALL) {
		return 0;
	}

	char *call_name = node->data.ic_data->name;

	if (look_up_in_template_map(call_name)) {
		return 1;
	}
	return 0;
}

const char *get_name_if_in_template(const struct policy_node *cur)
{
	while (cur->parent) {
		cur = cur->parent;
		if (cur->flavor == NODE_TEMP_DEF) {
			return cur->data.str;
		}
	}
	return NULL;
}

const char *decl_flavor_to_string(enum decl_flavor flavor)
{
	switch (flavor) {
	case DECL_TYPE:
		return "type";
	case DECL_ATTRIBUTE:
		return "attribute";
	case DECL_ATTRIBUTE_ROLE:
		return "attribute role";
	case DECL_ROLE:
		return "role";
	case DECL_USER:
		return "user";
	case DECL_CLASS:
		return "class";
	case DECL_PERM:
		return "permission";
	case DECL_BOOL:
		return "boolean";
	default:
		return "unknown";
	}
}

struct string_list *get_names_in_node(const struct policy_node *node)
{

	struct string_list *ret = NULL;
	struct string_list *cur = NULL;
	struct av_rule_data *av_data;
	struct type_transition_data *tt_data;
	struct role_transition_data *rt_data;
	struct declaration_data *d_data;
	struct if_call_data *ifc_data;
	struct role_allow_data *ra_data;
	struct role_types_data *rtyp_data;
	struct attribute_data *at_data;

	switch (node->flavor) {
	case NODE_AV_RULE:
	case NODE_XAV_RULE:
		// Since the common elements are ordered identically, we can just look
		// at the common subset for the XAV rule
		av_data = node->data.av_data;
		cur = ret = copy_string_list(av_data->sources);
		if (cur) {
			while (cur->next) {
				cur = cur->next;
			}
			cur->next = copy_string_list(av_data->targets);
		} else {
			ret = copy_string_list(av_data->targets);
		}
		break;

	case NODE_TT_RULE:
		tt_data = node->data.tt_data;
		cur = ret = copy_string_list(tt_data->sources);
		if (cur) {
			while (cur->next) {
				cur = cur->next;
			}
			cur->next = copy_string_list(tt_data->targets);
		} else {
			cur = ret = copy_string_list(tt_data->targets);
		}
		if (cur) {
			while (cur->next) {
				cur = cur->next;
			}
			cur->next = sl_from_str(tt_data->default_type);
		} else {
			cur = ret = sl_from_str(tt_data->default_type);
		}
		break;

	case NODE_RT_RULE:
		rt_data = node->data.rt_data;
		cur = ret = copy_string_list(rt_data->sources);
		if (cur) {
			while (cur->next) {
				cur = cur->next;
			}
			cur->next = copy_string_list(rt_data->targets);
		} else {
			cur = ret = copy_string_list(rt_data->targets);
		}
		if (cur) {
			while (cur->next) {
				cur = cur->next;
			}
			cur->next = sl_from_str(rt_data->default_role);
		} else {
			cur = ret = sl_from_str(rt_data->default_role);
		}
		break;

	case NODE_DECL:
		d_data = node->data.d_data;
		ret = sl_from_str(d_data->name);
		ret->next = copy_string_list(d_data->attrs);
		break;

	case NODE_IF_CALL:
		ifc_data = node->data.ic_data;
		ret = copy_string_list(ifc_data->args);
		break;

	case NODE_ROLE_ALLOW:
		ra_data = node->data.ra_data;
		cur = ret = copy_string_list(ra_data->from);
		while (cur->next) {
			cur = cur->next;
		}
		cur->next = copy_string_list(ra_data->to);
		break;

	case NODE_ROLE_TYPES:
		rtyp_data = node->data.rtyp_data;
		ret = sl_from_str(rtyp_data->role);
		ret->next = copy_string_list(rtyp_data->types);
		break;

	case NODE_TYPE_ATTRIBUTE:
	case NODE_ROLE_ATTRIBUTE:
		at_data = node->data.at_data;
		ret = sl_from_str(at_data->type);
		ret->next = copy_string_list(at_data->attrs);
		break;

	case NODE_ALIAS:
	case NODE_TYPE_ALIAS:
	case NODE_PERMISSIVE:
		ret = sl_from_str(node->data.str);
		break;

	/*
	   NODE_TE_FILE,
	   NODE_IF_FILE,
	   NODE_FC_FILE,
	   NODE_SPT_FILE,
	   NODE_AV_FILE,
	   NODE_COND_FILE,
	   NODE_HEADER,
	   NODE_M4_CALL,
	   NODE_M4_SIMPLE_MACRO,
	   NODE_DEFINE,
	   NODE_OPTIONAL_POLICY,
	   NODE_OPTIONAL_ELSE,
	   NODE_BOOLEAN_POLICY,
	   NODE_TUNABLE_POLICY,
	   NODE_IFDEF,
	   NODE_IFELSE,
	   NODE_M4_ARG,
	   NODE_START_BLOCK,
	   NODE_INTERFACE_DEF,
	   NODE_TEMP_DEF,
	   NODE_REQUIRE,
	   NODE_GEN_REQ,
	   NODE_FC_ENTRY,
	   NODE_COMMENT,
	   NODE_EMPTY,
	   NODE_SEMICOLON,
	   NODE_CLEANUP,
	   NODE_ERROR
	 */
	default:
		break;
	}

	// Check if any of the types are exclusions
	cur = ret;
	while (cur) {
		if (cur->string[0] == '-') {
			// memmove is safe for overlapping strings
			// Length is strlen exactly because it doesn't copy the first
			// character, but does copy the null terminator
			memmove(cur->string, cur->string + 1, strlen(cur->string));
		}
		cur = cur->next;
	}

	return ret;
}

struct string_list *get_names_required(const struct policy_node *node)
{
	struct string_list *ret = NULL;
	struct string_list *ret_cursor = NULL;

	struct policy_node *cur = node->first_child;

	while (cur) {
		if (ret_cursor) {
			ret_cursor->next = get_names_in_node(cur);
		} else {
			ret = ret_cursor = get_names_in_node(cur);
		}
		while (ret_cursor && ret_cursor->next) {
			ret_cursor = ret_cursor->next;
		}

		cur = cur->next;
	}

	return ret;
}

int is_in_require(const struct policy_node *cur)
{
	while (cur->parent) {
		cur = cur->parent;
		if (cur->flavor == NODE_GEN_REQ || cur->flavor == NODE_REQUIRE) {
			return 1;
		}
	}
	return 0;
}

struct policy_node *dfs_next(const struct policy_node *node)
{
	if (node->first_child) {
		return node->first_child;
	} else if (node->next) {
		return node->next;
	} else {
		while (node->parent && !node->parent->next) {
			node = node->parent;
		}
		if (node->parent) {
			return node->parent->next;
		} else {
			return NULL;
		}
	}
}

enum selint_error free_policy_node(struct policy_node *to_free)
{
	if (to_free == NULL) {
		return SELINT_BAD_ARG;
	}

	switch (to_free->flavor) {
	case NODE_HEADER:
		free_header_data(to_free->data.h_data);
		break;
	case NODE_AV_RULE:
		free_av_rule_data(to_free->data.av_data);
		break;
	case NODE_XAV_RULE:
		free_xav_rule_data(to_free->data.xav_data);
		break;
	case NODE_ROLE_ALLOW:
		free_ra_data(to_free->data.ra_data);
		break;
	case NODE_ROLE_TYPES:
		free_rtyp_data(to_free->data.rtyp_data);
		break;
	case NODE_TT_RULE:
		free_type_transition_data(to_free->data.tt_data);
		break;
	case NODE_RT_RULE:
		free_role_transition_data(to_free->data.rt_data);
		break;
	case NODE_IF_CALL:
		free_if_call_data(to_free->data.ic_data);
		break;
	case NODE_DECL:
		free_declaration_data(to_free->data.d_data);
		break;
	case NODE_FC_ENTRY:
		free_fc_entry(to_free->data.fc_data);
		break;
	case NODE_TYPE_ATTRIBUTE:
	case NODE_ROLE_ATTRIBUTE:
		free_attribute_data(to_free->data.at_data);
		break;
	case NODE_GEN_REQ:
		free_gen_require_data(to_free->data.gr_data);
		break;
	case NODE_BOOLEAN_POLICY:
	case NODE_TUNABLE_POLICY:
		free_cond_declaration_data(to_free->data.cd_data);
		break;
	default:
		if (to_free->data.str != NULL) {
			free(to_free->data.str);
		}
		break;
	}

	free(to_free->exceptions);
	to_free->exceptions = NULL;

	free_policy_node(to_free->first_child);
	to_free->first_child = NULL;

	free_policy_node(to_free->next);
	to_free->next = NULL;

	to_free->prev = NULL;

	free(to_free);

	return SELINT_SUCCESS;
}

enum selint_error free_header_data(struct header_data *to_free)
{

	if (to_free == NULL) {
		return SELINT_BAD_ARG;
	}

	free(to_free->module_name);

	free(to_free);

	return SELINT_SUCCESS;
}

enum selint_error free_av_rule_data(struct av_rule_data *to_free)
{

	if (to_free == NULL) {
		return SELINT_BAD_ARG;
	}

	free_string_list(to_free->sources);
	free_string_list(to_free->targets);
	free_string_list(to_free->object_classes);
	free_string_list(to_free->perms);

	free(to_free);

	return SELINT_SUCCESS;
}

enum selint_error free_xav_rule_data(struct xav_rule_data *to_free)
{

	if (to_free == NULL) {
		return SELINT_BAD_ARG;
	}

	free_string_list(to_free->sources);
	free_string_list(to_free->targets);
	free_string_list(to_free->object_classes);
	free(to_free->operation);
	free_string_list(to_free->perms);

	free(to_free);

	return SELINT_SUCCESS;
}

enum selint_error free_ra_data(struct role_allow_data *to_free)
{

	if (to_free == NULL) {
		return SELINT_BAD_ARG;
	}

	free_string_list(to_free->from);
	free_string_list(to_free->to);
	free(to_free);

	return SELINT_SUCCESS;
}

enum selint_error free_rtyp_data(struct role_types_data *to_free)
{

	if (to_free == NULL) {
		return SELINT_BAD_ARG;
	}

	free(to_free->role);
	free_string_list(to_free->types);
	free(to_free);

	return SELINT_SUCCESS;
}

enum selint_error free_type_transition_data(struct type_transition_data
                                            *to_free)
{

	if (to_free == NULL) {
		return SELINT_BAD_ARG;
	}

	free_string_list(to_free->sources);
	free_string_list(to_free->targets);
	free_string_list(to_free->object_classes);
	free(to_free->default_type);
	free(to_free->name);

	free(to_free);

	return SELINT_SUCCESS;
}

enum selint_error free_role_transition_data(struct role_transition_data
                                            *to_free)
{
	if (to_free == NULL) {
		return SELINT_BAD_ARG;
	}

	free_string_list(to_free->sources);
	free_string_list(to_free->targets);
	free_string_list(to_free->object_classes);
	free(to_free->default_role);

	free(to_free);

	return SELINT_SUCCESS;
}

enum selint_error free_if_call_data(struct if_call_data *to_free)
{

	if (to_free == NULL) {
		return SELINT_BAD_ARG;
	}

	free(to_free->name);
	free_string_list(to_free->args);

	free(to_free);

	return SELINT_SUCCESS;
}

enum selint_error free_declaration_data(struct declaration_data *to_free)
{
	if (to_free == NULL) {
		return SELINT_BAD_ARG;
	}

	free_string_list(to_free->attrs);
	free(to_free->name);

	free(to_free);

	return SELINT_SUCCESS;
}

enum selint_error free_decl_list(struct decl_list *to_free)
{

	while (to_free) {
		free_declaration_data(to_free->decl);
		struct decl_list *tmp = to_free;
		to_free = to_free->next;
		free(tmp);
	}
	return SELINT_SUCCESS;
}

// The if call data structs in an if call list are pointers to data that is freed elsewhere
enum selint_error free_if_call_list(struct if_call_list *to_free)
{

	while (to_free) {
		struct if_call_list *tmp = to_free;
		to_free = to_free->next;
		free(tmp);
	}
	return SELINT_SUCCESS;
}

void free_fc_entry(struct fc_entry *to_free)
{
	if (to_free->path) {
		free(to_free->path);
	}
	if (to_free->context) {
		free_sel_context(to_free->context);
	}
	free(to_free);
}

void free_sel_context(struct sel_context *to_free)
{
	if (to_free->user) {
		free(to_free->user);
	}
	if (to_free->role) {
		free(to_free->role);
	}
	if (to_free->type) {
		free(to_free->type);
	}
	if (to_free->range) {
		free(to_free->range);
	}
	free(to_free);
}

void free_attribute_data(struct attribute_data *to_free)
{
	if (to_free->type) {
		free(to_free->type);
	}
	if (to_free->attrs) {
		free_string_list(to_free->attrs);
	}
	free(to_free);
}

void free_gen_require_data(struct gen_require_data *to_free)
{
	free(to_free);
}

void free_cond_declaration_data(struct cond_declaration_data *to_free)
{
	free_string_list(to_free->identifiers);
	free(to_free);
}
