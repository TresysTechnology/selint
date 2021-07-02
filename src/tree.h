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

#ifndef TREE_H
#define TREE_H

#include "selint_error.h"
#include "string_list.h"

enum node_flavor {
	NODE_TE_FILE,
	NODE_IF_FILE,
	NODE_FC_FILE,
	NODE_SPT_FILE,
	NODE_AV_FILE,
	NODE_COND_FILE,
	NODE_AV_RULE,
	NODE_XAV_RULE,
	NODE_TT_RULE,
	NODE_RT_RULE,
	NODE_HEADER,
	NODE_ROLE_ALLOW,
	NODE_ROLE_TYPES,
	NODE_DECL,
	NODE_ALIAS,
	NODE_TYPE_ALIAS,
	NODE_TYPE_ATTRIBUTE,
	NODE_ROLE_ATTRIBUTE,
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
	NODE_IF_CALL,
	NODE_REQUIRE,
	NODE_GEN_REQ,
	NODE_PERMISSIVE,
	NODE_FC_ENTRY,
	NODE_COMMENT,
	NODE_EMPTY,
	NODE_SEMICOLON,         // A semicolon that is not needed to close the previous line
	NODE_CLEANUP,           // Called after each file parsing is complete so that checks
	                        // that register on this node have a way to clean up state
	NODE_ERROR              // When a parsing error occurs, save an error node in the tree
	                        // NODE_ERROR must be the last item in the node_flavor enum
	                        // as check_hooks.c assumes it when allocating an array of
	                        // length equal to the number of node types
};

enum header_flavor {
	HEADER_BARE,
	HEADER_MACRO
};

enum av_rule_flavor {
	AV_RULE_ALLOW,
	AV_RULE_AUDITALLOW,
	AV_RULE_DONTAUDIT,
	AV_RULE_NEVERALLOW
};

enum decl_flavor {
	DECL_TYPE,
	DECL_ATTRIBUTE,
	DECL_ATTRIBUTE_ROLE,
	DECL_ROLE,
	DECL_USER,
	DECL_CLASS,
	DECL_PERM,
	DECL_BOOL
};

enum attr_flavor {
	ATTR_TYPE,
	ATTR_ROLE
};

enum tt_flavor {
	TT_TT,
	TT_TM,
	TT_TC,
	TT_RT
};

struct header_data {
	enum header_flavor flavor;
	char *module_name;
};

#define AV_RULE_MEMBERS \
	enum av_rule_flavor flavor;\
	struct string_list *sources;\
	struct string_list *targets;\
	struct string_list *object_classes;\
	struct string_list *perms;

struct av_rule_data {
	AV_RULE_MEMBERS;
};

struct xav_rule_data {
	AV_RULE_MEMBERS;
	// All xav_rule specific members MUST go after AV_RULE ones
	char *operation;
};

struct role_allow_data {
	struct string_list *from;
	struct string_list *to;
};

struct role_types_data {
	char *role;
	struct string_list *types;
};

struct type_transition_data {
	struct string_list *sources;
	struct string_list *targets;
	struct string_list *object_classes;
	char *default_type;
	char *name;
	enum tt_flavor flavor;
};

struct role_transition_data {
	struct string_list *sources;
	struct string_list *targets;
	struct string_list *object_classes;
	char *default_role;
};

struct if_call_data {
	char *name;
	struct string_list *args;
};

struct if_call_list {
	struct if_call_data *call;
	struct if_call_list *next;
};

struct declaration_data {
	enum decl_flavor flavor;
	char *name;
	struct string_list *attrs;
};

struct decl_list {
	struct declaration_data *decl;
	struct decl_list *next;
};

struct sel_context {
	int has_gen_context;    // 1 if context is wrapped in gen_context, 0 if not
	char *user;
	char *role;
	char *type;
	char *range;
};

struct fc_entry {
	char *path;
	char obj;
	struct sel_context *context;
};

struct attribute_data {
	char *type;
	struct string_list *attrs;
	enum attr_flavor flavor;
};

struct gen_require_data {
	unsigned char unquoted;
};

struct cond_declaration_data {
	struct string_list *identifiers;
};

union node_data {
	struct header_data *h_data;
	struct av_rule_data *av_data;
	struct xav_rule_data *xav_data;
	struct role_allow_data *ra_data;
	struct role_types_data *rtyp_data;
	struct type_transition_data *tt_data;
	struct role_transition_data *rt_data;
	struct if_call_data *ic_data;
	struct declaration_data *d_data;
	struct fc_entry *fc_data;
	struct attribute_data *at_data;
	struct gen_require_data *gr_data;
	struct cond_declaration_data *cd_data;
	char *str;
};

struct policy_node {
	struct policy_node *parent;
	struct policy_node *next;
	struct policy_node *prev;
	struct policy_node *first_child;
	enum node_flavor flavor;
	union node_data data;
	char *exceptions;
	unsigned int lineno;
};

enum selint_error insert_policy_node_child(struct policy_node *parent,
                                           enum node_flavor flavor, union node_data data,
                                           unsigned int lineno);

enum selint_error insert_policy_node_next(struct policy_node *prev,
                                          enum node_flavor flavor, union node_data data,
                                          unsigned int lineno);

// Returns 1 if the node is a template call, and 0 if not
int is_template_call(const struct policy_node *node);

const char *get_name_if_in_template(const struct policy_node *cur);

struct string_list *get_names_in_node(const struct policy_node *node);

struct string_list *get_names_required(const struct policy_node *node);

const char *decl_flavor_to_string(enum decl_flavor flavor);

/**********************************
* Return 1 if the node is in a require block
* and 0 otherwise
**********************************/
int is_in_require(const struct policy_node *cur);

//Return the next node in a depth first search of the tree
struct policy_node *dfs_next(const struct policy_node *node);

enum selint_error free_policy_node(struct policy_node *to_free);

enum selint_error free_header_data(struct header_data *to_free);

enum selint_error free_av_rule_data(struct av_rule_data *to_free);

enum selint_error free_xav_rule_data(struct xav_rule_data *to_free);

enum selint_error free_ra_data(struct role_allow_data *to_free);

enum selint_error free_rtyp_data(struct role_types_data *to_free);

enum selint_error free_type_transition_data(struct type_transition_data
                                            *to_free);

enum selint_error free_role_transition_data(struct role_transition_data
                                            *to_free);

enum selint_error free_if_call_data(struct if_call_data *to_free);

enum selint_error free_declaration_data(struct declaration_data *to_free);

enum selint_error free_decl_list(struct decl_list *to_free);

// Only free the list, not what it's pointing to
enum selint_error free_if_call_list(struct if_call_list *to_free);

void free_fc_entry(struct fc_entry *to_free);

void free_sel_context(struct sel_context *to_free);

void free_attribute_data(struct attribute_data *to_free);

void free_gen_require_data(struct gen_require_data *to_free);

void free_cond_declaration_data(struct cond_declaration_data *to_free);

#endif
