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

#include <ctype.h>
#include <stdio.h>

#include "color.h"
#include "te_checks.h"
#include "maps.h"
#include "tree.h"
#include "ordering.h"
#include "util.h"
#include "perm_macro.h"

struct check_result *check_te_order(const struct check_data *data,
                                    const struct policy_node *node)
{
	if (!data || !data->config_check_data) {
		return alloc_internal_error("Uninitialized data given to C-001");
	}
	if (data->flavor != FILE_TE_FILE) {
		return NULL;
	}

	static struct ordering_metadata *order_data;
	static unsigned int order_node_arr_index;

	switch (node->flavor) {
	case NODE_TE_FILE:
		order_data = prepare_ordering_metadata(data, node);
		order_node_arr_index = 0;
		if (!order_data) {
			return alloc_internal_error("Failed to initialize ordering for C-001");
		}
		switch (data->config_check_data->order_conf) {
		case ORDER_REF:
			calculate_longest_increasing_subsequence(node, order_data, compare_nodes_refpolicy);
			break;
		case ORDER_LIGHT:
			calculate_longest_increasing_subsequence(node, order_data, compare_nodes_refpolicy_light);
			break;
		case ORDER_LAX:
			calculate_longest_increasing_subsequence(node, order_data, compare_nodes_refpolicy_lax);
			break;
		default:
			return alloc_internal_error("Unknown ordering configuration given to C-001");
		}
		break;
	case NODE_CLEANUP:
		free_ordering_metadata(order_data);
		order_data = NULL;
		break;
	default:
		if (!order_data) {
			return alloc_internal_error("Ordering data was not generated for C-001");
		}
		for (unsigned int i=order_node_arr_index; i < order_data->order_node_len; i++) {
			if (order_data->nodes[i].node == node) {
				order_node_arr_index = i;
				if (order_data->nodes[i].in_order) {
					return NULL;
				} else {
					char *reason_str = get_ordering_reason(order_data, order_node_arr_index, data->config_check_data->order_conf);
					if (!reason_str) {
						return alloc_internal_error("Failed to compute reason C-001");
					}

					struct check_result *to_ret = make_check_result('C',
					                                                C_ID_TE_ORDER,
					                                                "%s",
					                                                reason_str);
					free(reason_str);
					return to_ret;
				}
			}
		}
		return alloc_internal_error("Could not find ordering info for line");
	}
	return NULL;
}

struct check_result *check_unordered_perms(__attribute__((unused)) const struct check_data *data,
                                           const struct policy_node *node)
{
	const struct string_list *prev = NULL, *cur = NULL;
	const char *flavor;
	if (node->flavor == NODE_AV_RULE) {
		cur = node->data.av_data->perms;
		flavor = "av rule";
	} else if (node->flavor == NODE_XAV_RULE) {
		cur = node->data.xav_data->perms;
		flavor = "xav rule";
	} else if (node->flavor == NODE_DECL) {
		// ignore non-class declarations
		if (node->data.d_data->flavor != DECL_CLASS) {
			return NULL;
		}
		cur = node->data.d_data->attrs;
		flavor = "class declaration";
	} else {
		return alloc_internal_error("Invalid node type for `check_unordered_perms`");
	}

	while (cur) {
		if (prev && strcmp(prev->string, "~") != 0 && strcmp(cur->string, "-") != 0) {
			const int compare = strcmp(prev->string, cur->string);

			if (compare > 0) {
				return make_check_result('C', C_ID_UNORDERED_PERM,
			                                 "Permissions in %s not ordered (%s before %s)",
			                                 flavor,
			                                 prev->string,
			                                 cur->string);
			} else if (compare == 0) {
				return make_check_result('C', C_ID_UNORDERED_PERM,
			                                 "Permissions in %s repeated (%s)",
			                                 flavor,
			                                 cur->string);
			}
		}

		prev = cur;
		cur = cur->next;
	}

	return NULL;

}

struct check_result *check_no_self(__attribute__((unused)) const struct check_data *data,
                                   const struct policy_node *node)
{
	if (node->flavor != NODE_AV_RULE && node->flavor != NODE_XAV_RULE) {
		return alloc_internal_error("Bad node type given to check C-007");
	}
	struct av_rule_data *av_data = node->data.av_data;

	if (av_data->sources->next ||
	    av_data->targets->next ||
	    0 == strcmp(av_data->targets->string, "self") ||
	    0 != strcmp(av_data->sources->string, av_data->targets->string)) {
		return NULL;
	}

	if (av_data->sources->string[0] == '$') {
		// On variables, we skip unless they are "_t" suffixed
		if (!ends_with(av_data->sources->string, strlen(av_data->sources->string), "_t", 2)) {
			return NULL;
		}
	} else if (!look_up_in_decl_map(av_data->sources->string, DECL_TYPE)) {
		// skip attributes
		return NULL;
	}

	return make_check_result('C', C_ID_SELF,
	                         "Recommend use of self keyword instead of redundant type");

}

struct check_result *check_foreign_cond_id(const struct check_data
                                           *data,
                                           const struct policy_node
                                           *node)
{
	if (node->flavor != NODE_BOOLEAN_POLICY && node->flavor != NODE_TUNABLE_POLICY) {
		return alloc_internal_error("Invalid node type for `check_foreign_cond_id`");
	}

	const struct string_list *identifiers = node->data.cd_data->identifiers;

	for (const struct string_list *ids = identifiers; ids; ids = ids->next) {
		const char *id = ids->string;

		const char *mod_name = look_up_in_decl_map(id, DECL_BOOL);

		/* Ignore non-existent identifiers, covered by W-012 */
		if (mod_name == NULL) {
			continue;
		}

		if (0 == strcmp(mod_name, data->mod_name)) {
			continue;
		}

		if (0 == strcmp(mod_name, "__global__")) {
			continue;
		}

		return make_check_result('C', C_ID_FOREIGN_CONDID,
		                         "Identifier %s in expression for conditional block not found in own module, but in module %s (candidate for global declaration or interface)",
		                         id,
		                         mod_name);
        }

	return NULL;
}

struct check_result *check_require_block(const struct check_data *data,
                                         const struct policy_node *node)
{
	if (data->flavor != FILE_TE_FILE) {
		return NULL;
	}

	struct policy_node *cur = node->first_child;
	while (cur) {
		if (cur->flavor != NODE_DECL) {
			cur = cur->next;
			continue;
		}
		if (cur->data.d_data->flavor != DECL_CLASS &&
		    cur->data.d_data->flavor != DECL_PERM) {
			return make_check_result('S', S_ID_REQUIRE,
			                         "Require block used in te file (use an interface call instead)");
		}
		cur = cur->next;
	}
	// Require contained only object classes and permissions
	return NULL;
}

struct check_result *check_useless_semicolon(__attribute__((unused)) const struct check_data *data,
                                             __attribute__((unused)) const struct policy_node *node)
{
	return make_check_result('S', S_ID_SEMICOLON,
	                         "Unnecessary semicolon");
}

struct check_result *check_bare_module_statement(__attribute__((unused)) const struct check_data *data,
                                                 const struct policy_node *node)
{
	if (node->data.h_data->flavor == HEADER_BARE) {
		return make_check_result('S', S_ID_BARE_MODULE,
	                                 "Bare module statement (use `policy_module()` instead)");
	}

	return NULL;
}

// check if all classes are netlink socket classes
static bool all_netlink_socket_classes(const struct string_list *classes)
{
	for (; classes; classes = classes->next) {
		if (0 != strncmp(classes->string, "netlink_", strlen("netlink_"))) {
			return false;
		}
	}

	return true;
}

// check if all classes are socket classes
static bool all_socket_classes(const struct string_list *classes)
{
	for (; classes; classes = classes->next) {
		if (!ends_with(classes->string, strlen(classes->string), "_socket", strlen("_socket"))) {
			return false;
		}
	}

	return true;
}

// check if '$STR' ends with '$SUFFIX_perms'
static bool ends_with_suffix_perms(const char *str, size_t str_len, const char *suffix, size_t suffix_len)
{
	if (str_len < (suffix_len + strlen("_perms"))) {
		return 0;
	}

	// no need to check last 6 characters are actual '_perms'
	// we call this only on strings we have checked to have this suffix
	return (0 == strncmp(str + str_len - (suffix_len + strlen("_perms")),
			     suffix,
			     suffix_len));
}
static bool ends_with_all_suffix_perms(const char *str, size_t str_len, const struct string_list *classes)
{
	for (; classes; classes = classes->next) {
		if (!ends_with_suffix_perms(str, str_len, classes->string, strlen(classes->string))) {
			// check class alias as fallback
			static const char *const class_aliases[][2] = {
				{ "chr_file", "term"   },
				{ "process",  "signal" },
			};
			const char *class_alias = NULL;
			for (size_t i = 0; i < (sizeof class_aliases / sizeof *class_aliases); ++i) {
				if (0 == strcmp(classes->string, class_aliases[i][0])) {
					class_alias = class_aliases[i][1];
					break;
				}
			}
			if (!class_alias || !ends_with_suffix_perms(str, str_len, class_alias, strlen(class_alias))) {
				return false;
			}
		}
	}

	return true;
}

struct check_result *check_perm_macro_class_mismatch(__attribute__((unused)) const struct check_data *data,
                                                     const struct policy_node *node)
{
	static const char *const file_suffix_classes[] = {
		"lnk_file",
		"chr_file",
		"blk_file",
		"sock_file",
		"fifo_file",
	};

	const struct string_list *classes = node->data.av_data->object_classes;

	// ignore class set av rules
	if (ends_with(classes->string, strlen(classes->string), "_class_set", strlen("_class_set"))) {
		return NULL;
	}

	const bool is_file_class = str_in_sl("file", classes);
	const bool is_netlink_socket_class = all_netlink_socket_classes(classes);
	const bool is_socket_class = all_socket_classes(classes);

	for (const struct string_list *perms = node->data.av_data->perms; perms; perms = perms->next) {
		const size_t perm_len = strlen(perms->string);

		// ignore permissions without '_perms' suffix; they are probably not macros
		if (!ends_with(perms->string, perm_len, "_perms", strlen("_perms"))) {
			continue;
		}

		// ignore permissions matching 'something[_something]_$CLASSNAME_perms'
		// and 'something[_something]_$CLASSNAMEALIAS_perms'
		if (ends_with_all_suffix_perms(perms->string, perm_len, classes)) {
			// report usage of macros matching different class with actual class as suffix
			// e.g. report 'something_fifo_file_perms' for class 'file'
			if (is_file_class) {
				for (size_t i = 0; i < (sizeof file_suffix_classes / sizeof *file_suffix_classes); ++i) {
					if (ends_with_suffix_perms(perms->string, perm_len, file_suffix_classes[i], strlen(file_suffix_classes[i]))) {
						goto report;
					}
				}
			}
			continue;
		}

		// ignore permissions 'something[_something]_netlink_socket_perms' for netlink classes
		if (is_netlink_socket_class &&
		    ends_with(perms->string, perm_len, "_socket_perms", strlen("_socket_perms"))) {
			continue;
		}

		// ignore permissions 'something[_something]_socket_perms' for (non-netlink) socket classes
		if (is_socket_class &&
		    !is_netlink_socket_class &&
		    ends_with(perms->string, perm_len, "_socket_perms", strlen("_socket_perms")) &&
		    !ends_with(perms->string, perm_len, "netlink_socket_perms", strlen("netlink_socket_perms"))) {
			continue;
		}

report:
		return make_check_result('S', S_ID_PERM_SUFFIX,
					 "Permission macro %s does not match class %s",
					 perms->string,
					 classes->next ? "(multi class av rule)" : classes->string);
	}

	return NULL;
}

struct check_result *check_perm_macro_available(__attribute__((unused)) const struct check_data *data,
                                                const struct policy_node *node)
{
	// ignore non allow rules
	if (node->data.av_data->flavor != AV_RULE_ALLOW) {
		return NULL;
	}

	// ignore multi class av rules
	const struct string_list *class = node->data.av_data->object_classes;
	if (class->next ||
	    ends_with(class->string, strlen(class->string), "_class_set", strlen("_class_set"))) {
		return NULL;
	}

	char *check_str = permmacro_check(node->data.av_data->object_classes->string,
					  node->data.av_data->perms);
	if (!check_str) {
		return NULL;
	}

	struct check_result *res = make_check_result('S', S_ID_PERMMACRO,
						     "%s",
						     check_str);
	free(check_str);
	return res;
}

// Helper for check_no_explicit_declaration.  Returns 1 is there is a require block
// for name earlier in the file, and 0 otherwise
static int has_require(const struct policy_node *node, const char *name, enum decl_flavor flavor)
{
	const struct policy_node *cur = node;
	while (cur) {
		if (cur->flavor == NODE_REQUIRE || cur->flavor == NODE_GEN_REQ) {
			cur = cur->first_child;
			while (1) {
				if (cur->flavor == NODE_DECL && cur->data.d_data->flavor == flavor) {
					if (0 == strcmp(name, cur->data.d_data->name)) {
						return 1;
					}
					struct string_list *other_types = cur->data.d_data->attrs; // In requires these
					                                                           // are types, not
					                                                           // attributes
					while (other_types) {
						if (0 == strcmp(name, other_types->string)) {
							return 1;
						}
						other_types = other_types->next;
					}
				}
				if (cur->next) {
					cur = cur->next;
				} else {
					break;
				}
			}
			// Not found in this require block, keep going
			cur = cur->parent;
			if (!cur) {
				break;
			}
		}
		if (cur->prev) {
			cur = cur->prev;
		} else {
			cur = cur->parent;
		}
	}
	return 0;
}


struct check_result *check_no_explicit_declaration(const struct check_data *data,
                                                   const struct policy_node *node)
{
	if (data->flavor != FILE_TE_FILE) {
		return NULL;
	}

	struct string_list *names = get_names_in_node(node);

	for (const struct string_list *name = names; name; name = name->next) {
		const char *mod_name;
		enum decl_flavor flavor;

		if ((mod_name = look_up_in_decl_map(name->string, DECL_TYPE))) {
			flavor = DECL_TYPE;
		} else if ((mod_name = look_up_in_decl_map(name->string, DECL_ATTRIBUTE))) {
			flavor = DECL_ATTRIBUTE;
		} else if ((mod_name = look_up_in_decl_map(name->string, DECL_ATTRIBUTE_ROLE))) {
			flavor = DECL_ATTRIBUTE_ROLE;
		// Do not check for roles: in refpolicy they are defined in the kernel module
		// and used in role modules (like unprivuser)
		} else {
			//Not a known name
			continue;
		}

		if (0 != strcmp(data->mod_name, mod_name)) {
			// It may be required
			if (!has_require(node, name->string, flavor)) {
				// We didn't find a require block with this name
				struct check_result *to_ret = make_check_result('W', W_ID_NO_EXPLICIT_DECL,
										"No explicit declaration for %s from module %s.  You should access it via interface call or use a require block.",
										name->string, mod_name);
				free_string_list(names);
				return to_ret;
			}
			// Otherwise, keep checking other names in this node
		}
	}

	free_string_list(names);
	return NULL;
}

struct check_result *check_module_if_call_in_optional(const struct check_data
                                                      *data,
                                                      const struct policy_node
                                                      *node)
{

	const struct if_call_data *if_data = node->data.ic_data;

	const char *if_mod_name = look_up_in_ifs_map(if_data->name);

	if (!if_mod_name) {
		// Not defined as an interface.  Probably a macro
		return NULL;
	}

	if (0 == strcmp(if_mod_name, data->mod_name)) {
		// No issue calling interfaces in your own module
		return NULL;
	}

	const char *mod_type = look_up_in_mods_map(if_mod_name);

	if (!mod_type) {
		// If mod_type is NULL, we have no info on this module.  We *should* have info
		// on all modules of type module, but in some cases may be missing ones that are
		// off or base.  Off and base pass the check.
		return NULL;
	}

	if (0 == strcmp(mod_type, "base")) {
		// No issue calling interfaces in base module
		return NULL;
	}

	const struct policy_node *tmp = node;

	while (tmp->parent) {
		tmp = tmp->parent;
		if (tmp->flavor == NODE_OPTIONAL_POLICY) {
			return NULL;
		}
	}

	return make_check_result('W', W_ID_IF_CALL_OPTIONAL,
	                         "Call to interface %s defined in module %s should be in optional_policy block",
	                         if_data->name,
	                         if_mod_name);
}

struct check_result *check_empty_if_call_arg(__attribute__((unused)) const struct
                                             check_data *data,
                                             const struct
                                             policy_node *node)
{
	if (!node->data.ic_data->args) {
		return make_check_result('W',
					 W_ID_EMPTY_IF_CALL_ARG,
					 "Call to interface %s with empty argument",
					 node->data.ic_data->name);
	}

	return NULL;
}

struct check_result *check_space_if_call_arg(__attribute__((unused)) const struct
                                             check_data *data,
                                             const struct
                                             policy_node *node)
{
	const struct string_list *prev = NULL, *args = node->data.ic_data->args;
	unsigned short i = 1;

	while (args) {
		if (args->has_incorrect_space) {
			// do not issue on mls ranges
			if (prev &&
			    (args->string[0] != '-' ||
			    look_up_in_decl_map(prev->string, DECL_TYPE) ||
			    look_up_in_decl_map(prev->string, DECL_ATTRIBUTE) ||
			    look_up_in_decl_map(prev->string, DECL_ROLE) ||
			    look_up_in_decl_map(prev->string, DECL_ATTRIBUTE_ROLE) ||
			    look_up_in_decl_map(prev->string, DECL_USER))) {

				return make_check_result('W',
							 W_ID_SPACE_IF_CALL_ARG,
							 "Argument no. %u '%s ...' of call to interface %s contains unquoted space",
							 i - 1, // need to subtract one, cause it is the next string who has the flag set
							 prev->string,
							 node->data.ic_data->name);
			}
		} else {
			i++;
		}

		prev = args;
		args = args->next;
	}

	return NULL;
}

struct check_result *check_risky_allow_perm(__attribute__((unused)) const struct
                                            check_data *data,
                                            const struct
                                            policy_node *node)
{
	// ignore non-allow rules
	if (node->data.av_data->flavor != AV_RULE_ALLOW) {
		return NULL;
	}

	const struct string_list *perms = node->data.av_data->perms;

	while (perms) {
		if (0 == strcmp(perms->string, "*") ||
		    0 == strcmp(perms->string, "~")) {
			return make_check_result('W', W_ID_RISKY_ALLOW_PERM,
						 "Allow rule with complement or wildcard permission");
		}

		perms = perms->next;
	}

	return NULL;
}

struct check_result *check_module_file_name_mismatch(const struct check_data
						     *data,
						     const struct policy_node
						     *node)
{
	const char *mod_name = node->data.h_data->module_name;
	size_t mod_name_len = strlen(mod_name);
	const char *file_name = data->filename;
	size_t file_name_len = strlen(file_name);

	const char *file_name_ext = strrchr(file_name, '.');
	if (file_name_ext) {
		file_name_len -= strlen(file_name_ext);
	}

	if (mod_name_len != file_name_len || strncmp(mod_name, file_name, file_name_len)) {
		return make_check_result('W', W_ID_MOD_NAME_FILE,
					 "Module name %s does not match file name %s",
					 mod_name,
					 file_name);
	}

	return NULL;
}

static bool starts_with_module_prefix(const char *name)
{
	for (const char *prefix = strchr(name, '_'); prefix; prefix = strchr(prefix + 1, '_')) {
		char *search_mod = strndup(name, (size_t)(prefix - name));
		if (look_up_in_mods_map(search_mod)) {
			free(search_mod);
			return true;
		}

		for (size_t i = 0; i < (sizeof RefPol_module_abbreviations / sizeof *RefPol_module_abbreviations); ++i) {
			if (0 == strcmp(search_mod, RefPol_module_abbreviations[i][0]) &&
			    look_up_in_mods_map(RefPol_module_abbreviations[i][1])) {
				free(search_mod);
				return true;
			}
		}

		free(search_mod);
	}

	return false;
}

struct check_result *check_unknown_interface_call(__attribute__((unused)) const struct check_data
						  *data,
						  const struct policy_node
						  *node)
{
	const char *if_name = node->data.ic_data->name;

	// ignore known macros starting with module name
	for (size_t i = 0; i < (sizeof RefPol_macros_with_module_prefix / sizeof *RefPol_macros_with_module_prefix); ++i) {
		if (0 == strcmp(if_name, RefPol_macros_with_module_prefix[i])) {
			return NULL;
		}
	}

	// ignore calls which does not start with a module name: they are probably macros
	if (!starts_with_module_prefix(if_name)) {
		return NULL;
	}

	// ignore known interfaces
	if (look_up_in_ifs_map(if_name)) {
		return NULL;
	}

	return make_check_result('W', W_ID_UNKNOWN_CALL,
				 "Call to %s can not be referenced to any interface",
				 if_name);
}

static bool is_bare_parameter(const char *name)
{
	if (name[0] != '$' || name[1] == '\0') {
		return false;
	}

	for (const char *c = name + 1; *c; c++) {
		if (!isdigit((unsigned char)*c)) {
			return false;
		}
	}

	return true;
}

static bool temp_has_bool_decl(const char *temp_name, const char *bool_name)
{
	if (temp_name == NULL) {
		return false;
	}

	for (const struct decl_list *dl = look_up_decl_in_template_map(temp_name); dl; dl = dl->next) {
		const struct declaration_data *decl = dl->decl;

		if (decl->flavor != DECL_BOOL) {
			continue;
		}

		if (0 == strcmp(decl->name, bool_name)) {
			return true;
		}
	}

	return false;
}

struct check_result *check_unknown_cond_id(__attribute__((unused)) const struct check_data
					   *data,
					   const struct policy_node
					   *node)
{
	if (node->flavor != NODE_BOOLEAN_POLICY && node->flavor != NODE_TUNABLE_POLICY) {
		return alloc_internal_error("Invalid node type for `check_foreign_cond_id`");
	}

	const struct string_list *identifiers = node->data.cd_data->identifiers;

	for (const struct string_list *ids = identifiers; ids; ids = ids->next) {
		const char *id = ids->string;

		/* Ignore interface parameters */
		if (is_bare_parameter(id)) {
			continue;
		}

		if (look_up_in_decl_map(id, DECL_BOOL) != NULL) {
			continue;
		}

		if (temp_has_bool_decl(get_name_if_in_template(node), id)) {
			continue;
		}

		return make_check_result('W', W_ID_UNKNOWN_COND_ID,
					 "Expression for conditional block uses unknown identifier %s",
					 id);
	}

	return NULL;
}

struct check_result *check_declaration_interface_nameclash(__attribute__((unused)) const struct check_data
							   *data,
							   const struct policy_node
							   *node)
{
	const char *decl_name = node->data.d_data->name;

	if (look_up_in_ifs_map(decl_name)) {
		return make_check_result('E', E_ID_DECL_IF_CLASH,
				  "Declaration with name %s clashes with same named interface",
				  decl_name);
	}

	return NULL;
}

bool check_unknown_permission_condition()
{
	// ignore if no permission or permission macro have been parsed
	if (permmacros_map_count() == 0) {
		printf("%sNote%s: Check E-007 is not performed because no permission macro has been parsed.\n",
		       color_note(), color_reset());
		return false;
	}
	if (decl_map_count(DECL_PERM) == 0) {
		printf("%sNote%s: Check E-007 is not performed because no permission has been parsed.\n",
		       color_note(), color_reset());
		return false;
	}

	return true;
}

struct check_result *check_unknown_permission(__attribute__((unused)) const struct check_data
					      *data,
					      const struct policy_node
					      *node)
{
	for (const struct string_list *cur = node->data.av_data->perms; cur; cur = cur->next) {

		if (0 == strcmp(cur->string, "*") ||
		    0 == strcmp(cur->string, "~")) {
			continue;
		}

		// ignore generated all_ permission macros
		if (0 == strncmp(cur->string, "all_", strlen("all_")) &&
		    ends_with(cur->string, strlen(cur->string), "_perms", strlen("_perms"))) {
			continue;
		}

		if (look_up_in_decl_map(cur->string, DECL_PERM)) {
			// TODO: check if class supports this permission
			continue;
		}

		if (look_up_in_permmacros_map(cur->string)) {
			continue;
		}

		return make_check_result('E', E_ID_UNKNOWN_PERM,
					 "Unknown permission %s used",
					 cur->string);
	}

	return NULL;
}

bool check_unknown_class_condition()
{
	// ignore if no class has been parsed
	if (decl_map_count(DECL_CLASS) == 0) {
		printf("%sNote%s: Check E-008 is not performed because no class has been parsed.\n",
		       color_note(), color_reset());
		return false;
	}

	return true;
}

struct check_result *check_unknown_class(__attribute__((unused)) const struct check_data
					 *data,
					 const struct policy_node
					 *node)
{
	const struct string_list *object_classes;
	switch (node->flavor) {
	case NODE_AV_RULE:
		object_classes = node->data.av_data->object_classes;
		break;
	case NODE_RT_RULE:
		object_classes = node->data.rt_data->object_classes;
		break;
	case NODE_TT_RULE:
		object_classes = node->data.tt_data->object_classes;
		break;
	default:
		return alloc_internal_error("Invalid node type for `check_unknown_class`");
	}

	for (const struct string_list *cur = object_classes; cur; cur = cur->next) {
		// ignore interface parameters
		if (cur->string[0] == '$' && isdigit((unsigned char)cur->string[1])) {
			continue;
		}

		// ignore class sets
		if (ends_with(cur->string, strlen(cur->string), "_class_set", strlen("_class_set"))) {
			continue;
		}

		if (look_up_in_decl_map(cur->string, DECL_CLASS)) {
			continue;
		}

		return make_check_result('E', E_ID_UNKNOWN_CLASS,
					 "Unknown class %s used",
					 cur->string);
	}

	return NULL;
}

struct check_result *check_empty_block(__attribute__((unused)) const struct check_data
                                       *data,
                                       const struct policy_node
                                       *node)
{
	for (const struct policy_node *cur = node->first_child; cur; cur = cur->next) {
		if (cur->flavor == NODE_START_BLOCK ||
		    cur->flavor == NODE_COMMENT ||
		    cur->flavor == NODE_SEMICOLON) {
			continue;
		}

		// found a statement
		return NULL;
	}

	return make_check_result('E', E_ID_EMPTY_BLOCK,
				 "Empty block found");
}

static const struct policy_node *is_ifelse_argument(const struct policy_node *cur)
{
	for(; cur && cur->parent; cur = cur->parent) {
		if (cur->flavor == NODE_M4_ARG && cur->parent->flavor == NODE_IFELSE) {
			return cur;
		}
	}

	return NULL;
}

struct check_result *check_stray_word(const struct check_data
				      *data,
				      const struct policy_node
				      *node)
{
	const char *macro_name = node->data.str;

	if (str_in_sl(macro_name, data->config_check_data->custom_te_simple_macros)) {
		return NULL;
	}

	// ignore comparison arguments to ifelse
	// (do not ignore last node of block, which is never a comparison argument)
	const struct policy_node *ifelse_arument = is_ifelse_argument(node);
	if (ifelse_arument && ifelse_arument->next) {
		int position = 0;
		for (const struct policy_node *cur = ifelse_arument; cur->prev; cur = cur->prev) {
			position++;
		}

		position = position % 3;

		if ((position == 1 || position == 2)) {
			return NULL;
		}
	}

	return make_check_result('E', E_ID_STRAY_WORD,
				 "Found stray word %s. If it is a simple m4 macro please add an selint-disable comment or ignore in the SELint configuration file.",
				 macro_name);
}
