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

#include "maps.h"

static struct hash_elem *type_map = NULL;
static struct hash_elem *role_map = NULL;
static struct hash_elem *user_map = NULL;
static struct hash_elem *attr_type_map = NULL;
static struct hash_elem *attr_role_map = NULL;
static struct hash_elem *bool_map = NULL;
static struct hash_elem *class_map = NULL;
static struct hash_elem *perm_map = NULL;
static struct hash_elem *mods_map = NULL;
static struct hash_elem *mod_layers_map = NULL;
static struct hash_elem *ifs_map = NULL;
static struct bool_hash_elem *transform_map = NULL;
static struct bool_hash_elem *filetrans_map = NULL;
static struct bool_hash_elem *role_if_map = NULL;
static struct bool_hash_elem *used_if_map = NULL;
static struct sl_hash_elem *permmacros_map = NULL;
static struct template_hash_elem *template_map = NULL;

#if defined(__clang__) && defined(__clang_major__) && (__clang_major__ >= 4)
__attribute__((no_sanitize("unsigned-integer-overflow")))
#if (__clang_major__ >= 12)
__attribute__((no_sanitize("unsigned-shift-base")))
#endif
#endif
static struct hash_elem *look_up_hash_elem(const char *name, enum decl_flavor flavor)
{

	if (!name) {
		return NULL;
	}

	struct hash_elem *decl;

	switch (flavor) {
	case DECL_TYPE:
		HASH_FIND(hh_type, type_map, name, strlen(name), decl);
		break;
	case DECL_ROLE:
		HASH_FIND(hh_role, role_map, name, strlen(name), decl);
		break;
	case DECL_USER:
		HASH_FIND(hh_user, user_map, name, strlen(name), decl);
		break;
	case DECL_ATTRIBUTE:
		HASH_FIND(hh_attr_type, attr_type_map, name, strlen(name), decl);
		break;
	case DECL_ATTRIBUTE_ROLE:
		HASH_FIND(hh_attr_role, attr_role_map, name, strlen(name), decl);
		break;
	case DECL_BOOL:
		HASH_FIND(hh_bool, bool_map, name, strlen(name), decl);
		break;
	case DECL_CLASS:
		HASH_FIND(hh_class, class_map, name, strlen(name), decl);
		break;
	case DECL_PERM:
		HASH_FIND(hh_perm, perm_map, name, strlen(name), decl);
		break;
	default:
		decl = NULL;
	}

	return decl;
}

#if defined(__clang__) && defined(__clang_major__) && (__clang_major__ >= 4)
__attribute__((no_sanitize("unsigned-integer-overflow")))
#if (__clang_major__ >= 12)
__attribute__((no_sanitize("unsigned-shift-base")))
#endif
#endif
void insert_into_decl_map(const char *name, const char *module_name,
                          enum decl_flavor flavor)
{

	struct hash_elem *decl = look_up_hash_elem(name, flavor);

	if (decl == NULL) {     // Item not in hash table already

		decl = malloc(sizeof(struct hash_elem));
		decl->key = strdup(name);
		decl->val = strdup(module_name);

		switch (flavor) {
		case DECL_TYPE:
			HASH_ADD_KEYPTR(hh_type, type_map, decl->key,
			                strlen(decl->key), decl);
			break;
		case DECL_ROLE:
			HASH_ADD_KEYPTR(hh_role, role_map, decl->key,
			                strlen(decl->key), decl);
			break;
		case DECL_USER:
			HASH_ADD_KEYPTR(hh_user, user_map, decl->key,
			                strlen(decl->key), decl);
			break;
		case DECL_ATTRIBUTE:
			HASH_ADD_KEYPTR(hh_attr_type, attr_type_map, decl->key,
			                strlen(decl->key), decl);
			break;
		case DECL_ATTRIBUTE_ROLE:
			HASH_ADD_KEYPTR(hh_attr_role, attr_role_map, decl->key,
			                strlen(decl->key), decl);
			break;
		case DECL_BOOL:
			HASH_ADD_KEYPTR(hh_bool, bool_map, decl->key,
			                strlen(decl->key), decl);
			break;
		case DECL_CLASS:
			HASH_ADD_KEYPTR(hh_class, class_map, decl->key,
			                strlen(decl->key), decl);
			break;
		case DECL_PERM:
			HASH_ADD_KEYPTR(hh_perm, perm_map, decl->key,
			                strlen(decl->key), decl);
			break;
		default:
			free(decl->key);
			free(decl->val);
			free(decl);
			return;
		}
	}       //TODO: else report error?
}

const char *look_up_in_decl_map(const char *name, enum decl_flavor flavor)
{

	struct hash_elem *decl = look_up_hash_elem(name, flavor);

	if (decl == NULL) {
		return NULL;
	} else {
		return decl->val;
	}
}

#if defined(__clang__) && defined(__clang_major__) && (__clang_major__ >= 4)
__attribute__((no_sanitize("unsigned-integer-overflow")))
#if (__clang_major__ >= 12)
__attribute__((no_sanitize("unsigned-shift-base")))
#endif
#endif
void insert_into_mods_map(const char *mod_name, const char *status)
{

	struct hash_elem *mod;

	HASH_FIND(hh_mods, mods_map, mod_name, strlen(mod_name), mod);

	if (!mod) {
		mod = malloc(sizeof(struct hash_elem));
		mod->key = strdup(mod_name);
		mod->val = strdup(status);
		HASH_ADD_KEYPTR(hh_mods, mods_map, mod->key, strlen(mod->key),
		                mod);
	}
}

#if defined(__clang__) && defined(__clang_major__) && (__clang_major__ >= 4)
__attribute__((no_sanitize("unsigned-integer-overflow")))
#if (__clang_major__ >= 12)
__attribute__((no_sanitize("unsigned-shift-base")))
#endif
#endif
const char *look_up_in_mods_map(const char *mod_name)
{

	struct hash_elem *mod;

	HASH_FIND(hh_mods, mods_map, mod_name, strlen(mod_name), mod);

	if (mod == NULL) {
		return NULL;
	} else {
		return mod->val;
	}
}

#if defined(__clang__) && defined(__clang_major__) && (__clang_major__ >= 4)
__attribute__((no_sanitize("unsigned-integer-overflow")))
#if (__clang_major__ >= 12)
__attribute__((no_sanitize("unsigned-shift-base")))
#endif
#endif
void insert_into_mod_layers_map(const char *mod_name, const char *layer)
{
	struct hash_elem *mod;

	HASH_FIND(hh_mod_layers, mod_layers_map, mod_name, strlen(mod_name), mod);

	if (!mod) {
		mod = malloc(sizeof(struct hash_elem));
		mod->key = strdup(mod_name);
		mod->val = strdup(layer);
		HASH_ADD_KEYPTR(hh_mod_layers, mod_layers_map, mod->key, strlen(mod->key),
		                mod);
	}

}

#if defined(__clang__) && defined(__clang_major__) && (__clang_major__ >= 4)
__attribute__((no_sanitize("unsigned-integer-overflow")))
#if (__clang_major__ >= 12)
__attribute__((no_sanitize("unsigned-shift-base")))
#endif
#endif
const char *look_up_in_mod_layers_map(const char *mod_name)
{
	struct hash_elem *mod;

	HASH_FIND(hh_mod_layers, mod_layers_map, mod_name, strlen(mod_name), mod);

	if (mod == NULL) {
		return NULL;
	} else {
		return mod->val;
	}
}

#if defined(__clang__) && defined(__clang_major__) && (__clang_major__ >= 4)
__attribute__((no_sanitize("unsigned-integer-overflow")))
#if (__clang_major__ >= 12)
__attribute__((no_sanitize("unsigned-shift-base")))
#endif
#endif
void insert_into_ifs_map(const char *if_name, const char *mod_name)
{

	struct hash_elem *if_call;

	HASH_FIND(hh_ifs, ifs_map, if_name, strlen(if_name), if_call);

	if (!if_call) {
		if_call = malloc(sizeof(struct hash_elem));
		if_call->key = strdup(if_name);
		if_call->val = strdup(mod_name);
		HASH_ADD_KEYPTR(hh_ifs, ifs_map, if_call->key,
		                strlen(if_call->key), if_call);
	}
}

#if defined(__clang__) && defined(__clang_major__) && (__clang_major__ >= 4)
__attribute__((no_sanitize("unsigned-integer-overflow")))
#if (__clang_major__ >= 12)
__attribute__((no_sanitize("unsigned-shift-base")))
#endif
#endif
const char *look_up_in_ifs_map(const char *if_name)
{

	struct hash_elem *if_call;

	HASH_FIND(hh_ifs, ifs_map, if_name, strlen(if_name), if_call);

	if (if_call == NULL) {
		return NULL;
	} else {
		return if_call->val;
	}
}

unsigned int decl_map_count(enum decl_flavor flavor)
{
	switch (flavor) {
	case DECL_TYPE:
		return HASH_CNT(hh_type, type_map);
	case DECL_ATTRIBUTE:
		return HASH_CNT(hh_attr_type, attr_type_map);
	case DECL_ATTRIBUTE_ROLE:
		return HASH_CNT(hh_attr_role, attr_role_map);
	case DECL_ROLE:
		return HASH_CNT(hh_role, role_map);
	case DECL_USER:
		return HASH_CNT(hh_user, user_map);
	case DECL_BOOL:
		return HASH_CNT(hh_bool, bool_map);
	case DECL_CLASS:
		return HASH_CNT(hh_class, class_map);
	case DECL_PERM:
		return HASH_CNT(hh_perm, perm_map);
	default:
		return 0;
	}
}

#if defined(__clang__) && defined(__clang_major__) && (__clang_major__ >= 4)
__attribute__((no_sanitize("unsigned-integer-overflow")))
#if (__clang_major__ >= 12)
__attribute__((no_sanitize("unsigned-shift-base")))
#endif
#endif
void mark_transform_if(const char *if_name)
{
	struct bool_hash_elem *transform_if;

	HASH_FIND(hh_transform, transform_map, if_name, strlen(if_name), transform_if);

	if (!transform_if) {
		transform_if = malloc(sizeof(struct bool_hash_elem));
		transform_if->key = strdup(if_name);
		transform_if->val = 1;
		HASH_ADD_KEYPTR(hh_transform, transform_map, transform_if->key,
		                strlen(transform_if->key), transform_if);
	} else {
		transform_if->val = 1;
	}
}

#if defined(__clang__) && defined(__clang_major__) && (__clang_major__ >= 4)
__attribute__((no_sanitize("unsigned-integer-overflow")))
#if (__clang_major__ >= 12)
__attribute__((no_sanitize("unsigned-shift-base")))
#endif
#endif
int is_transform_if(const char *if_name)
{
	struct bool_hash_elem *transform_if;
	HASH_FIND(hh_transform, transform_map, if_name, strlen(if_name), transform_if);
	if (transform_if && transform_if->val == 1) {
		return 1;
	} else {
		return 0;
	}
}

#if defined(__clang__) && defined(__clang_major__) && (__clang_major__ >= 4)
__attribute__((no_sanitize("unsigned-integer-overflow")))
#if (__clang_major__ >= 12)
__attribute__((no_sanitize("unsigned-shift-base")))
#endif
#endif
void mark_filetrans_if(const char *if_name)
{
	struct bool_hash_elem *filetrans_if;

	HASH_FIND(hh_filetrans, filetrans_map, if_name, strlen(if_name), filetrans_if);

	if (!filetrans_if) {
		filetrans_if = malloc(sizeof(struct bool_hash_elem));
		filetrans_if->key = strdup(if_name);
		filetrans_if->val = 1;
		HASH_ADD_KEYPTR(hh_filetrans, filetrans_map, filetrans_if->key,
		                strlen(filetrans_if->key), filetrans_if);
	} else {
		filetrans_if->val = 1;
	}
}

#if defined(__clang__) && defined(__clang_major__) && (__clang_major__ >= 4)
__attribute__((no_sanitize("unsigned-integer-overflow")))
#if (__clang_major__ >= 12)
__attribute__((no_sanitize("unsigned-shift-base")))
#endif
#endif
int is_filetrans_if(const char *if_name)
{
	struct bool_hash_elem *filetrans_if;
	HASH_FIND(hh_filetrans, filetrans_map, if_name, strlen(if_name), filetrans_if);
	if (filetrans_if && filetrans_if->val == 1) {
		return 1;
	} else {
		return 0;
	}
}

#if defined(__clang__) && defined(__clang_major__) && (__clang_major__ >= 4)
__attribute__((no_sanitize("unsigned-integer-overflow")))
#if (__clang_major__ >= 12)
__attribute__((no_sanitize("unsigned-shift-base")))
#endif
#endif
void mark_role_if(const char *if_name)
{
	struct bool_hash_elem *role_if;

	HASH_FIND(hh_role_if, role_if_map, if_name, strlen(if_name), role_if);

	if (!role_if) {
		role_if = malloc(sizeof(struct bool_hash_elem));
		role_if->key = strdup(if_name);
		role_if->val = 1;
		HASH_ADD_KEYPTR(hh_role_if, role_if_map, role_if->key,
		                strlen(role_if->key), role_if);
	} else {
		role_if->val = 1;
	}
}

#if defined(__clang__) && defined(__clang_major__) && (__clang_major__ >= 4)
__attribute__((no_sanitize("unsigned-integer-overflow")))
#if (__clang_major__ >= 12)
__attribute__((no_sanitize("unsigned-shift-base")))
#endif
#endif
int is_role_if(const char *if_name)
{
	struct bool_hash_elem *role_if;
	HASH_FIND(hh_role_if, role_if_map, if_name, strlen(if_name), role_if);
	if (role_if && role_if->val == 1) {
		return 1;
	} else {
		return 0;
	}
}

#if defined(__clang__) && defined(__clang_major__) && (__clang_major__ >= 4)
__attribute__((no_sanitize("unsigned-integer-overflow")))
#if (__clang_major__ >= 12)
__attribute__((no_sanitize("unsigned-shift-base")))
#endif
#endif
void mark_used_if(const char *if_name)
{
	struct bool_hash_elem *used_if;

	HASH_FIND(hh_used_if, used_if_map, if_name, strlen(if_name), used_if);

	if (!used_if) {
		used_if = malloc(sizeof(struct bool_hash_elem));
		used_if->key = strdup(if_name);
		used_if->val = 1;
		HASH_ADD_KEYPTR(hh_used_if, used_if_map, used_if->key,
				strlen(used_if->key), used_if);
	} else {
		used_if->val = 1;
	}
}

#if defined(__clang__) && defined(__clang_major__) && (__clang_major__ >= 4)
__attribute__((no_sanitize("unsigned-integer-overflow")))
#if (__clang_major__ >= 12)
__attribute__((no_sanitize("unsigned-shift-base")))
#endif
#endif
int is_used_if(const char *if_name)
{
	struct bool_hash_elem *used_if;
	HASH_FIND(hh_used_if, used_if_map, if_name, strlen(if_name), used_if);
	if (used_if && used_if->val == 1) {
		return 1;
	} else {
		return 0;
	}
}

static void insert_decl(struct template_hash_elem *template, void *new_node)
{
	if (template->declarations) {
		struct decl_list *cur = template->declarations;
		while (cur->next) {
			cur = cur->next;
		}
		cur->next = (struct decl_list *)new_node;
	} else {
		template->declarations = (struct decl_list *)new_node;
	}
}

static void insert_call(struct template_hash_elem *template, void *new_node)
{
	if (template->calls) {
		struct if_call_list *cur = template->calls;
		while (cur->next) {
			cur = cur->next;
		}
		cur->next = (struct if_call_list *)new_node;
	} else {
		template->calls = (struct if_call_list *)new_node;
	}
}

static void insert_noop(__attribute__((unused)) struct template_hash_elem *template,
                 __attribute__((unused)) void *new_node)
{
	return;
}

#if defined(__clang__) && defined(__clang_major__) && (__clang_major__ >= 4)
__attribute__((no_sanitize("unsigned-integer-overflow")))
#if (__clang_major__ >= 12)
__attribute__((no_sanitize("unsigned-shift-base")))
#endif
#endif
static void insert_into_template_map(const char *name, void *new_node,
                              void (*insertion_func)(struct template_hash_elem
                                                     *, void *))
{

	struct template_hash_elem *template;

	HASH_FIND(hh, template_map, name, strlen(name), template);

	if (template == NULL) {
		template = malloc(sizeof(struct template_hash_elem));
		template->name = strdup(name);
		template->declarations = NULL;
		template->calls = NULL;

		HASH_ADD_KEYPTR(hh, template_map, template->name,
		                strlen(template->name), template);

	}

	insertion_func(template, new_node);
}

void insert_template_into_template_map(const char *name)
{
	insert_into_template_map(name, NULL, insert_noop);
}

void insert_decl_into_template_map(const char *name, enum decl_flavor flavor,
                                   const char *declaration)
{

	struct declaration_data *new_data =
		malloc(sizeof(struct declaration_data));

	new_data->flavor = flavor;
	new_data->name = strdup(declaration);
	new_data->attrs = NULL; //Not needed

	struct decl_list *new_node = malloc(sizeof(struct decl_list));
	new_node->decl = new_data;
	new_node->next = NULL;

	insert_into_template_map(name, new_node, insert_decl);
}

void insert_call_into_template_map(const char *name, struct if_call_data *call)
{

	struct if_call_list *new_node = malloc(sizeof(struct if_call_list));

	new_node->call = call;
	new_node->next = NULL;

	insert_into_template_map(name, new_node, insert_call);
}

#if defined(__clang__) && defined(__clang_major__) && (__clang_major__ >= 4)
__attribute__((no_sanitize("unsigned-integer-overflow")))
#if (__clang_major__ >= 12)
__attribute__((no_sanitize("unsigned-shift-base")))
#endif
#endif
const struct template_hash_elem *look_up_in_template_map(const char *name)
{

	struct template_hash_elem *template;

	HASH_FIND(hh, template_map, name, strlen(name), template);

	return template;
}

const struct decl_list *look_up_decl_in_template_map(const char *name)
{
	const struct template_hash_elem *template = look_up_in_template_map(name);

	if (template) {
		return template->declarations;
	} else {
		return NULL;
	}
}

const struct if_call_list *look_up_call_in_template_map(const char *name)
{
	const struct template_hash_elem *template = look_up_in_template_map(name);

	if (template) {
		return template->calls;
	} else {
		return NULL;
	}
}

#if defined(__clang__) && defined(__clang_major__) && (__clang_major__ >= 4)
__attribute__((no_sanitize("unsigned-integer-overflow")))
#if (__clang_major__ >= 12)
__attribute__((no_sanitize("unsigned-shift-base")))
#endif
#endif
void insert_into_permmacros_map(const char *name, struct string_list *permissions)
{

	struct sl_hash_elem *perm_macro;

	HASH_FIND(hh_permmacros, permmacros_map, name, strlen(name), perm_macro);

	if (!perm_macro) {
		perm_macro = malloc(sizeof(struct sl_hash_elem));
		perm_macro->key = strdup(name);
		perm_macro->val = permissions;
		HASH_ADD_KEYPTR(hh_permmacros, permmacros_map, perm_macro->key, strlen(perm_macro->key),
		                perm_macro);
	}
}

#if defined(__clang__) && defined(__clang_major__) && (__clang_major__ >= 4)
__attribute__((no_sanitize("unsigned-integer-overflow")))
#if (__clang_major__ >= 12)
__attribute__((no_sanitize("unsigned-shift-base")))
#endif
#endif
const struct string_list *look_up_in_permmacros_map(const char *name)
{

	struct sl_hash_elem *perm_macro;

	HASH_FIND(hh_permmacros, permmacros_map, name, strlen(name), perm_macro);

	if (perm_macro == NULL) {
		return NULL;
	} else {
		return perm_macro->val;
	}
}

void visit_all_in_permmacros_map(void (*visitor)(const char *name, const struct string_list *permissions))
{
	const struct sl_hash_elem *cur_sl, *tmp_sl;

	HASH_ITER(hh_permmacros, permmacros_map, cur_sl, tmp_sl) {
		visitor(cur_sl->key, cur_sl->val);
	}
}

unsigned int permmacros_map_count()
{
	return HASH_CNT(hh_permmacros, permmacros_map);
}

#define FREE_MAP(mn) HASH_ITER(hh_ ## mn, mn ## _map, cur_decl, tmp_decl) { \
		HASH_DELETE(hh_ ## mn, mn ## _map, cur_decl); \
		free(cur_decl->key); \
		free(cur_decl->val); \
		free(cur_decl); \
} \

#define FREE_BOOL_MAP(mn) HASH_ITER(hh_ ## mn, mn ## _map, cur_bool, tmp_bool) { \
		HASH_DELETE(hh_ ## mn, mn ## _map, cur_bool); \
		free(cur_bool->key); \
		free(cur_bool); \
} \

void free_all_maps()
{

	struct hash_elem *cur_decl, *tmp_decl;

	FREE_MAP(type);

	FREE_MAP(role);

	FREE_MAP(user);

	FREE_MAP(attr_type);

	FREE_MAP(attr_role);

	FREE_MAP(bool);

	FREE_MAP(class);

	FREE_MAP(perm);

	FREE_MAP(mods);

	FREE_MAP(mod_layers);

	FREE_MAP(ifs);

	struct bool_hash_elem *cur_bool, *tmp_bool;

	FREE_BOOL_MAP(transform);

	FREE_BOOL_MAP(filetrans);

	FREE_BOOL_MAP(role_if);

	FREE_BOOL_MAP(used_if);

	struct sl_hash_elem *cur_sl, *tmp_sl;

	HASH_ITER(hh_permmacros, permmacros_map, cur_sl, tmp_sl) {
		HASH_DELETE(hh_permmacros, permmacros_map, cur_sl);
		free(cur_sl->key);
		free_string_list(cur_sl->val);
		free(cur_sl);
	}

	struct template_hash_elem *cur_template, *tmp_template;

	HASH_ITER(hh, template_map, cur_template, tmp_template) {
		HASH_DELETE(hh, template_map, cur_template);
		free(cur_template->name);
		free_decl_list(cur_template->declarations);
		free_if_call_list(cur_template->calls);
		free(cur_template);
	}
}
