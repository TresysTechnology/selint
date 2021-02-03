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

#ifndef MAPS_H
#define MAPS_H

#include <uthash.h>

#include "tree.h"
#include "selint_error.h"

struct hash_elem {
	char *key;
	char *val;
	UT_hash_handle hh_type, hh_role, hh_user, hh_attr_type, hh_attr_role, hh_bool,
	               hh_class, hh_perm, hh_mods, hh_ifs, hh_mod_layers;
};

struct bool_hash_elem {
	char *key;
	int val;
	UT_hash_handle hh_transform, hh_filetrans, hh_role_if, hh_used_if;
};

struct sl_hash_elem {
	char *key;
	struct string_list *val;
	UT_hash_handle hh_permmacros;
};

struct template_hash_elem {
	char *name;
	struct decl_list *declarations;
	struct if_call_list *calls;
	UT_hash_handle hh;
};

void insert_into_decl_map(const char *name, const char *module_name,
                          enum decl_flavor flavor);

const char *look_up_in_decl_map(const char *name, enum decl_flavor flavor);

void insert_into_mods_map(const char *mod_name, const char *status);

const char *look_up_in_mods_map(const char *mod_name);

void insert_into_mod_layers_map(const char *mod_name, const char *layer);

const char *look_up_in_mod_layers_map(const char *mod_name);

void insert_into_ifs_map(const char *if_name, const char *mod_name);

const char *look_up_in_ifs_map(const char *if_name);

void mark_transform_if(const char *if_name);

int is_transform_if(const char *if_name);

void mark_filetrans_if(const char *if_name);

int is_filetrans_if(const char *if_name);

void mark_role_if(const char *if_name);

int is_role_if(const char *if_name);

void mark_used_if(const char *if_name);

int is_used_if(const char *if_name);

// Just generate a template entry in the map, but don't save any calls
// or decls to it.  This is helpful to know what is a template for certain
// checks even if the template never calls or declares anything
void insert_template_into_template_map(const char *name);

void insert_decl_into_template_map(const char *name, enum decl_flavor flavor,
                                   const char *declaration);

void insert_call_into_template_map(const char *name, struct if_call_data *call);

const struct template_hash_elem *look_up_in_template_map(const char *name);

const struct decl_list *look_up_decl_in_template_map(const char *name);

const struct if_call_list *look_up_call_in_template_map(const char *name);

void insert_into_permmacros_map(const char *name, struct string_list *permissions);

const struct string_list *look_up_in_permmacros_map(const char *name);

void visit_all_in_permmacros_map(void (*visitor)(const char *name, const struct string_list *permissions));

unsigned int permmacros_map_count(void);

unsigned int decl_map_count(enum decl_flavor flavor);

void free_all_maps(void);

#endif
