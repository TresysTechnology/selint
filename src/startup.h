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

#ifndef STARTUP_H
#define STARTUP_H

#include "selint_error.h"
#include "file_list.h"
#include "string_list.h"

enum selint_error load_access_vectors_kernel(const char *av_path);

enum selint_error load_access_vectors_source(const char *av_path);

void load_modules_normal(void);

enum selint_error load_modules_source(const char *modules_conf_path);

enum selint_error load_obj_perm_sets_source(const char *obj_perm_sets_path);

enum selint_error load_devel_headers(struct policy_file_list *context_files);

enum selint_error load_global_conditions(const struct string_list *paths);

enum selint_error mark_transform_interfaces(const struct policy_file_list *files);

#endif
