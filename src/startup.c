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
#include <fts.h>
#include <stdio.h>
#include <unistd.h>

#include "startup.h"
#include "color.h"
#include "maps.h"
#include "parse.h"
#include "parse_functions.h"
#include "tree.h"
#include "util.h"
#include "parse.h"

enum selint_error load_access_vectors_kernel(const char *av_path)
{
	/* check if av_path really exists,
	 * e.g. checking nonexistent /sys/fs/selinux/class
	 * on a SELinux disabled system
	 */
	if (access(av_path, F_OK) != 0) {
		return SELINT_IO_ERROR;
	}

	enum selint_error r = SELINT_PARSE_ERROR;
	const char *paths[2] = { av_path, NULL };

IGNORE_CONST_DISCARD_BEGIN;
	FTS *ftsp = fts_open(paths, FTS_PHYSICAL, NULL);
IGNORE_CONST_DISCARD_END;

	FTSENT *file = fts_read(ftsp);

	while (file) {

		if (file->fts_level != 0 && file->fts_info == FTS_D
		    && 0 != strcmp(file->fts_name, "perms")) {
			// Directory being visited the first time

			insert_into_decl_map(file->fts_name, "class",
			                     DECL_CLASS);
		} else if (file->fts_info == FTS_F
		           && 0 != strcmp(file->fts_name, "index")) {
			// File

			insert_into_decl_map(file->fts_name, "perm", DECL_PERM);

			r = SELINT_SUCCESS;
		}
		file = fts_read(ftsp);
	}
	fts_close(ftsp);

	return r;
}

enum selint_error load_access_vectors_source(const char *av_path)
{
	print_if_verbose("Parsing access_vector file %s\n", av_path);

	set_current_module_name(av_path);

	FILE *f = fopen(av_path, "r");
	if (!f) {
		printf("%sError%s: Failed to open %s: %s\n", color_error(), color_reset(), av_path, strerror(errno));
		return SELINT_IO_ERROR;
	}

	struct policy_node *ast = yyparse_wrapper(f, av_path, NODE_AV_FILE);
	fclose(f);

	if (!ast) {
		return SELINT_PARSE_ERROR;
	}

	free_policy_node(ast);
	return SELINT_SUCCESS;
}

void load_modules_normal()
{

}

static int is_space(char c)
{
	return c == ' ' || c == '\t' || c == '\n' || c == '\r';
}

static char *strip_space(char *str)
{

	while (is_space(*str)) {
		str++;
	}

	char *end = str;

	while (!is_space(*end)) {
		end++;
	}

	*end = '\0';

	return str;
}

enum selint_error load_modules_source(const char *modules_conf_path)
{
	FILE *fd = fopen(modules_conf_path, "r");

	if (!fd) {
		return SELINT_IO_ERROR;
	}

	char *line = NULL;
	ssize_t len_read = 0;
	size_t buf_len = 0;
	while ((len_read = getline(&line, &buf_len, fd)) != -1) {
		if (len_read <= 1 || line[0] == '#') {
			continue;
		}
		char *pos = line;
		while (*pos != '\0' && is_space(*pos)) {
			pos++;
		}
		if (pos[0] == '#' || pos[0] == '\0') {
			continue;
		}
		pos = strtok(line, "=");
		if (!pos) {
			free(line);
			fclose(fd);
			return SELINT_PARSE_ERROR;
		}
		char *mod_name = strip_space(pos);
		pos = strtok(NULL, "=");
		if (!pos) {
			free(line);
			fclose(fd);
			return SELINT_PARSE_ERROR;
		}
		char *status = strip_space(pos);
		insert_into_mods_map(mod_name, status);
		if (strtok(NULL, "=")) {
			free(line);
			fclose(fd);
			return SELINT_PARSE_ERROR;
		}
	}
	free(line);
	fclose(fd);

	return SELINT_SUCCESS;
}

enum selint_error load_obj_perm_sets_source(const char *obj_perm_sets_path)
{
	FILE *f = fopen(obj_perm_sets_path, "r");
	if (!f) {
		return SELINT_IO_ERROR;
	}

	struct policy_node *ast = yyparse_wrapper(f, obj_perm_sets_path, NODE_SPT_FILE);
	fclose(f);

	if (ast == NULL) {
		return SELINT_PARSE_ERROR;
	}

	free_policy_node(ast);
	return SELINT_SUCCESS;
}

static int mark_transform_interfaces_one_file(const struct policy_node *ast) {
	int marked_transform = 0;
	const struct policy_node *cur = ast;
	while (cur) {
		if (cur->flavor == NODE_INTERFACE_DEF &&
		    cur->first_child &&
		    !is_transform_if(cur->data.str)) {
			const struct policy_node *child = cur->first_child;
			while (child &&
			       (child->flavor == NODE_START_BLOCK ||
			        child->flavor == NODE_REQUIRE ||
			        child->flavor == NODE_GEN_REQ)) {
				child = child->next;
			}
			if (!child) {
				// Nothing in interface besides possibly require
				cur = dfs_next(cur);
				continue;
			}
			if (child->flavor == NODE_IF_CALL) {
				if (is_transform_if(child->data.ic_data->name)) {
					mark_transform_if(cur->data.str);
					marked_transform = 1;
				}
			}
		}
		cur = dfs_next(cur);
	}
	return marked_transform;
}

enum selint_error load_devel_headers(struct policy_file_list *context_files)
{
	const char *header_loc = "/usr/share/selinux/devel";
	const char *paths[2] = {header_loc, 0};

IGNORE_CONST_DISCARD_BEGIN;
	FTS *ftsp = fts_open(paths, FTS_PHYSICAL | FTS_NOSTAT, NULL);
IGNORE_CONST_DISCARD_END;

	FTSENT *file = fts_read(ftsp);
	while (file) {
		const char *suffix = (file->fts_pathlen > 3) ? (file->fts_path + file->fts_pathlen - 3) : NULL;
		if (suffix && !strcmp(suffix, ".if")) {
			file_list_push_back(context_files,
			                    make_policy_file(file->fts_path,
			                                     NULL));
			char *mod_name = strdup(file->fts_name);
			mod_name[file->fts_namelen - 3] = '\0';
			insert_into_mod_layers_map(mod_name, file->fts_parent->fts_name);
			free(mod_name);
		}
		file = fts_read(ftsp);
	}

	fts_close(ftsp);
	return SELINT_SUCCESS;
}

static enum selint_error load_global_conditions_file(const char *path)
{
	print_if_verbose("Parsing global conditions file %s\n", path);

	set_current_module_name("__global__");

	FILE *f = fopen(path, "r");
	if (!f) {
		printf("%sError%s: Failed to open file %s: %s\n", color_error(), color_reset(), path, strerror(errno));
		return SELINT_IO_ERROR;
	}

	struct policy_node *ast = yyparse_wrapper(f, path, NODE_COND_FILE);
	fclose(f);

	if (!ast) {
		return SELINT_PARSE_ERROR;
	}

	free_policy_node(ast);
	return SELINT_SUCCESS;
}

enum selint_error load_global_conditions(const struct string_list *paths)
{
	for (const struct string_list *p = paths; p; p = p->next) {
		enum selint_error rc = load_global_conditions_file(p->string);
		if (rc != SELINT_SUCCESS) {
			return rc;
		}
	}

	return SELINT_SUCCESS;
}

enum selint_error mark_transform_interfaces(const struct policy_file_list *files)
{
	const struct policy_file_node *cur;
	int marked_transform;
	do {
		marked_transform = 0;
		cur = files->head;
		while (cur) {
			marked_transform = marked_transform ||
			                   mark_transform_interfaces_one_file(cur->file->ast);
			cur = cur->next;
		}
	} while (marked_transform);

	return SELINT_SUCCESS;
}
