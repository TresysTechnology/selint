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

#define _GNU_SOURCE
#include <stdarg.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include "check_hooks.h"

#define ALLOC_NODE(nl)  if (ck->check_nodes[nl]) { \
		loc = ck->check_nodes[nl]; \
		while (loc->next) { loc = loc->next; } \
		loc->next = malloc(sizeof(struct check_node)); \
		if (!loc->next) { return SELINT_OUT_OF_MEM; } \
		loc = loc->next; \
} else { \
		ck->check_nodes[nl] = malloc(sizeof(struct check_node)); \
		if (!ck->check_nodes[nl]) { return SELINT_OUT_OF_MEM; } \
		loc = ck->check_nodes[nl]; \
}

enum selint_error add_check(enum node_flavor check_flavor, struct checks *ck,
                            const char *check_id,
                            struct check_result *(*check_function)(const struct check_data *check_data,
                                                                   const struct policy_node *node))
{
	struct check_node *loc;

	ALLOC_NODE(check_flavor);

	loc->check_function = check_function;
	loc->check_id = strdup(check_id);
	loc->next = NULL;

	return SELINT_SUCCESS;
}

enum selint_error call_checks(struct checks *ck, struct check_data *data,
                              struct policy_node *node)
{
	return call_checks_for_node_type(ck->check_nodes[node->flavor], data, node);
}

enum selint_error call_checks_for_node_type(struct check_node *ck_list,
                                            struct check_data *data,
                                            struct policy_node *node)
{

	struct check_node *cur = ck_list;

	while (cur) {
		if (node->exceptions && strstr(node->exceptions, cur->check_id)) {
			cur = cur->next;
			continue;
		}
		struct check_result *res = cur->check_function(data, node);
		if (res) {
			res->lineno = node->lineno;
			display_check_result(res, data);
			free_check_result(res);
		}
		cur = cur->next;
	}
	return SELINT_SUCCESS;
}

void display_check_result(struct check_result *res, struct check_data *data)
{

	const size_t len = strlen(data->filename);
	unsigned int padding;

	if (18 < len) {
		padding = 0;
	} else {
		padding = 18 - len;
	}

	printf("%s:%*u: (%c): %s (%c-%03u)\n",
	       data->filename,
	       padding,
	       res->lineno,
	       res->severity, res->message, res->severity, res->check_id);
}

struct check_result *alloc_internal_error(const char *string)
{
	return make_check_result('F', F_ID_INTERNAL, string);
}

int is_valid_check(const char *check_str)
{
	if (!check_str) {
		return 0;
	}

	if (check_str[1] != '-') {
		return 0;
	}

	int max_id = 0;

	char severity = check_str[0];

	switch (severity) {
	case 'C':
		max_id = C_END - 1;
		break;
	case 'S':
		max_id = S_END - 1;
		break;
	case 'W':
		max_id = W_END - 1;
		break;
	case 'E':
		max_id = E_END - 1;
		break;
	case 'F':
		max_id = 2;
		break;
	default:
		return 0;
	}

	int check_id = atoi(check_str+2);
	if (check_id > 0 && check_id <= max_id) {
		return 1;
	} else {
		return 0;
	}
}

void free_check_result(struct check_result *res)
{
	free(res->message);
	free(res);
}

__attribute__ ((format(printf, 3, 4)))
struct check_result *make_check_result(char severity, unsigned int check_id,
                                       const char *format, ...)
{

	struct check_result *res = malloc(sizeof(struct check_result));

	res->severity = severity;
	res->check_id = check_id;

	va_list args;
	va_start(args, format);

	if (vasprintf(&res->message, format, args) == -1) {
		free(res);
		res = alloc_internal_error(
			"Failed to generate check result message");
	}

	va_end(args);

	return res;
}

void free_checks(struct checks *to_free)
{
	for (int i=0; i < NODE_ERROR + 1; i++) {
		if (to_free->check_nodes[i]) {
			free_check_node(to_free->check_nodes[i]);
		}
	}
	free(to_free);
}

void free_check_node(struct check_node *to_free)
{

	if (to_free->next) {
		free_check_node(to_free->next);
	}
	free(to_free->check_id);
	free(to_free);

}
