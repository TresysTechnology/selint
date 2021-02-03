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
#include "color.h"

int found_issue = 0;
int suppress_output = 0;

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
	loc->issues_found = 0;
	loc->next = NULL;

	return SELINT_SUCCESS;
}

enum selint_error call_checks(struct checks *ck,
                              const struct check_data *data,
                              const struct policy_node *node)
{
	return call_checks_for_node_type(ck->check_nodes[node->flavor], data, node);
}

enum selint_error call_checks_for_node_type(struct check_node *ck_list,
                                            const struct check_data *data,
                                            const struct policy_node *node)
{

	struct check_node *cur = ck_list;

	while (cur) {
		if (node->exceptions && strstr(node->exceptions, cur->check_id)) {
			cur = cur->next;
			continue;
		}
		struct check_result *res = cur->check_function(data, node);
		if (res) {
			found_issue = 1;
			cur->issues_found++;
			res->lineno = node->lineno;
			if (!suppress_output) {
				display_check_result(res, data);
			}
			free_check_result(res);
		}
		cur = cur->next;
	}
	return SELINT_SUCCESS;
}

void display_check_result(const struct check_result *res, const struct check_data *data)
{
	static const size_t FILENAME_PADDING = 22;

	const size_t len = strlen(data->filename);
	unsigned int padding;

	if (FILENAME_PADDING < len) {
		padding = 0;
	} else {
		padding = (unsigned)(FILENAME_PADDING - len);
	}

	printf("%s:%*u: %s(%c)%s: %s (%c-%03u)\n",
	       data->filename,
	       padding,
	       res->lineno,
	       color_severity(res->severity),
	       res->severity,
	       color_reset(),
	       res->message, res->severity, res->check_id);
}

struct check_result *alloc_internal_error(const char *string)
{
	return make_check_result('F', F_ID_INTERNAL, "%s", string);
}

bool is_valid_severity(char check_char)
{
	switch (check_char) {
	case 'C':
	case 'S':
	case 'W':
	case 'E':
	case 'F':
		return true;
	}

	return false;
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
	case 'X':
		max_id = X_END - 1;
		break;
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

// Return the number of check nodes in the checks structure
static unsigned int count_check_nodes(const struct checks *ck)
{
	unsigned int count = 0;
	for (int i=0; i <= NODE_ERROR; i++) {
		if (ck->check_nodes[i]) {
			struct check_node *cur = ck->check_nodes[i];
			while (cur) {
				count++;
				cur = cur->next;
			}
		}
	}
	return count;
}

static int id_priority(char id)
{
	switch (id) {
	case 'X':
		return 0;
	case 'C':
		return 1;
	case 'S':
		return 2;
	case 'W':
		return 3;
	case 'E':
		return 4;
	default:
		return 5; //Should never happen, but no way to return an error
	}
}

// Return negative if n1 goes before n2, positive if n1 goes after n2 or equal if they are equivalent
static int comp_check_nodes(const void *n1, const void *n2)
{
	const struct check_node *node1 = *(const struct check_node *const *)n1;
	const struct check_node *node2 = *(const struct check_node *const *)n2;

	int check1_priority = id_priority(node1->check_id[0]);
	int check2_priority = id_priority(node2->check_id[0]);

	int r = (check1_priority > check2_priority) - (check1_priority < check2_priority);
	if (r != 0) {
		return r;
	}

	int node1_id = atoi(node1->check_id + 2);
	int node2_id = atoi(node2->check_id + 2);

	return (node1_id > node2_id) - (node1_id < node2_id);
}

void display_check_issue_counts(const struct checks *ck)
{
	size_t num_nodes = count_check_nodes(ck);
	unsigned int printed_something = 0;

	// Build flat array of check nodes
	struct check_node **node_arr = calloc(num_nodes, sizeof(struct check_node *));
	unsigned int node_arr_index = 0;
	for (int i=0; i <= NODE_ERROR; i++) {
		if (ck->check_nodes[i]) {
			struct check_node *cur = ck->check_nodes[i];
			while (cur) {
				node_arr[node_arr_index] = cur;
				cur = cur->next;
				node_arr_index++;
			}
		}
	}

	qsort((void *) node_arr, num_nodes, sizeof(struct check_node *), comp_check_nodes);

	unsigned int issue_count = 0;
	char *old_issue_name = NULL;
	for (unsigned int i=0; i < num_nodes; i++) {
		if (old_issue_name && 0 != strcmp(old_issue_name, node_arr[i]->check_id)) {
			// New issue.  Print the old info
			if (issue_count != 0) {
				printf("%s%s%s: %u\n", color_severity(old_issue_name[0]), old_issue_name, color_reset(), issue_count);
				printed_something = 1;
			}

			// Start counting new
			issue_count = node_arr[i]->issues_found;
		} else {
			// Same issue as previous element
			issue_count += node_arr[i]->issues_found;
		}
		old_issue_name = node_arr[i]->check_id;
	}

	// Possible print last issue
	if (issue_count != 0) {
		printf("%s%s%s: %u\n", color_severity(old_issue_name[0]), old_issue_name, color_reset(), issue_count);
		printed_something = 1;
	}

	if (!printed_something) {
		printf("%s(none)%s\n", color_ok(), color_reset());
	}

	free(node_arr);
}

void free_check_result(struct check_result *res)
{
	if (res) {
		free(res->message);
	}
	free(res);
}

struct check_result *make_check_result(char severity, unsigned int check_id,
                                       const char *format, ...)
{

	struct check_result *res = malloc(sizeof(struct check_result));

	res->severity = severity;
	res->check_id = check_id;

	va_list args;
	va_start(args, format);

	if (vasprintf(&res->message, format, args) == -1) {
		res->severity = 'F';
		res->check_id = F_ID_INTERNAL;
		res->message = strdup("Failed to generate check result message");
	}

	va_end(args);

	return res;
}

void free_checks(struct checks *to_free)
{
	if (to_free == NULL) {
		return;
	}

	for (int i=0; i < NODE_ERROR + 1; i++) {
		free_check_node(to_free->check_nodes[i]);
	}
	free(to_free);
}

void free_check_node(struct check_node *to_free)
{
	while (to_free) {
		struct check_node *tmp = to_free;
		to_free = to_free->next;
		free(tmp->check_id);
		free(tmp);
	}
}
