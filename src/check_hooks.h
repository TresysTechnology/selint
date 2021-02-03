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

#ifndef CHECK_HOOKS_H
#define CHECK_HOOKS_H

#include "tree.h"
#include "selint_error.h"
#include "selint_config.h"

enum extra_ids {
	X_ID_UNUSED_IF = 1,
	X_END
};

enum convention_ids {
	C_ID_TE_ORDER       = 1,
	C_ID_IF_COMMENT     = 4,
	C_ID_UNORDERED_PERM = 5,
	C_ID_UNORDERED_REQ  = 6,
	C_ID_SELF           = 7,
	C_END
};

enum style_ids {
	S_ID_REQUIRE        = 1,
	S_ID_FC_TYPE        = 2,
	S_ID_SEMICOLON      = 3,
	S_ID_IF_CALLS_TEMPL = 4,
	S_ID_DECL_IN_IF     = 5,
	S_ID_BARE_MODULE    = 6,
	S_ID_MISSING_RANGE  = 7,
	S_ID_UNQUOTE_GENREQ = 8,
	S_ID_PERM_SUFFIX    = 9,
	S_ID_PERMMACRO      = 10,
	S_END
};

enum warn_ids {
	W_ID_NO_EXPLICIT_DECL  = 1,
	W_ID_NO_REQ            = 2,
	W_ID_UNUSED_REQ        = 3,
	W_ID_FC_REGEX          = 4,
	W_ID_IF_CALL_OPTIONAL  = 5,
	W_ID_EMPTY_IF_CALL_ARG = 6,
	W_ID_SPACE_IF_CALL_ARG = 7,
	W_ID_RISKY_ALLOW_PERM  = 8,
	W_ID_MOD_NAME_FILE     = 9,
	W_ID_UNKNOWN_CALL      = 10,
	W_ID_IF_DECL_NOT_OWN   = 11,
	W_END
};

enum error_ids {
	E_ID_FC_ERROR          = 2,
	E_ID_FC_USER           = 3,
	E_ID_FC_ROLE           = 4,
	E_ID_FC_TYPE           = 5,
	E_ID_DECL_IF_CLASH     = 6,
	E_ID_UNKNOWN_PERM      = 7,
	E_ID_UNKNOWN_CLASS     = 8,
	E_ID_EMPTY_BLOCK       = 9,
	E_ID_STRAY_WORD        = 10,
	E_END
};

enum fatal_ids {
	F_ID_POLICY_SYNTAX = 1,
	F_ID_INTERNAL      = 2
};

enum file_flavor {
	FILE_TE_FILE,
	FILE_IF_FILE,
	FILE_FC_FILE
};

struct check_data {
	char *mod_name;
	char *filename;
	enum file_flavor flavor;
	const struct config_check_data *config_check_data;
};

// A check is responsible for filling out all fields except lineno
// which is filled out by the calling function.`
struct check_result {
	unsigned int lineno;
	char severity;
	unsigned int check_id;
	char *message;
};

struct check_node {
	struct check_result *(*check_function) (const struct check_data * data,
	                                        const struct policy_node * node);
	char *check_id;
	unsigned int issues_found;
	struct check_node *next;
};

struct checks {
	struct check_node *check_nodes[NODE_ERROR + 1];
};

// Whether an issue was found
extern int found_issue;
// Whether found issues are printed individually
extern int suppress_output;

/*********************************************
* Add an check to be called on check_flavor nodes
* check_flavor - The flavor of node to call the check for
* ck - The check structure to add the check to
* check_id - The ID code for the check
* check_function - the check to add
* returns SELINT_SUCCESS or an error code on failure
*********************************************/
enum selint_error add_check(enum node_flavor check_flavor, struct checks *ck,
                            const char *check_id,
                            struct check_result *(*check_function)(const struct
                                                                   check_data *
                                                                   check_data,
                                                                   const struct
                                                                   policy_node
                                                                   * node));

/*********************************************
* Call all registered checks for node->flavor node types
* and write any error messages to STDOUT
* ck - The checks structure
* data - Metadata about the file
* node - the node to check
* returns SELINT_SUCCESS or an error code on failure
*********************************************/
enum selint_error call_checks(struct checks *ck,
                              const struct check_data *data,
                              const struct policy_node *node);

/*********************************************
* Helper function for call_checks that takes the appropriate
* list of checks for the node flavor and writes any error messages to STDOUT
* ck_list - The checks to run
* data - Metadata about the file
* node - the node to check
* returns SELINT_SUCCESS or an error code on failure
*********************************************/
enum selint_error call_checks_for_node_type(struct check_node *ck_list,
                                            const struct check_data *data,
                                            const struct policy_node *node);

/*********************************************
* Display a result message for a positive check finding
* res - Information about the result of the check
* data - Metadata about the file
*********************************************/
void display_check_result(const struct check_result *res,
                          const struct check_data *data);

/*********************************************
* Creates a check_result, using a printf style format string and optional
* arguments to generate a message
* severity - The severity of the check result
* check_id - The check identifier
* format - A printf style format string
*********************************************/
__attribute__ ((format(printf, 3, 4)))
struct check_result *make_check_result(char severity,
                                       unsigned int check_id,
                                       const char *format, ...);

/*********************************************
* Generates a check result for an internal error (F-002)
* string - The error message to display
*********************************************/
struct check_result *alloc_internal_error(const char *string);

/*********************************************
* Determine if a character represents a valid severity.
* check_char - The character to check
* returns true if it is a valid check and false otherwise
*********************************************/
bool is_valid_severity(char check_char);

/*********************************************
* Determine if a string represents a valid check.
* This compares vs all checks that are defined in the ids enums
* check_str - The string to check
* returns 1 if it is a valid check and 0 otherwise
*********************************************/
int is_valid_check(const char *check_str);

/*********************************************
* Display a count of issues found in a run, but check ID.
* Don't display checks with no issues found
* ck - The checks structure, which should be already populated with issues_found
* from an analysis run
*********************************************/
void display_check_issue_counts(const struct checks *ck);

void free_check_result(struct check_result *);

void free_checks(struct checks *to_free);

void free_check_node(struct check_node *to_free);

#endif
