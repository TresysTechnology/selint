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

%define parse.error verbose
%locations
%define api.pure full
%lex-param {yyscan_t scanner}
%parse-param {yyscan_t scanner}

%code requires {
	typedef void* yyscan_t;
}

%{
	#include <stdio.h>
	#include <string.h>
	#include <libgen.h>
	#include <ctype.h>
	#include "tree.h"
	#include "parse_functions.h"
	#include "check_hooks.h"
	#include "util.h"
	#include "color.h"

	#define YYDEBUG 1

	struct location
	{
		unsigned int first_line;
		unsigned int first_column;
		unsigned int last_line;
		unsigned int last_column;
	};
	#define YYLTYPE struct location
%}

%union {
	char *string;
	char symbol;
	struct string_list *sl;
	enum av_rule_flavor av_flavor;
	enum node_flavor node_flavor;
}

%{
	// local variables and functions
	static const char *parsing_filename;
	static struct policy_node *cur;
	static enum node_flavor expected_node_flavor;
	static void yyerror(const YYLTYPE *locp, yyscan_t yyscanner, char const *msg);

	// lexer
	extern void yyrestart(FILE *input_file , yyscan_t yyscanner);
	extern int yylex(YYSTYPE *yylval_param, YYLTYPE *yylloc_param, yyscan_t yyscanner);
	extern int yylex_init(yyscan_t* scanner);
	extern int yylex_destroy(yyscan_t scanner);
	extern char *current_lines[LINES_TO_CACHE];
	extern unsigned line_cache_index;
	extern void reset_current_lines(void);
%}

%code provides {
	// number of lines stored, printed on parse errors for multiline statements
	#define LINES_TO_CACHE 5

	// global prototype
	struct policy_node *yyparse_wrapper(FILE *filefd, const char *filename, enum node_flavor expected_flavor);
}

%token <string> STRING;
%token <string> NUM_STRING;
%token <string> IPV4;
%token <string> IPV6;
%token <string> NUMBER;
%token <string> QUOTED_STRING;
%token <string> VERSION_NO;
%token <string> SELINT_COMMAND;

%destructor { free($$); } STRING
%destructor { free($$); } NUM_STRING
%destructor { free($$); } IPV4
%destructor { free($$); } IPV6
%destructor { free($$); } NUMBER
%destructor { free($$); } QUOTED_STRING
%destructor { free($$); } VERSION_NO

%token UNKNOWN_TOKEN;
%token POLICY_MODULE;
%token MODULE;
%token TYPE;
%token TYPEALIAS;
%token ALIAS;
%token ATTRIBUTE;
%token BOOL;
%token TYPE_ATTRIBUTE;
%token ROLE_ATTRIBUTE;
%token ROLE;
%token TYPES;
%token ATTRIBUTE_ROLE;
%token ALLOW;
%token ALLOW_XPERM;
%token AUDIT_ALLOW;
%token AUDIT_ALLOW_XPERM;
%token DONT_AUDIT;
%token DONT_AUDIT_XPERM;
%token NEVER_ALLOW;
%token NEVER_ALLOW_XPERM;
%token TYPE_TRANSITION;
%token TYPE_MEMBER;
%token TYPE_CHANGE;
%token RANGE_TRANSITION;
%token ROLE_TRANSITION;
%token OPTIONAL_POLICY;
%token GEN_REQUIRE;
%token GEN_BOOL;
%token GEN_TUNABLE;
%token REQUIRE;
%token TUNABLE_POLICY;
%token IFELSE;
%token REFPOLICYWARN;
%token CLASS;
%token COMMON;
%token INHERITS;
%token IFDEF;
%token IFNDEF;
%token IF;
%token ELSE;
%token GENFSCON;
%token SID;
%token PORTCON;
%token NETIFCON;
%token NODECON;
%token FS_USE_TRANS;
%token FS_USE_XATTR;
%token FS_USE_TASK;
%token DEFINE;
%token GEN_USER;
%token GEN_CONTEXT;
%token PERMISSIVE;
%token TYPEBOUNDS;
%token INTERFACE;
%token TEMPLATE;
%token USERDEBUG_OR_ENG;
%token FILE_TYPE_SPECIFIER;
%token OPEN_PAREN;
%token COMMA;
%token PERIOD;
%token CLOSE_PAREN;
%token OPEN_CURLY;
%token CLOSE_CURLY;
%token COLON;
%token SEMICOLON;
%token BACKTICK;
%token SINGLE_QUOTE;
%token TILDA;
%token STAR;
%token DASH;
%left AND;
%left OR;
%left XOR;
%right NOT;
%left EQUAL;
%left NOT_EQUAL;
%token COMMENT;

%type<sl> string_list
%type<sl> comma_string_list
%type<sl> strings
%type<sl> xperm_list
%type<sl> xperm_items
%type<string> sl_item
%type<string> xperm_item
%type<sl> arg
%type<sl> args
%type<string> mls_range
%type<string> mls_level
%type<string> mls_component
%type<string> maybe_string_comma
%type<av_flavor> av_type
%type<av_flavor> xperm_av_type
%type<node_flavor> if_keyword

%destructor { free($$); } mls_component mls_level mls_range sl_item xperm_item
%destructor { free_string_list($$); } arg args comma_string_list string_list strings xperm_list xperm_items

%%
selinux_file:
	%empty
	/* empty */ { cur->flavor = NODE_EMPTY; }
	|
	te_policy
	|
	comments te_policy
	|
	if_file
	|
	comments if_file
	|
	spt_file
	|
	comments spt_file
	|
	av_file
	|
	comments av_file
	|
	global_conditions_file
	|
	comments global_conditions_file
	|
	comments
	;

	// TE File parsing

te_policy:
	header body
	;

comments:
	comment
	|
	comment comments
	;

comment:
	COMMENT	{ insert_comment(&cur, @$.first_line); }
	;


header:
	POLICY_MODULE OPEN_PAREN STRING COMMA header_version CLOSE_PAREN {
			if (expected_node_flavor != NODE_TE_FILE) {
				free($3);
				const struct location loc = { @1.first_line, @1.first_column, @6.last_line, @6.last_column };
				yyerror(&loc, NULL, "Error: Unexpected te-file parsed"); YYERROR;
			}
			insert_header(&cur, $3, HEADER_MACRO, @$.first_line); free($3); } // Version number isn't needed
	|
	MODULE STRING header_version SEMICOLON {
			if (expected_node_flavor != NODE_TE_FILE) {
				free($2);
				const struct location loc = { @1.first_line, @1.first_column, @4.last_line, @4.last_column };
				yyerror(&loc, NULL, "Error: Unexpected te-file parsed"); YYERROR;
			}
			insert_header(&cur, $2, HEADER_BARE, @$.first_line); free($2); }
	;

header_version:
	VERSION_NO { free($1); }
	|
	NUMBER { free($1); }
	;

body:
	lines
	;

lines:
	lines line
	|
	line
	;

line:
	bare_line
	|
	bare_line SELINT_COMMAND { save_command(cur, $2); free($2); }
	;

bare_line:
	declaration
	|
	type_attribute
	|
	role_attribute
	|
	type_alias
	|
	rule
	|
	xperm_rule
	|
	role_allow
	|
	role_types
	|
	type_transition
	|
	range_transition
	|
	role_transition
	|
	interface_call
	|
	optional_block
	|
	require
	|
	m4_call
	|
	m4_simple_macro
	|
	cond_expr
	|
	genfscon
	|
	sid
	|
	portcon
	|
	netifcon
	|
	nodecon
	|
	fs_use
	|
	define
	|
	gen_user
	|
	permissive
	|
	typebounds
	|
	SEMICOLON { insert_semicolon(&cur, @$.first_line); }
	|
	COMMENT
	// Would like to do error recovery, but the best strategy seems to be to skip
	// to next newline, which lex doesn't give us right now.
	// Also, we would need to know in yyerror whether the error was recoverable
	|
	error {
		const struct location loc = { @1.first_line, @1.first_column, @1.last_line, @1.last_column };
		yyerror(&loc, NULL, "Error: Invalid statement");
		YYABORT;
		}
	;

declaration:
	type_declaration
	|
	ATTRIBUTE STRING SEMICOLON { insert_declaration(&cur, DECL_ATTRIBUTE, $2, NULL, @$.first_line); free($2); }
	|
	CLASS STRING string_list SEMICOLON { insert_declaration(&cur, DECL_CLASS, $2, $3, @$.first_line); free($2); }
	|
	ROLE STRING SEMICOLON { insert_declaration(&cur, DECL_ROLE, $2, NULL, @$.first_line); free($2); }
	|
	ATTRIBUTE_ROLE STRING SEMICOLON { insert_declaration(&cur, DECL_ATTRIBUTE_ROLE, $2, NULL, @$.first_line); free($2); }
	|
	bool_declaration
	;

type_declaration:
	TYPE STRING SEMICOLON { insert_declaration(&cur, DECL_TYPE, $2, NULL, @$.first_line); free($2); }
	|
	TYPE STRING COMMA comma_string_list SEMICOLON { insert_declaration(&cur, DECL_TYPE, $2, $4, @$.first_line); free($2); }
	|
	TYPE STRING ALIAS string_list SEMICOLON { insert_declaration(&cur, DECL_TYPE, $2, NULL, @$.first_line); free($2); insert_aliases(&cur, $4, DECL_TYPE, @$.first_line); }
	|
	TYPE STRING ALIAS string_list COMMA comma_string_list SEMICOLON {
				insert_declaration(&cur, DECL_TYPE, $2, $6, @$.first_line);
				free($2);
				insert_aliases(&cur, $4, DECL_TYPE, @$.first_line); }
	;

bool_declaration:
	BOOL STRING SEMICOLON { insert_declaration(&cur, DECL_BOOL, $2, NULL, @$.first_line); free($2); }
	|
	GEN_BOOL OPEN_PAREN STRING COMMA STRING CLOSE_PAREN { insert_declaration(&cur, DECL_BOOL, $3, NULL, @$.first_line); free($3); free($5); }
	|
	GEN_TUNABLE OPEN_PAREN BACKTICK STRING SINGLE_QUOTE COMMA STRING CLOSE_PAREN { insert_declaration(&cur, DECL_BOOL, $4, NULL, @$.first_line); free($4); free($7); }
	|
	GEN_TUNABLE OPEN_PAREN STRING COMMA STRING CLOSE_PAREN { insert_declaration(&cur, DECL_BOOL, $3, NULL, @$.first_line); free($3); free($5); }
	;

type_alias:
	TYPEALIAS STRING ALIAS string_list SEMICOLON { insert_type_alias(&cur, $2, @$.first_line); insert_aliases(&cur, $4, DECL_TYPE, @$.first_line); free($2); }
	;

type_attribute:
	TYPE_ATTRIBUTE STRING comma_string_list SEMICOLON { insert_type_attribute(&cur, $2, $3, @$.first_line); free($2); }
	;

role_attribute:
	ROLE_ATTRIBUTE STRING comma_string_list SEMICOLON { insert_role_attribute(&cur, $2, $3, @$.first_line); free($2); }

rule:
	av_type string_list string_list COLON string_list string_list SEMICOLON { insert_av_rule(&cur, $1, $2, $3, $5, $6, @$.first_line); }
	;

av_type:
	ALLOW { $$ = AV_RULE_ALLOW; }
	|
	AUDIT_ALLOW { $$ = AV_RULE_AUDITALLOW; }
	|
	DONT_AUDIT { $$ = AV_RULE_DONTAUDIT; }
	|
	NEVER_ALLOW { $$ = AV_RULE_NEVERALLOW; }
	;

xperm_rule:
	xperm_av_type string_list string_list COLON string_list STRING xperm_list SEMICOLON { insert_xperm_av_rule(&cur, $1, $2, $3, $5, $6, $7, @$.first_line); free($6); }
	;

xperm_av_type:
	ALLOW_XPERM { $$ = AV_RULE_ALLOW; }
	|
	AUDIT_ALLOW_XPERM { $$ = AV_RULE_AUDITALLOW; }
	|
	DONT_AUDIT_XPERM { $$ = AV_RULE_DONTAUDIT; }
	|
	NEVER_ALLOW_XPERM { $$ = AV_RULE_NEVERALLOW; }
	;

xperm_list:
	OPEN_CURLY xperm_items CLOSE_CURLY { $$ = $2; }
	|
	TILDA xperm_list { $$ = sl_from_str("~"); $$->next = $2; }
	|
	xperm_item { $$ = sl_from_str_consume($1); }
	;

xperm_items:
	xperm_items xperm_item { $$ = concat_string_lists($1, sl_from_str($2)); free($2); }
	|
	xperm_item { $$ = sl_from_str_consume($1); }
	;

xperm_item:
	STRING { $$ = $1; }
	|
	NUM_STRING { $$ = $1; }
	|
	NUMBER { $$ = $1; }
	|
	DASH { $$ = strdup("-"); }  // TODO: validate usage: enforce two surrounding increasing elements
	;

string_list:
	OPEN_CURLY strings CLOSE_CURLY { $$ = $2; }
	|
	TILDA string_list { $$ = sl_from_str("~"); $$->next = $2; }
	|
	sl_item { $$ = sl_from_str_consume($1); }
	|
	STAR { $$ = sl_from_str("*"); }
	;

strings:
	strings sl_item { $$ = concat_string_lists($1, sl_from_str($2)); free($2); }
	|
	sl_item { $$ = sl_from_str_consume($1); }
	;

sl_item:
	STRING
	|
	DASH STRING { $$ = malloc(sizeof(char) * (strlen($2) + 2));
			$$[0] = '-';
			$$[1] = '\0';
			strcat($$, $2);
			free($2);}
	|
	QUOTED_STRING
	;

comma_string_list:
	comma_string_list COMMA STRING { $$ = concat_string_lists($1, sl_from_str($3)); free($3); }
	|
	STRING { $$ = sl_from_str_consume($1); }
	;

role_allow:
	// It is an error for av_type to be anything other than ALLOW, but specifying ALLOW here is
	// a grammar conflict, so we leave it general in the parse rule and then check
	av_type string_list string_list SEMICOLON { if ($1 != AV_RULE_ALLOW) {
                                                                free_string_list($2);
                                                                free_string_list($3);
								const struct location loc = { @1.first_line, @1.first_column, @4.last_line, @4.last_column };
								yyerror(&loc, NULL, "Incomplete AV rule");
								YYERROR; }
	                                            insert_role_allow(&cur, $2, $3, @$.first_line);
	                                          }
	;

role_types:
        ROLE STRING TYPES string_list SEMICOLON { insert_role_types(&cur, $2, $4, @$.first_line); free($2); }
        ;

type_transition:
	TYPE_TRANSITION string_list string_list COLON string_list STRING SEMICOLON
	{ insert_type_transition(&cur, TT_TT, $2, $3, $5, $6, NULL, @$.first_line); free($6); }
	|
	TYPE_TRANSITION string_list string_list COLON string_list STRING QUOTED_STRING SEMICOLON
	{ insert_type_transition(&cur, TT_TT, $2, $3, $5, $6, $7, @$.first_line); free($6); free($7); }
	|
	TYPE_MEMBER string_list string_list COLON string_list STRING SEMICOLON { insert_type_transition(&cur, TT_TM, $2, $3, $5, $6, NULL, @$.first_line); free($6); }
	|
	TYPE_CHANGE string_list string_list COLON string_list STRING SEMICOLON { insert_type_transition(&cur, TT_TC, $2, $3, $5, $6, NULL, @$.first_line); free($6); }
	;

range_transition:
	RANGE_TRANSITION string_list string_list COLON string_list mls_range SEMICOLON { insert_type_transition(&cur, TT_RT, $2, $3, $5, $6, NULL, @$.first_line); free($6); }
	;

role_transition:
	ROLE_TRANSITION string_list string_list STRING SEMICOLON { insert_role_transition(&cur, $2, $3, NULL, $4, @$.first_line); free($4); }
	|
	ROLE_TRANSITION string_list string_list COLON string_list STRING SEMICOLON { insert_role_transition(&cur, $2, $3, $5, $6, @$.first_line); free($6); }
	;

interface_call:
	STRING OPEN_PAREN args CLOSE_PAREN
	{ insert_interface_call(&cur, $1, $3, @$.first_line); free($1); }
	|
	STRING OPEN_PAREN CLOSE_PAREN
	{ insert_interface_call(&cur, $1, NULL, @$.first_line); free($1); }
	;

optional_block:
	optional_open
	lines SINGLE_QUOTE CLOSE_PAREN { end_optional_policy(&cur); }
	|
	optional_open
	SINGLE_QUOTE CLOSE_PAREN { end_optional_policy(&cur); }
	|
	optional_open
	lines SINGLE_QUOTE COMMA { end_optional_policy(&cur); }
	BACKTICK { begin_optional_else(&cur, @$.first_line); }
	lines SINGLE_QUOTE CLOSE_PAREN { end_optional_else(&cur); }
	;

optional_open:
	OPTIONAL_POLICY OPEN_PAREN BACKTICK { begin_optional_policy(&cur, @$.first_line); }
	|
	OPTIONAL_POLICY OPEN_PAREN BACKTICK SELINT_COMMAND { begin_optional_policy(&cur, @$.first_line); save_command(cur->parent, $4); free($4); }
	;

require:
	gen_require_begin
	BACKTICK require_lines SINGLE_QUOTE CLOSE_PAREN { end_gen_require(&cur, 0); }
	|
	gen_require_begin
	BACKTICK SELINT_COMMAND require_lines SINGLE_QUOTE CLOSE_PAREN { end_gen_require(&cur, 0); save_command(cur, $3); free($3); }
	|
	gen_require_begin
	require_lines CLOSE_PAREN { end_gen_require(&cur, 1); }
	|
	REQUIRE OPEN_CURLY { begin_require(&cur, @$.first_line); }
	require_lines CLOSE_CURLY { end_require(&cur); }
	|
	REQUIRE OPEN_CURLY SELINT_COMMAND { begin_require(&cur, @$.first_line); save_command(cur->parent, $3); }
	require_lines CLOSE_CURLY { end_require(&cur); free($3); }
	;

gen_require_begin:
	GEN_REQUIRE OPEN_PAREN { begin_gen_require(&cur, @$.first_line); }
	|
	GEN_REQUIRE OPEN_PAREN SELINT_COMMAND { begin_gen_require(&cur, @$.first_line); save_command(cur->parent, $3); free($3); }
	;

require_lines:
	require_lines require_line
	|
	require_line
	;

require_line:
	require_bare
	|
	require_bare SELINT_COMMAND { save_command(cur, $2); free($2); }
	;

require_bare:
	TYPE comma_string_list SEMICOLON {
		for (const struct string_list *iter = $2; iter; iter = iter->next) insert_declaration(&cur, DECL_TYPE, iter->string, NULL, @$.first_line);
		free_string_list($2);
		}
	|
	ATTRIBUTE comma_string_list SEMICOLON {
		for (const struct string_list *iter = $2; iter; iter = iter->next) insert_declaration(&cur, DECL_ATTRIBUTE, iter->string, NULL, @$.first_line);
		free_string_list($2);
		}
	|
	ROLE comma_string_list SEMICOLON {
		for (const struct string_list *iter = $2; iter; iter = iter->next) insert_declaration(&cur, DECL_ROLE, iter->string, NULL, @$.first_line);
		free_string_list($2);
		}
	|
	ATTRIBUTE_ROLE comma_string_list SEMICOLON {
		for (const struct string_list *iter = $2; iter; iter = iter->next) insert_declaration(&cur, DECL_ATTRIBUTE_ROLE, iter->string, NULL, @$.first_line);
		free_string_list($2);
		}
	|
	BOOL comma_string_list SEMICOLON {
		for (const struct string_list *iter = $2; iter; iter = iter->next) insert_declaration(&cur, DECL_BOOL, iter->string, NULL, @$.first_line);
		free_string_list($2);
		}
	|
	CLASS STRING string_list SEMICOLON { insert_declaration(&cur, DECL_CLASS, $2, $3, @$.first_line); free($2); }
	|
	if_or_ifn OPEN_PAREN BACKTICK STRING SINGLE_QUOTE COMMA BACKTICK { begin_ifdef(&cur, @$.first_line); }
	require_lines SINGLE_QUOTE CLOSE_PAREN { end_ifdef(&cur); free($4); }
	|
	if_or_ifn OPEN_PAREN BACKTICK STRING SINGLE_QUOTE COMMA { begin_ifdef(&cur, @$.first_line); }
	require_lines CLOSE_PAREN { end_ifdef(&cur); free($4); }
	|
	COMMENT
	;

m4_simple_macro:
	STRING { insert_m4simplemacro(&cur, $1, @$.first_line); }
	;

m4_call:
	ifdef
	|
	ifelse
	|
	refpolicywarn
	|
	userdebug_or_eng
	;

ifdef:
	if_or_ifn OPEN_PAREN BACKTICK STRING SINGLE_QUOTE COMMA { begin_ifdef(&cur, @$.first_line); }
	m4_args CLOSE_PAREN { end_ifdef(&cur); free($4); }
	;

if_or_ifn:
	IFDEF
	|
	IFNDEF
	;

ifelse:
	IFELSE OPEN_PAREN { begin_ifelse(&cur, @$.first_line); } m4_args CLOSE_PAREN { end_ifelse(&cur); }
	;

refpolicywarn:
	REFPOLICYWARN OPEN_PAREN BACKTICK arbitrary_m4_string SINGLE_QUOTE CLOSE_PAREN
	;

userdebug_or_eng:
	USERDEBUG_OR_ENG OPEN_PAREN BACKTICK lines SINGLE_QUOTE CLOSE_PAREN
	;

arbitrary_m4_string:
	m4_string_elem
	|
	m4_string_elem arbitrary_m4_string
	|
	BACKTICK m4_string_elem SINGLE_QUOTE
	;

m4_string_elem:
	STRING { free($1); }
	|
	OPEN_PAREN
	|
	CLOSE_PAREN
	|
	OPEN_CURLY
	|
	CLOSE_CURLY
	|
	COMMA
	|
	PERIOD
	|
	COLON
	|
	SEMICOLON
	|
	DASH
	;

condition:
	STRING { save_identifier(cur->parent, $1); }
	|
	NOT condition
	|
	condition AND condition
	|
	condition OR condition
	|
	condition XOR condition
	|
	condition EQUAL condition
	|
	condition NOT_EQUAL condition
	|
	OPEN_PAREN condition CLOSE_PAREN
	;

m4_args:
	{ begin_m4_argument(&cur, @$.first_line); } m4_argument { end_m4_argument(&cur); }
	|
	m4_args COMMA { begin_m4_argument(&cur, @$.first_line); } m4_argument { end_m4_argument(&cur); }
	;

m4_argument:
	%empty
	|
	BACKTICK SINGLE_QUOTE
	|
	BACKTICK lines SINGLE_QUOTE
	|
	STRING { free($1); }
	;

arg:
	xperm_list
	|
	QUOTED_STRING { $$ = sl_from_str_consume($1); }
	|
	BACKTICK strings SINGLE_QUOTE { $$ = $2; }
	|
	BACKTICK SINGLE_QUOTE { $$ = sl_from_str(""); }
	;

args:
	arg
	|
	args COMMA arg { $$ = concat_string_lists($1, $3); }
	|
	args sl_item { struct string_list *sl = calloc(1, sizeof(struct string_list));
			sl->string = $2;
			sl->has_incorrect_space = 1;
			$$ = concat_string_lists($1, sl); }
	;

mls_range:
	mls_level DASH mls_level { size_t len = strlen($1) + strlen($3) + 1 /* DASH */ + 1 /* NT */;
				$$ = malloc(len);
				snprintf($$, len, "%s-%s", $1, $3);
				free($1); free($3); }
	|
	mls_level
	;

mls_level:
	mls_component
	|
	mls_component COLON mls_component { size_t len = strlen($1) + strlen($3) + 1 /* COLON */ + 1 /* NT */;
				$$ = malloc(len);
				snprintf($$, len, "%s:%s", $1, $3);
				free($1); free($3); }
	;

mls_component:
	STRING { $$ = strdup($1); free($1); }
	|
	STRING PERIOD STRING { size_t len = strlen($1) + strlen($3) + 1 /* PERIOD */ + 1 /* NT */;
				$$ = malloc(len);
				snprintf($$, len, "%s.%s", $1, $3);
				free($1); free($3); }
	;

cond_expr:
	tunable_block
	|
	boolean_block
	;

boolean_block:
	boolean_open condition CLOSE_PAREN OPEN_CURLY lines CLOSE_CURLY { end_boolean_policy(&cur); }
	|
	boolean_open condition CLOSE_PAREN OPEN_CURLY lines CLOSE_CURLY
	ELSE OPEN_CURLY lines CLOSE_CURLY { end_boolean_policy(&cur); }
	;

boolean_open:
	IF OPEN_PAREN { begin_boolean_policy(&cur, @$.first_line); }
	|
	IF OPEN_PAREN SELINT_COMMAND { begin_boolean_policy(&cur, @$.first_line); save_command(cur->parent, $3); free($3); }
	;

tunable_block:
	TUNABLE_POLICY OPEN_PAREN BACKTICK { begin_tunable_policy(&cur, @$.first_line); }
	condition SINGLE_QUOTE COMMA m4_args CLOSE_PAREN { end_tunable_policy(&cur); }
	|
	TUNABLE_POLICY OPEN_PAREN { begin_tunable_policy(&cur, @$.first_line); }
	condition COMMA m4_args CLOSE_PAREN { end_tunable_policy(&cur); }
	;

genfscon:
	GENFSCON STRING STRING genfscon_context { free($2); free($3); }
	|
	GENFSCON NUM_STRING STRING genfscon_context { free($2); free($3); }
	;

genfscon_context:
	context
	|
	FILE_TYPE_SPECIFIER context
	;

sid:
	SID STRING context { free($2); }
	;

portcon:
	PORTCON STRING port_range context { free($2); }
	;

port_range:
	NUM_STRING { free($1); }
	|
	NUMBER { free($1); }
	|
	// TODO: This only happens with whitespace around the dash.  NUM_STRING catches "1000-1001" type
	// names.  Is that actually a valid scenario?
	NUMBER DASH NUMBER { free($1); free($3); }
	;

netifcon:
	NETIFCON STRING context context { free($2); }
	;

nodecon:
	NODECON two_ip_addrs context
	;

two_ip_addrs:
	IPV4 IPV4 { free($1); free($2); }
	|
	IPV6 IPV6 { free($1); free($2); }
	;

fs_use:
	FS_USE_TRANS STRING context SEMICOLON { free($2); }
	|
	FS_USE_XATTR STRING context SEMICOLON { free($2); }
	|
	FS_USE_TASK STRING context SEMICOLON { free($2); }
	;

define:
	DEFINE OPEN_PAREN { begin_define(&cur, @$.first_line); }
	define_name define_content CLOSE_PAREN { end_define(&cur); }
	;

define_name:
	BACKTICK STRING SINGLE_QUOTE { free($2); }
	|
	STRING { free($1); }
	;

define_content:
	%empty
	|
	COMMA define_expansion
	;

define_expansion:
	%empty
	|
	BACKTICK arbitrary_m4_string SINGLE_QUOTE
	|
	STRING { free($1); }
	;

maybe_string_comma:
	STRING COMMA { $$ = $1; }
	|
	COMMA { $$ = strdup(""); }
	;

gen_user:
	GEN_USER OPEN_PAREN maybe_string_comma maybe_string_comma strings COMMA mls_range COMMA mls_range CLOSE_PAREN { free($3); free($4); free_string_list($5); free($7); free($9); }
	|
	GEN_USER OPEN_PAREN maybe_string_comma maybe_string_comma strings COMMA mls_range COMMA mls_range COMMA mls_range CLOSE_PAREN { free($3); free($4); free_string_list($5); free($7); free($9); free($11); }
	;

context:
	raw_context
	|
	GEN_CONTEXT OPEN_PAREN raw_context CLOSE_PAREN
	|
	GEN_CONTEXT OPEN_PAREN raw_context COMMA mls_range CLOSE_PAREN { free($5); }
	|
	GEN_CONTEXT OPEN_PAREN raw_context COMMA mls_range COMMA mls_range CLOSE_PAREN { free($5); free($7); }
	|
	GEN_CONTEXT OPEN_PAREN raw_context COMMA mls_range COMMA CLOSE_PAREN { free($5); }
	;

raw_context:
	STRING COLON STRING COLON STRING { free($1); free($3); free($5); }
	|
	STRING COLON STRING COLON STRING COLON mls_range { free($1); free($3); free($5); free($7); }
	;

permissive:
	PERMISSIVE STRING SEMICOLON { insert_permissive_statement(&cur, $2, @$.first_line); free($2);}
	;

typebounds:
	TYPEBOUNDS STRING STRING SEMICOLON { free($2); free($3); }
	;

	// IF File parsing
if_file:
	interface_def if_lines
	|
	interface_def
	//|
	// Empty file
	//EOF
	;

if_lines:
	if_lines if_line
	|
	if_line
	;

if_line:
	interface_def
	|
	COMMENT { insert_comment(&cur, @$.first_line); }
	;

interface_def:
	start_interface lines end_interface
	|
	start_interface end_interface
	;

start_interface:
	if_keyword OPEN_PAREN BACKTICK STRING SINGLE_QUOTE COMMA BACKTICK {
				if (expected_node_flavor != NODE_IF_FILE) {
					const struct location loc = { @1.first_line, @1.first_column, @7.last_line, @7.last_column };
					yyerror(&loc, NULL, "Error: Unexpected if-file parsed");
					YYERROR;
				}
				begin_interface_def(&cur, $1, $4, @$.first_line); free($4); }
	;

end_interface:
	SINGLE_QUOTE CLOSE_PAREN { end_interface_def(&cur); }
	;

if_keyword:
	INTERFACE { $$ = NODE_INTERFACE_DEF; }
	|
	TEMPLATE { $$ = NODE_TEMP_DEF; }
	;

	// spt file parsing
spt_file:
	support_def spt_lines
	|
	support_def
	;

spt_lines:
	spt_lines spt_line
	|
	spt_line
	;

spt_line:
	support_def
	|
	COMMENT
	;

support_def:
	DEFINE OPEN_PAREN BACKTICK STRING SINGLE_QUOTE COMMA BACKTICK string_list SINGLE_QUOTE CLOSE_PAREN {
			if (expected_node_flavor != NODE_SPT_FILE) {
				free($4); free_string_list($8);
				const struct location loc = { @1.first_line, @1.first_column, @10.last_line, @10.last_column };
				yyerror(&loc, NULL, "Error: Unexpected spt-file parsed"); YYERROR;
			}
			if (ends_with($4, strlen($4), "_perms", strlen("_perms"))) {
				insert_into_permmacros_map($4, $8);
			} else {
				free_string_list($8);
			}
			free($4); }
	|
	DEFINE OPEN_PAREN BACKTICK STRING SINGLE_QUOTE COMMA BACKTICK string_list refpolicywarn SINGLE_QUOTE CLOSE_PAREN {
			if (expected_node_flavor != NODE_SPT_FILE) {
				free($4); free_string_list($8);
				const struct location loc = { @1.first_line, @1.first_column, @11.last_line, @11.last_column };
				yyerror(&loc, NULL, "Error: Unexpected spt-file parsed"); YYERROR;
			}
			free($4); free_string_list($8); } // do not import
	;

// access-vector file

av_file: // must not allow a comment to be first -> parser conflict
	av_definition av_contents
	|
	av_definition
	;

av_contents:
	av_contents av_content
	|
	av_content
	;

av_content:
	av_definition
	|
	COMMENT
	;

av_definition:
	av_class_definition
	|
	av_common_definition
	;

av_class_definition:
	CLASS STRING av_permission_list {
			if (expected_node_flavor != NODE_AV_FILE) {
				free($2);
				const struct location loc = { @1.first_line, @1.first_column, @3.last_line, @3.last_column };
				yyerror(&loc, NULL, "Error: Unexpected av-file parsed"); YYERROR;
			}
			insert_into_decl_map($2, "__av_file__", DECL_CLASS); free($2); }
	|
	CLASS STRING INHERITS STRING {
			if (expected_node_flavor != NODE_AV_FILE) {
				free($2); free($4);
				const struct location loc = { @1.first_line, @1.first_column, @4.last_line, @4.last_column };
				yyerror(&loc, NULL, "Error: Unexpected av-file parsed"); YYERROR;
			}
			insert_into_decl_map($2, "__av_file__", DECL_CLASS); free($2); free($4); }
	|
	CLASS STRING INHERITS STRING av_permission_list {
			if (expected_node_flavor != NODE_AV_FILE) {
				free($2); free($4);
				const struct location loc = { @1.first_line, @1.first_column, @5.last_line, @5.last_column };
				yyerror(&loc, NULL, "Error: Unexpected av-file parsed"); YYERROR;
			}
			insert_into_decl_map($2, "__av_file__", DECL_CLASS); free($2); free($4); }
	;

av_common_definition:
	COMMON STRING av_permission_list { free($2); }
	;

av_permission_list:
	OPEN_CURLY av_permissions CLOSE_CURLY
	;

av_permissions:
	av_permissions av_permission
	|
	av_permission
	;

av_permission:
	STRING { insert_into_decl_map($1, "__av_file__", DECL_PERM); free($1); }
	|
	COMMENT
	;

// policy/global_booleans and policy/global_tunables files

global_conditions_file: // must not allow a comment to be first -> parser conflict
	gcf_definition gcf_contents
	|
	gcf_definition
	;

gcf_contents:
	gcf_contents gcf_content
	|
	gcf_content
	;

gcf_content:
	gcf_definition
	|
	COMMENT
	;

gcf_definition:
	bool_declaration {
		if (expected_node_flavor != NODE_COND_FILE) {
				const struct location loc = { @1.first_line, @1.first_column, @1.last_line, @1.last_column };
				yyerror(&loc, NULL, "Error: Unexpected global conditionals file parsed"); YYERROR;
		} }
	;

%%
static unsigned leading_spaces(const char *str) {
	unsigned result = 0;
	while (str[result] == ' ' || str[result] == '\t')
		result++;
	return result;
}

static void yyerror(const YYLTYPE *locp, __attribute__((unused)) yyscan_t scanner, char const *msg) {

	// Print error tag: """test7.if:             1: (F): Error: Unexpected te-file parsed (F-001)"""
	{
		struct check_result *res = make_check_result('F', F_ID_POLICY_SYNTAX, "%s", msg);
		res->lineno = locp->first_line;

		struct check_data data;
		data.mod_name = get_current_module_name();
		char *copy = strdup(parsing_filename);
		data.filename = basename(copy);
		data.flavor = FILE_TE_FILE; // We don't know but it's unused by display_check_result

		display_check_result(res, &data);

		free(copy);
		free_check_result(res);
	}

	unsigned lines_to_print = locp->last_line - locp->first_line + 1;
	bool shortened = false;
	if (lines_to_print > LINES_TO_CACHE) {
		lines_to_print = LINES_TO_CACHE;
		shortened = true;
		printf("%5u |  ...  [truncated]\n", locp->last_line - LINES_TO_CACHE);
	}

	for (unsigned k = lines_to_print; k > 0; --k) {

		const char *current_line = trim_right(current_lines[(LINES_TO_CACHE + line_cache_index - k + 1) % LINES_TO_CACHE]);
		const unsigned current_first_column = (k == lines_to_print && !shortened) ? locp->first_column : (1 + leading_spaces(current_line));
		const unsigned current_last_column = (k == 1) ? locp->last_column : (unsigned)strlen(current_line);

		printf("%5u |", locp->last_line - (k - 1));

		// print line, replace tabs
		unsigned tabs_before_hinter = 0, tabs_inside_hinter = 0;
		if (*current_line != '\0') {
			printf(" ");
		}
		for (const char *c = current_line; *c != '\0'; ++c) {
			if (*c == '\t') {
				if ((size_t)(c - current_line) < current_first_column) {
					tabs_before_hinter++;
				} else if ((size_t)(c - current_line) < current_last_column) {
					tabs_inside_hinter++;
				}
				printf("    ");
				continue;
			}

			if (!isprint((unsigned char)*c) && !isspace((unsigned char)*c)) {
				printf("%s!%s\n%sWarning%s: Line in question contains unprintable character at position %zu: 0x%.2x\n",
				       color_error(), color_reset(),
				       color_warning(), color_reset(),
				       (size_t)(c - current_line + 1),
				       *c);
				return;
			}

			printf("%c", *c);
		}

		printf("\n      | ");

		// print hinter
		for (unsigned i = 0; i < tabs_before_hinter; ++i) {
			printf("    ");
		}
		for (unsigned i = tabs_before_hinter + 1; i < current_first_column; ++i) {
			printf(" ");
		}

		if (k == lines_to_print) {
			printf("%s^", color_error());
		} else {
			printf("%s~", color_error());
		}

		if (current_last_column > current_first_column) {
			for (unsigned i = 0; i < (current_last_column - current_first_column); ++i) {
				printf("~");
			}
			for (unsigned i = 0; i < tabs_inside_hinter; ++i) {
				printf("~~~");
			}
		}
		printf("%s\n", color_reset());
	}
}

struct policy_node *yyparse_wrapper(FILE *filefd, const char *filename, enum node_flavor expected_flavor) {
	struct policy_node *ast = calloc(1, sizeof(struct policy_node));
	ast->flavor = expected_node_flavor = expected_flavor;
	yyscan_t scanner;
	yylex_init(&scanner);
	yyrestart(filefd, scanner);
	parsing_filename = filename;
	cur = ast;

	const int ret = yyparse(scanner);

	reset_current_lines();
	yylex_destroy(scanner);

	if (ret != 0) {
		// parser will have printed an error message
		free_policy_node(ast);
		return NULL;
	}

	return ast;
}
