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

#include <stdio.h>
#include <getopt.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fts.h>
#include <unistd.h>
#include <sysexits.h>

#include "runner.h"
#include "parse.h"
#include "config.h"
#include "file_list.h"
#include "util.h"
#include "selint_config.h"
#include "startup.h"
#include "color.h"

// ASCII characters go up to 127
#define CONTEXT_ID          128
#define COLOR_ID            129
#define SUMMARY_ONLY_ID     130
#define SCAN_HIDDEN_DIRS_ID 131
#define DEBUG_PARSER_ID     132

extern int yydebug;

extern int verbose_flag;

static void usage(void)
{

	/* *INDENT-OFF* */
	printf("Usage: selint [OPTIONS] FILE [...]\n"\
		"Perform static code analysis on SELinux policy source.\n\n");
	printf("  -c, --config=CONFIGFILE\tOverride default config with config\n"\
		"\t\t\t\tspecified on command line.  See\n"\
		"\t\t\t\tCONFIGURATION section for config file syntax.\n"\
		"      --color=COLOR_OPTION\tConfigure color output.\n"\
		"\t\t\t\tOptions are on, off and auto (the default).\n"\
		"      --context=CONTEXT_PATH\tRecursively scan CONTEXT_PATH to find additional te and if\n"\
		"\t\t\t\tfiles to parse, but not scan.  SELint will assume the scanned policy files\n"\
		"\t\t\t\tare intended to be compiled together with the context files.\n"\
		"\t\t\t\tare intended to be compiled together with the context files.  Implies -s.\n"\
		"      --debug-parser\t\tEnable debug output for the internal policy parser.\n"\
		"\t\t\t\tVery noisy, useful to debug parsing failures.\n"\
		"  -d, --disable=CHECKID\t\tDisable check with the given ID.\n"\
		"  -e, --enable=CHECKID\t\tEnable check with the given ID.\n"\
		"  -E, --only-enabled\t\tOnly run checks that are explicitly enabled with\n"\
		"\t\t\t\tthe --enable option.\n"\
		"  -F, --fail\t\t\tExit with a non-zero value if any issue was found.\n"\
		"  -h, --help\t\t\tDisplay this menu.\n"\
		"  -l, --level=LEVEL\t\tOnly list errors with a severity level at or\n"\
		"\t\t\t\tgreater than LEVEL.  Options are C (convention), S (style),\n"\
		"\t\t\t\tW (warning), E (error), F (fatal error).\n"\
		"      --scan-hidden-dirs\tScan hidden directories.\n"\
		"\t\t\t\tBy default hidden directories (like '.git') are skipped in recursive mode.\n"\
		"  -s, --source\t\t\tRun in \"source mode\" to scan a policy source repository\n"\
		"\t\t\t\tthat is designed to compile into a full system policy.\n"\
		"  -S, --summary\t\t\tDisplay a summary of issues found after running the analysis.\n"\
		"      --summary-only\t\tOnly display a summary of issues found after running the analysis.\n"\
		"\t\t\t\tDo not show the individual findings.  Implies -S.\n"\
		"  -r, --recursive\t\tScan recursively and check all SELinux policy files found.\n"\
		"  -v, --verbose\t\t\tEnable verbose output.\n"\
		"  -V, --version\t\t\tShow version information and exit.\n"
);
	/* *INDENT-ON* */

}

#define WARN_ON_INVALID_CHECK_ID(id, desc)\
	if (!is_valid_check(id)) {\
		printf("%sWarning%s: %s, %s, is not a valid check id.\n", color_warning(), color_reset(), id, desc);\
	}

int main(int argc, char **argv)
{

	char severity = '\0';
	const char *config_filename = NULL;
	int source_flag = 0;
	int recursive_scan = 0;
	int only_enabled = 0;
	int exit_code = EX_OK;
	int summary_flag = 0;
	int fail_on_finding = 0;
	int scan_hidden_dirs = 0;
	struct string_list *context_paths = NULL;
	char color = 0;  // 0 auto, 1 off, 2 on

	struct string_list *config_disabled_checks = NULL;
	struct string_list *config_enabled_checks = NULL;
	struct string_list *cl_disabled_checks = NULL;
	struct string_list *cl_enabled_checks = NULL;

	struct string_list *custom_fc_macros = NULL;

	struct string_list *cl_e_cursor = NULL;
	struct string_list *cl_d_cursor = NULL;

	yydebug = 0;

	while (1) {

		static const struct option long_options[] = {
			{ "config",           required_argument, NULL,          'c' },
			{ "context",          required_argument, NULL,          CONTEXT_ID },
			{ "debug-parser",     no_argument,       NULL,          DEBUG_PARSER_ID },
			{ "disable",          required_argument, NULL,          'd' },
			{ "enable",           required_argument, NULL,          'e' },
			{ "fail",             no_argument,       NULL,          'F' },
			{ "only-enabled",     no_argument,       NULL,          'E' },
			{ "help",             no_argument,       NULL,          'h' },
			{ "level",            required_argument, NULL,          'l' },
			{ "modules-conf",     required_argument, NULL,          'm' },
			{ "recursive",        no_argument,       NULL,          'r' },
			{ "source",           no_argument,       NULL,          's' },
			{ "summary",          no_argument,       NULL,          'S' },
			{ "color",            required_argument, NULL,          COLOR_ID },
			{ "scan-hidden-dirs", no_argument,       NULL,          SCAN_HIDDEN_DIRS_ID },
			{ "summary-only",     no_argument,       NULL,          SUMMARY_ONLY_ID },
			{ "version",          no_argument,       NULL,          'V' },
			{ "verbose",          no_argument,       &verbose_flag, 1   },
			{ 0,                  0,                 0,             0   }
		};

		int option_index = 0;

		int c = getopt_long(argc,
		                    argv,
		                    "c:d:e:EFhl:mrsSVv",
		                    long_options,
		                    &option_index);

		if (c == -1) {
			break;
		}

		switch (c) {

		case 0:
			break;

		case 'c':
			// Specify config file
			config_filename = optarg;
			break;

		case CONTEXT_ID:
			// Specify a path for context files
			if (!context_paths) {
				context_paths = sl_from_str(optarg);
			} else {
				append_to_sl(context_paths, optarg);
			}
			// Don't parse system devel policies if a context is given
			source_flag = 1;
			break;

		case COLOR_ID:
			if (0 == strcmp(optarg, "on")) {
				color = 2;
			} else if (0 == strcmp(optarg, "off")) {
				color = 1;
			} else if (0 == strcmp(optarg, "auto")) {
				color = 0;
			} else {
				printf("Invalid argument '%s' given for option --color\n", optarg);
				usage();
				exit(EX_USAGE);
			}
			break;

		case DEBUG_PARSER_ID:
			// Enable debug mode for the internal parser
			yydebug = 1;
			break;

		case 'd':
			// Disable a given check
			if (cl_d_cursor) {
				cl_d_cursor->next =
					calloc(1, sizeof(struct string_list));
				cl_d_cursor = cl_d_cursor->next;
			} else {
				cl_d_cursor =
					calloc(1, sizeof(struct string_list));
				cl_disabled_checks = cl_d_cursor;
			}
			cl_d_cursor->string = strdup(optarg);
			break;

		case 'e':
			// Enable a given check
			if (cl_e_cursor) {
				cl_e_cursor->next =
					calloc(1, sizeof(struct string_list));
				cl_e_cursor = cl_e_cursor->next;
			} else {
				cl_e_cursor =
					calloc(1, sizeof(struct string_list));
				cl_enabled_checks = cl_e_cursor;
			}
			cl_e_cursor->string = strdup(optarg);
			break;

		case 'E':
			// Only run checks enabled by the --enable flag.
			only_enabled = 1;
			break;

		case 'F':
			// Exit non-zero if any issue was found
			fail_on_finding = 1;
			break;

		case 'h':
			// Display usage info and exit
			usage();
			exit(0);

		case 'l':
			// Set the severity level
			severity = optarg[0];
			if (!is_valid_severity(severity)) {
				printf("Invalid argument '%s' given for option --level\n", optarg);
				usage();
				exit(EX_USAGE);
			}
			break;

		case 'm':
			// Specify a modules.conf file.  (Not in the README)
			// TODO
			break;

		case 'r':
			// Scan recursively for files to parse
			recursive_scan = 1;
			break;

		case 's':
			// Run in source mode
			source_flag = 1;
			break;

		case SCAN_HIDDEN_DIRS_ID:
			// Scan hidden directories in recursive mode
			scan_hidden_dirs = 1;
			break;

		case SUMMARY_ONLY_ID:
			// Do not display individual findings
			suppress_output = 1;
			// FALLTHRU
		case 'S':
			// Display a summary at the end of the run
			summary_flag = 1;
			break;

		case 'V':
			// Output version info and exit
			printf("SELint %s\n", VERSION);
			exit(0);

		case 'v':
			// Run in verbose mode
			verbose_flag = 1;
			break;

		case '?':
			usage();
			exit(EX_USAGE);
		}

	}

	print_if_verbose("Verbose mode enabled\n");

	if (color == 2 || (color == 0 && isatty(STDOUT_FILENO))) {
		color_enable();
		print_if_verbose("Color output enabled\n");
	}

	if (source_flag) {
		print_if_verbose("Source mode enabled\n");

		if (!recursive_scan) {
			printf("%sNote%s: Source mode enabled without recursive flag (only explicit specified files will be checked).\n", color_note(), color_reset());
		}
	}

	for (const struct string_list * cur = cl_disabled_checks; cur; cur = cur->next) {
		WARN_ON_INVALID_CHECK_ID(cur->string, "disabled on command line");
	}
	for (const struct string_list * cur = cl_enabled_checks; cur; cur = cur->next) {
		WARN_ON_INVALID_CHECK_ID(cur->string, "enabled on command line");
	}

	if (config_filename && 0 != access(config_filename, R_OK)) {
		printf("%sError%s: No configuration file found at '%s'!\n", color_error(), color_reset(), config_filename);
		exit(EX_USAGE);
	} else if (!config_filename) {
		config_filename = SYSCONFDIR "/selint.conf";    // Default install path
		if (0 != access(config_filename, R_OK)) {
			//No default config found
			print_if_verbose(
				"No config specified and could not find default config at %s.\n",
				config_filename);
			config_filename = NULL;
		}
	}

	struct config_check_data ccd = { ORDER_LAX, {}, true, true, NULL };

	if (config_filename) {
		char cfg_severity;
		if (SELINT_SUCCESS != parse_config(config_filename, source_flag,
		                                   &cfg_severity, &config_disabled_checks,
		                                   &config_enabled_checks, &custom_fc_macros, &ccd)) {
			// Error message printed by parse_config()
			exit(EX_CONFIG);
		}
		if (severity == '\0') {
			severity = cfg_severity;
		}
	} else {
		// If there is no config, we should assume the existence of normal users and
		// roles that we wouldn't otherwise know about
		insert_into_decl_map("system_u", "__assumed__", DECL_USER);
		insert_into_decl_map("object_r", "__assumed__", DECL_ROLE);
	}

	for (const struct string_list *config_check_id = config_disabled_checks; config_check_id; config_check_id = config_check_id->next) {
		WARN_ON_INVALID_CHECK_ID(config_check_id->string, "disabled in config");
	}
	for (const struct string_list *config_check_id = config_enabled_checks; config_check_id; config_check_id = config_check_id->next) {
		WARN_ON_INVALID_CHECK_ID(config_check_id->string, "enabled in config");
	}

	if (only_enabled && !cl_enabled_checks) {
		printf("%sError%s: no warning enabled!\n", color_error(), color_reset());
		exit(EX_USAGE);
	}

	if (severity == '\0') {
		severity = 'C';
	}

	print_if_verbose("Severity level set to %c\n", severity);

	if (optind == argc) {
		usage();
		exit(EX_USAGE);
	}

	struct policy_file_list *te_files =
		calloc(1, sizeof(struct policy_file_list));

	struct policy_file_list *if_files =
		calloc(1, sizeof(struct policy_file_list));

	struct policy_file_list *fc_files =
		calloc(1, sizeof(struct policy_file_list));

	struct policy_file_list *context_te_files =
		calloc(1, sizeof(struct policy_file_list));

	struct policy_file_list *context_if_files =
		calloc(1, sizeof(struct policy_file_list));

	char **paths = malloc(sizeof(char *) * (unsigned)argc - (unsigned)optind + 2);

	int i = 0;
	while (optind < argc) {
		print_if_verbose("Path added to scan: '%s'\n", argv[optind]);
		paths[i++] = argv[optind++];
	}

	paths[i] = NULL;

	FTS *ftsp = fts_open(paths, FTS_PHYSICAL | FTS_NOSTAT, NULL);

	FTSENT *file = fts_read(ftsp);

	char *modules_conf_path = NULL;
	char *obj_perm_sets_path = NULL;
	char *access_vector_path = NULL;
	struct string_list *global_cond_files = NULL;

	while (file) {
		const char *suffix = (file->fts_pathlen > 3) ? (file->fts_path + file->fts_pathlen - 3) : NULL;

		if (suffix && !strcmp(suffix, ".te")) {
			file_list_push_back(te_files,
			                    make_policy_file(file->fts_path,
			                                     NULL));
		} else if (suffix && !strcmp(suffix, ".if")) {
			file_list_push_back(if_files,
			                    make_policy_file(file->fts_path,
			                                     NULL));
			char *mod_name = strdup(file->fts_name);
			mod_name[file->fts_namelen - 3] = '\0';
			insert_into_mod_layers_map(mod_name, file->fts_parent->fts_name);
			free(mod_name);
		} else if (suffix && !strcmp(suffix, ".fc")) {
			file_list_push_back(fc_files,
			                    make_policy_file(file->fts_path,
			                                     NULL));
		} else if (source_flag
		           && !strcmp(file->fts_name, "modules.conf")) {
			// TODO: Make modules.conf name configurable
			modules_conf_path = strdup(file->fts_path);
		} else if (source_flag
		           && !strcmp(file->fts_name, "obj_perm_sets.spt")) {
			// TODO: Make obj_perm_sets.spt name configurable
			obj_perm_sets_path = strdup(file->fts_path);
		} else if (source_flag
		           && !strcmp(file->fts_name, "access_vectors")) {
			// TODO: Make access_vectors name configurable
			access_vector_path = strdup(file->fts_path);
		} else if (source_flag
		           && (!strcmp(file->fts_name, "global_booleans") || !strcmp(file->fts_name, "global_tunables"))) {
			// TODO: Make names configurable
			global_cond_files = concat_string_lists(global_cond_files, sl_from_str(file->fts_path));
		} else {
			// Directories might get traversed twice: preorder and final visit.
			// Print only the final visit
			if (file->fts_info != FTS_D) {
				if (recursive_scan) {
					print_if_verbose("Skipping %s which is not a policy file\n",
						         file->fts_path);
				} else {
					printf("%sNote%s: Skipping %s which is not a policy file\n",
					       color_note(), color_reset(), file->fts_path);
				}
			}

			if (!recursive_scan) {
				fts_set(ftsp, file, FTS_SKIP);
			}

			if (!scan_hidden_dirs &&
			    file->fts_info == FTS_D &&
			    file->fts_name[0] == '.' &&
			    file->fts_name[1] != '.' &&
			    file->fts_name[1] != '\0') {
				print_if_verbose("Skipping hidden directory %s\n", file->fts_path);
				fts_set(ftsp, file, FTS_SKIP);
			}
		}

		file = fts_read(ftsp);
	}

	fts_close(ftsp);

	struct string_list *context_path_node = context_paths;

	while (context_path_node) {
		paths[0] = context_path_node->string;
		paths[1] = NULL;

		ftsp = fts_open(paths, FTS_PHYSICAL | FTS_NOSTAT, NULL);
		file = fts_read(ftsp);

		while (file) {
			const char *suffix = (file->fts_pathlen > 3) ? (file->fts_path + file->fts_pathlen - 3) : NULL;
			if (suffix &&  !strcmp(suffix, ".te")) {
				if (!file_name_in_file_list(file->fts_path, te_files)) {
					file_list_push_back(context_te_files,
							    make_policy_file(file->fts_path,
							    NULL));
				}
			} else if (suffix &&  !strcmp(suffix, ".if")) {
				if (!file_name_in_file_list(file->fts_path, if_files)) {
					file_list_push_back(context_if_files,
							    make_policy_file(file->fts_path,
							    NULL));
				}
			} else if (source_flag
                                   && !modules_conf_path
                                   && 0 == strcmp(file->fts_name, "modules.conf")) {
				modules_conf_path = strdup(file->fts_path);
			} else if (source_flag
                                   && !obj_perm_sets_path
                                   && 0 == strcmp(file->fts_name, "obj_perm_sets.spt")) {
				obj_perm_sets_path = strdup(file->fts_path);
			} else if (source_flag
                                   && !access_vector_path
                                   && 0 == strcmp(file->fts_name, "access_vectors")) {
				access_vector_path = strdup(file->fts_path);
			} else if (source_flag
			           && !str_in_sl(file->fts_path, global_cond_files)
			           && (0 == strcmp(file->fts_name, "global_booleans") || 0 == strcmp(file->fts_name, "global_tunables"))) {
				global_cond_files = concat_string_lists(global_cond_files, sl_from_str(file->fts_path));
			}
			file = fts_read(ftsp);
		}

		fts_close(ftsp);
		context_path_node = context_path_node->next;
	}

	free_string_list(context_paths);
	free(paths);

	// Load object classes and permissions
	if (source_flag) {
		if (access_vector_path) {
			enum selint_error res = load_access_vectors_source(access_vector_path);
			if (res != SELINT_SUCCESS) {
				printf("%sWarning%s: Failed to parse access_vectors from %s: %d\n", color_warning(), color_reset(), access_vector_path, res);
			} else {
				print_if_verbose("Loaded classes and permissions from %s\n", access_vector_path);
			}
		} else {
			printf("%sWarning%s: Failed to locate access_vectors file.\n", color_warning(), color_reset());
		}

		if (modules_conf_path) {
			enum selint_error res =
				load_modules_source(modules_conf_path);
			if (res != SELINT_SUCCESS) {
				printf("%sWarning%s: Failed to load modules from %s: %d\n", color_warning(), color_reset(), modules_conf_path, res);
			} else {
				print_if_verbose("Loaded modules from %s\n",
				                 modules_conf_path);
			}
		} else {
			printf("%sWarning%s: Failed to locate modules.conf file.\n", color_warning(), color_reset());
		}

		if (obj_perm_sets_path) {
			enum selint_error res =
				load_obj_perm_sets_source(obj_perm_sets_path);
			if (res != SELINT_SUCCESS) {
				printf("%sWarning%s: Failed to permission and class set macros from %s: %d\n", color_warning(), color_reset(), obj_perm_sets_path, res);
			} else {
				print_if_verbose("Loaded permission and class set macros from %s\n",
				                 obj_perm_sets_path);
			}
		} else {
			printf("%sWarning%s: Failed to locate obj_perm_sets.spt file.\n", color_warning(), color_reset());
		}

		if (global_cond_files) {
			enum selint_error res = load_global_conditions(global_cond_files);
			if (res != SELINT_SUCCESS) {
				printf("%sWarning%s: Failed to parse global conditions: %d\n", color_warning(), color_reset(), res);
			} else {
				print_if_verbose("Loaded global conditions\n");
			}
		} else {
			printf("%sWarning%s: Failed to locate global conditions files.\n", color_warning(), color_reset());
		}

	} else {
		enum selint_error r = load_access_vectors_kernel("/sys/fs/selinux/class");
		if (r != SELINT_SUCCESS) {
			if (r == SELINT_IO_ERROR) {
				printf("%sNote%s: Failed to load classes and perms probably due to running on a SELinux disabled system.\n",
				       color_note(), color_reset());
			} else {
				printf("%sWarning%s: Failed to load classes and perms from current kernel.\n",
				       color_warning(), color_reset());
			}
		}

		load_modules_normal();
		enum selint_error res = load_devel_headers(context_if_files);
		if (res != SELINT_SUCCESS) {
			printf("%sWarning%s: Failed to load SELinux development header files.\n", color_warning(), color_reset());
		}
	}

	/* Delay until support files have been parsed for check conditions. */
	struct checks *ck = register_checks(severity,
	                                    config_enabled_checks,
	                                    config_disabled_checks,
	                                    cl_enabled_checks,
	                                    cl_disabled_checks,
	                                    only_enabled);

	if (!ck) {
		printf("%sError%s: Failed to register checks (bad configuration)\n", color_error(), color_reset());
		free_file_list(te_files);
		free_file_list(if_files);
		free_file_list(fc_files);
		free_file_list(context_te_files);
		free_file_list(context_if_files);
		free(obj_perm_sets_path);
		free(access_vector_path);
		free(modules_conf_path);
		free_string_list(global_cond_files);
		return EX_CONFIG;
	}

	free(obj_perm_sets_path);
	free(access_vector_path);
	free(modules_conf_path);
	free_string_list(global_cond_files);

	enum selint_error res = run_analysis(ck, te_files, if_files, fc_files, context_te_files, context_if_files, custom_fc_macros, &ccd);
	switch (res) {
	case SELINT_SUCCESS:
		if (summary_flag) {
			display_run_summary(ck);
		}
		break;
	case SELINT_PARSE_ERROR:
		printf("%sError%s: Failed to parse files\n", color_error(), color_reset());
		exit_code = EX_SOFTWARE;
		break;
	default:
		printf("%sError%s: Internal error: %d\n", color_error(), color_reset(), res);
		exit_code = EX_SOFTWARE;
	}

	if (config_enabled_checks) {
		free_string_list(config_enabled_checks);
	}
	if (config_disabled_checks) {
		free_string_list(config_disabled_checks);
	}
	if (cl_enabled_checks) {
		free_string_list(cl_enabled_checks);
	}
	if (cl_disabled_checks) {
		free_string_list(cl_disabled_checks);
	}

	free_checks(ck);
	free_file_list(te_files);
	free_file_list(if_files);
	free_file_list(fc_files);
	free_file_list(context_te_files);
	free_file_list(context_if_files);
	free_selint_config(&ccd);

	if (fail_on_finding && found_issue && exit_code == EX_OK) {
		return EX_DATAERR;
	}

	return exit_code;
}
