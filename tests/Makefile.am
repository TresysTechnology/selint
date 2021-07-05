# Copyright 2019 Tresys Technology, LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

@VALGRIND_CHECK_RULES@
VALGRIND_memcheck_FLAGS=--leak-check=full --show-reachable=yes --show-leak-kinds=all --errors-for-leak-kinds=all

TESTS = check_tree check_parse_functions check_maps check_parsing check_parse_fc check_template check_file_list check_fc_checks check_check_hooks check_selint_config check_if_checks check_string_list check_runner check_startup check_te_checks check_ordering check_perm_macro
check_PROGRAMS = ${TESTS}

AV_FILE_PERM_FILES=sample_av/file/index \
			sample_av/file/perms/append \
			sample_av/file/perms/audit_access \
			sample_av/file/perms/create \
			sample_av/file/perms/entrypoint \
			sample_av/file/perms/execmod \
			sample_av/file/perms/execute \
			sample_av/file/perms/execute_no_trans \
			sample_av/file/perms/getattr \
			sample_av/file/perms/ioctl \
			sample_av/file/perms/link \
			sample_av/file/perms/lock \
			sample_av/file/perms/map \
			sample_av/file/perms/mounton \
			sample_av/file/perms/open \
			sample_av/file/perms/quotaon \
			sample_av/file/perms/read \
			sample_av/file/perms/relabelfrom \
			sample_av/file/perms/relabelto \
			sample_av/file/perms/rename \
			sample_av/file/perms/setattr \
			sample_av/file/perms/swapon \
			sample_av/file/perms/unlink \
			sample_av/file/perms/write

AV_SOCKET_PERM_FILES=sample_av/socket/index \
			sample_av/socket/perms/accept \
			sample_av/socket/perms/append \
			sample_av/socket/perms/bind \
			sample_av/socket/perms/connect \
			sample_av/socket/perms/create \
			sample_av/socket/perms/getattr \
			sample_av/socket/perms/getopt \
			sample_av/socket/perms/ioctl \
			sample_av/socket/perms/listen \
			sample_av/socket/perms/lock \
			sample_av/socket/perms/map \
			sample_av/socket/perms/name_bind \
			sample_av/socket/perms/read \
			sample_av/socket/perms/recvfrom \
			sample_av/socket/perms/recv_msg \
			sample_av/socket/perms/relabelfrom \
			sample_av/socket/perms/relabelto \
			sample_av/socket/perms/send_msg \
			sample_av/socket/perms/sendto \
			sample_av/socket/perms/setattr \
			sample_av/socket/perms/setopt \
			sample_av/socket/perms/shutdown \
			sample_av/socket/perms/write

AV_X_CURSOR_PERM_FILES=sample_av/x_cursor/index \
			sample_av/x_cursor/perms/create \
			sample_av/x_cursor/perms/destroy \
			sample_av/x_cursor/perms/getattr \
			sample_av/x_cursor/perms/read \
			sample_av/x_cursor/perms/setattr \
			sample_av/x_cursor/perms/use \
			sample_av/x_cursor/perms/write

SAMPLE_CONFIG_FILES=sample_configs/bad_format_2.conf \
			sample_configs/bad_format.conf \
			sample_configs/check_config.conf \
			sample_configs/invalid_option.conf \
			sample_configs/severity_convention.conf \
			sample_configs/severity_error.conf \
			sample_configs/severity_fatal.conf \
			sample_configs/severity_invalid.conf \
			sample_configs/severity_style.conf \
			sample_configs/severity_warning.conf \
			sample_configs/bad_order.conf \
			sample_configs/refpolicy_ordering.conf \
			sample_configs/order_requires.conf

SAMPLE_POLICY_FILES=sample_policy_files/access_vectors \
			sample_policy_files/bad_modules.conf \
			sample_policy_files/bad_obj_perm_sets.spt \
			sample_policy_files/bad_role_allow.te \
			sample_policy_files/basic.fc \
			sample_policy_files/basic.if \
			sample_policy_files/basic.te \
			sample_policy_files/blocks.te \
			sample_policy_files/bool_declarations.te \
			sample_policy_files/declaring_template.if \
			sample_policy_files/declaring_template.te \
			sample_policy_files/disable_comment.if \
			sample_policy_files/disable_comment.te \
			sample_policy_files/empty.te \
			sample_policy_files/extended_perms.te \
			sample_policy_files/ifdef_block.te \
			sample_policy_files/modules.conf \
			sample_policy_files/nested_templates.if \
			sample_policy_files/none_context.fc \
			sample_policy_files/obj_perm_sets.spt \
			sample_policy_files/perms.spt \
			sample_policy_files/syntax_error.te \
			sample_policy_files/uncommon.te \
			sample_policy_files/with_m4.fc

FUNCTIONAL_TEST_FILES=functional/end-to-end.bats \
			functional/configs/bad_ids.conf \
			functional/configs/broken.conf \
			functional/configs/default.conf \
			functional/configs/empty.conf \
			functional/configs/fc_macros.conf \
			functional/configs/order_ref.conf \
			functional/configs/order_lax.conf \
			functional/policies/check_triggers/access_vectors \
			functional/policies/check_triggers/c04.if \
			functional/policies/check_triggers/c05.if \
			functional/policies/check_triggers/c05.te \
			functional/policies/check_triggers/c06.pass.if \
			functional/policies/check_triggers/c06.warn.if \
			functional/policies/check_triggers/c07.te \
			functional/policies/check_triggers/c07.if \
			functional/policies/check_triggers/e02.fc \
			functional/policies/check_triggers/e03e04e05.fc \
			functional/policies/check_triggers/e06.te \
			functional/policies/check_triggers/e06.if \
			functional/policies/check_triggers/e07.pass.te \
			functional/policies/check_triggers/e07.warn.te \
			functional/policies/check_triggers/e08.pass.te \
			functional/policies/check_triggers/e08.warn.te \
			functional/policies/check_triggers/e09.te \
			functional/policies/check_triggers/e10.pass.te \
			functional/policies/check_triggers/e10.warn.te \
			functional/policies/check_triggers/modules.conf \
			functional/policies/check_triggers/obj_perm_sets.spt \
			functional/policies/check_triggers/s01.te \
			functional/policies/check_triggers/s02.fc \
			functional/policies/check_triggers/s02_other.te \
			functional/policies/check_triggers/s03.te \
			functional/policies/check_triggers/s04.if \
			functional/policies/check_triggers/s05.if \
			functional/policies/check_triggers/s06.te \
			functional/policies/check_triggers/s07.fc \
			functional/policies/check_triggers/s08.if \
			functional/policies/check_triggers/s09.pass.te \
			functional/policies/check_triggers/s09.warn.te \
			functional/policies/check_triggers/w01_other.te \
			functional/policies/check_triggers/w01.te \
			functional/policies/check_triggers/w02.if \
			functional/policies/check_triggers/w02_role.if \
			functional/policies/check_triggers/w02_role.te \
			functional/policies/check_triggers/w02.te \
			functional/policies/check_triggers/w03_alias.if \
			functional/policies/check_triggers/w03.if \
			functional/policies/check_triggers/w03_role.if \
			functional/policies/check_triggers/w03_stub.if \
			functional/policies/check_triggers/w03_ta.if \
			functional/policies/check_triggers/w04.fc \
			functional/policies/check_triggers/w05_other.if \
			functional/policies/check_triggers/w05.te \
			functional/policies/check_triggers/w06.if \
			functional/policies/check_triggers/w07.if \
			functional/policies/check_triggers/w07.0.te \
			functional/policies/check_triggers/w07.1.te \
			functional/policies/check_triggers/w08.1.te \
			functional/policies/check_triggers/w08.2.te \
			functional/policies/check_triggers/w09.te \
			functional/policies/check_triggers/w10.pass.te \
			functional/policies/check_triggers/w10.warn.te \
			functional/policies/check_triggers/w11.te \
			functional/policies/check_triggers/w11.if \
			functional/policies/check_triggers/x01.if \
			functional/policies/check_triggers/x01.te \
			functional/policies/check_triggers/C-001/interleaved.expect.ref \
			functional/policies/check_triggers/C-001/interleaved.expect.lax \
			functional/policies/check_triggers/C-001/interleaved.te \
			functional/policies/check_triggers/C-001/if_in_optional.expect.ref \
			functional/policies/check_triggers/C-001/if_in_optional.expect.lax \
			functional/policies/check_triggers/C-001/if_in_optional.te \
			functional/policies/check_triggers/C-001/kernel_module_first.expect.ref \
			functional/policies/check_triggers/C-001/kernel_module_first.expect.lax \
			functional/policies/check_triggers/C-001/kernel_module_first.te \
			functional/policies/check_triggers/C-001/optional.expect.ref \
			functional/policies/check_triggers/C-001/optional.expect.lax \
			functional/policies/check_triggers/C-001/optional.te \
			functional/policies/check_triggers/C-001/role_ifs.expect.ref \
			functional/policies/check_triggers/C-001/role_ifs.expect.lax \
			functional/policies/check_triggers/C-001/role_ifs.te \
			functional/policies/check_triggers/C-001/simple.expect.ref \
			functional/policies/check_triggers/C-001/simple.expect.lax \
			functional/policies/check_triggers/C-001/simple.te \
			functional/policies/check_triggers/C-001/types_in_requires.expect.ref \
			functional/policies/check_triggers/C-001/types_in_requires.expect.lax \
			functional/policies/check_triggers/C-001/types_in_requires.te \
			functional/policies/check_triggers/C-001/decl_in_block.expect.ref \
			functional/policies/check_triggers/C-001/decl_in_block.expect.lax \
			functional/policies/check_triggers/C-001/decl_in_block.te \
			functional/policies/check_triggers/C-001/interfaces/kernel/domain.if \
			functional/policies/check_triggers/C-001/interfaces/kernel/kernel.if \
			functional/policies/check_triggers/C-001/interfaces/other/mta.if \
			functional/policies/check_triggers/C-001/interfaces/other/role_ifs.if \
			functional/policies/check_triggers/C-001/interfaces/system/logging.if \
			functional/policies/check_triggers/C-001/interfaces/system/init.if \
			functional/policies/context/context.if \
			functional/policies/context/context.te \
			functional/policies/context2/context2.if \
			functional/policies/context2/context2.te \
			functional/policies/misc/disable.if \
			functional/policies/misc/disable_multiple_other.te \
			functional/policies/misc/disable_multiple.te \
			functional/policies/misc/disable_require_decl.if \
			functional/policies/misc/disable_require_start.te \
			functional/policies/misc/disable.te \
			functional/policies/misc/fc_macros.fc \
			functional/policies/misc/needs_context.te \
			functional/policies/misc/nesting.if \
			functional/policies/misc/nesting.te \
			functional/policies/misc/no_issues.te \
			functional/policies/parse_errors/test1.output \
			functional/policies/parse_errors/test1.te \
			functional/policies/parse_errors/test2.output \
			functional/policies/parse_errors/test2.te \
			functional/policies/parse_errors/test3.output \
			functional/policies/parse_errors/test4.output \
			functional/policies/parse_errors/test4.te \
			functional/policies/parse_errors/test5.output \
			functional/policies/parse_errors/test6.output \
			functional/policies/parse_errors/test7.if \
			functional/policies/parse_errors/test7.output \
			functional/policies/parse_errors/test8.te \
			functional/policies/parse_errors/test8.output \
			functional/policies/parse_errors/test9.te \
			functional/policies/parse_errors/test9.output

EXTRA_DIST = ${AV_FILE_PERM_FILES} ${AV_SOCKET_PERM_FILES} ${AV_X_CURSOR_PERM_FILES} ${SAMPLE_CONFIG_FILES} ${SAMPLE_POLICY_FILES} ${FUNCTIONAL_TEST_FILES}

AM_CFLAGS += @CHECK_CFLAGS@ -DSAMPLE_POL_DIR="\"$(srcdir)/sample_policy_files/\"" -DSAMPLE_CONF_DIR="\"$(srcdir)/sample_configs/\"" -DSAMPLE_AV_DIR="\"$(srcdir)/sample_av/\""
if COND_GCOV
AM_CFLAGS += --coverage -fno-inline -fno-inline-small-functions -fno-default-inline
endif

TEST_UTILS_HEADS=test_utils.h $(top_builddir)/src/tree.h $(top_builddir)/src/string_list.h
# Below does not include test_utils.o, because that will be built by the
# inclusion of test_utils.c in SOURCES for each program needing test_utils,
# so this only includes the additional object files to link against
TEST_UTILS_OBJS=$(top_builddir)/src/tree.o $(top_builddir)/src/string_list.o

UTIL_HEADS=$(top_builddir)/src/util.h
UTIL_OBJS=$(top_builddir)/src/util.o
SELINT_ERROR_HEADS=$(top_builddir)/src/selint_error.h
STRING_LIST_HEADS=$(top_builddir)/src/string_list.h ${SELINT_ERROR_HEADS}
STRING_LIST_OBJS=$(top_builddir)/src/string_list.o
COLOR_HEADS=$(top_builddir)/src/color.h
COLOR_OBJS=$(top_builddir)/src/color.o
PERM_MACRO_HEADS=$(top_builddir)/src/perm_macro.h ${UTIL_HEADS} ${COLOR_HEADS}
PERM_MACRO_OBJS=$(top_builddir)/src/perm_macro.o ${UTIL_OBJS} ${COLOR_OBJS}
SELINT_CONFIG_HEADS=$(top_builddir)/src/selint_config.h ${STRING_LIST_HEADS} ${TREE_HEADS} ${MAPS_HEADS} ${ORDERING_HEADS}
SELINT_CONFIG_OBJS=$(top_builddir)/src/selint_config.o ${STRING_LIST_OBJS} ${TREE_OBJS} ${MAPS_OBJS} ${UTIL_OBJS}
TREE_HEADS=$(top_builddir)/src/tree.h ${STRING_LIST_HEADS}
TREE_OBJS=$(top_builddir)/src/tree.o ${STRING_LIST_OBJS} $(top_builddir)/src/maps.o
FILE_LIST_HEADS=$(top_builddir)/src/file_list.h ${TREE_HEADS}
FILE_LIST_OBJS=$(top_builddir)/src/file_list.o ${TREE_OBJS}
MAPS_HEADS=$(top_builddir)/src/maps.h ${SELINT_ERROR_HEADS} ${TREE_HEADS}
MAPS_OBJS=$(top_builddir)/src/maps.o ${TREE_OBJS}
TEMPLATE_HEADS=$(top_builddir)/src/template.h ${SELINT_ERROR_HEADS} ${TREE_HEADS}
TEMPLATE_OBJS=$(top_builddir)/src/template.o ${TREE_OBJS}
PARSE_FUNCTIONS_HEADS=$(top_builddir)/src/parse_functions.h ${SELINT_ERROR_HEADS} ${TREE_HEADS} ${MAPS_HEADS} ${PERM_MACRO_HEADS}
PARSE_FUNCTIONS_OBJS=$(top_builddir)/src/parse_functions.o ${TEMPLATE_OBJS} ${ORDERING_OBJS} ${PERM_MACRO_OBJS}
PARSE_HEADS=$(top_builddir)/src/parse.h ${PARSE_FUNCTIONS_HEADS}
PARSE_OBJS=$(top_builddir)/src/parse.o $(top_builddir)/src/lex.o ${CHECK_HOOKS_OBJS} ${PARSE_FUNCTIONS_OBJS}
STARTUP_HEADS=$(top_builddir)/src/startup.h ${SELINT_ERROR_HEADS} ${FILE_LIST_HEADS} ${PARSE_HEADS}
STARTUP_OBJS=$(top_builddir)/src/startup.o ${FILE_LIST_OBJS} ${PARSE_OBJS}
PARSE_FC_HEADS = $(top_builddir)/src/parse_fc.h $(TREE_HEADS)
PARSE_FC_OBJS = $(top_builddir)/src/parse_fc.o $(TREE_OBJS)
CHECK_HOOKS_HEADS=$(top_builddir)/src/check_hooks.h ${COLOR_HEADS} ${SELINT_ERROR_HEADS} ${TREE_HEADS}
CHECK_HOOKS_OBJS=$(top_builddir)/src/check_hooks.o ${COLOR_OBJS} ${TREE_OBJS}
FC_CHECKS_HEADS=$(top_builddir)/src/fc_checks.h ${CHECK_HOOKS_HEADS}
FC_CHECKS_OBJS=$(top_builddir)/src/fc_checks.o ${CHECK_HOOKS_OBJS}
IF_CHECKS_HEADS=$(top_builddir)/src/if_checks.h ${CHECK_HOOKS_HEADS} ${UTIL_HEADS}
IF_CHECKS_OBJS=$(top_builddir)/src/if_checks.o ${CHECK_HOOKS_OBJS} ${UTIL_OBJS}
TE_CHECKS_HEADS=$(top_builddir)/src/te_checks.h ${CHECK_HOOKS_HEADS} ${UTIL_HEADS}
TE_CHECKS_OBJS=$(top_builddir)/src/te_checks.o ${CHECK_HOOKS_OBJS} $(top_builddir)/src/ordering.o ${UTIL_OBJS}
RUNNER_HEADS=$(top_builddir)/src/runner.h ${SELINT_ERROR_HEADS} ${CHECK_HOOKS_HEADS} ${PARSE_FUNCTIONS_HEADS} ${FILE_LIST_HEADS}
RUNNER_OBJS=$(top_builddir)/src/runner.o ${CHECK_HOOKS_OBJS} ${PARSE_FUNCTIONS_OBJS} ${FILE_LIST_OBJS} ${FC_CHECKS_OBJS} ${IF_CHECKS_OBJS} ${TE_CHECKS_OBJS} ${PARSE_FC_OBJS} ${UTIL_OBJS} ${STARTUP_OBJS} ${PARSE_OBJS}
ORDERING_HEADS=$(top_builddir)/src/ordering.h ${SELINT_ERROR_HEADS} ${TREE_HEADS}
ORDERING_OBJS=$(top_builddir)/src/ordering.o ${TREE_OBJS} ${MAPS_OBJS}

check_string_list_SOURCES = check_string_list.c ${STRING_LIST_HEADS}
check_string_list_LDADD = @CHECK_LIBS@ $(sort ${STRING_LIST_OBJS})

check_selint_config_SOURCES = check_selint_config.c ${SELINT_CONFIG_HEADS} ${STRING_LIST_HEADS}
check_selint_config_LDADD = @CHECK_LIBS@ $(sort ${SELINT_CONFIG_OBJS} ${STRING_LIST_OBJS})

check_maps_SOURCES = check_maps.c ${MAPS_HEADS}
check_maps_LDADD = @CHECK_LIBS@ $(sort ${MAPS_OBJS})

check_startup_SOURCES = check_startup.c ${STARTUP_HEADS} ${MAPS_HEADS} ${SELINT_ERROR_HEADS}
check_startup_LDADD = @CHECK_LIBS@ $(sort ${STARTUP_OBJS} ${MAPS_OBJS})

check_tree_SOURCES = check_tree.c test_utils.c ${TREE_HEADS} ${TEST_UTILS_HEADS}
check_tree_LDADD = @CHECK_LIBS@ $(sort ${TREE_OBJS} ${MAPS_OBJS} ${TEST_UTILS_OBJS})

check_file_list_SOURCES = check_file_list.c ${FILE_LIST_HEADS}
check_file_list_LDADD = @CHECK_LIBS@ $(sort ${FILE_LIST_OBJS})

check_parse_functions_SOURCES = check_parse_functions.c ${PARSE_FUNCTIONS_HEADS} ${MAPS_HEADS} ${PARSE_HEADS} ${SELINT_ERROR_HEADS}
check_parse_functions_LDADD = @CHECK_LIBS@ $(sort ${PARSE_FUNCTIONS_OBJS} ${MAPS_OBJS} ${PARSE_OBJS})

check_parsing_SOURCES = check_parsing.c ${PARSE_HEADS} ${TREE_HEADS} ${PARSE_FUNCTIONS_HEADS} ${SELINT_ERROR_HEADS}
check_parsing_LDADD = @CHECK_LIBS@ $(sort ${PARSE_OBJS} ${TREE_OBJS} ${PARSE_FUNCTIONS_OBJS})

check_parse_fc_SOURCES = check_parse_fc.c ${PARSE_FC_HEADS} ${TREE_HEADS}
check_parse_fc_LDADD = @CHECK_LIBS@ $(sort ${PARSE_FC_OBJS} ${TREE_OBJS})

check_template_SOURCES = check_template.c ${PARSE_FUNCTIONS_HEADS} ${TEMPLATE_HEADS} ${PARSE_HEADS} ${MAPS_HEADS}
check_template_LDADD = @CHECK_LIBS@ $(sort ${PARSE_FUNCTIONS_OBJS} ${TEMPLATE_OBJS} ${PARSE_OBJS} ${MAPS_OBJS})

check_check_hooks_SOURCES = check_check_hooks.c ${CHECK_HOOKS_HEADS}
check_check_hooks_LDADD = @CHECK_LIBS@ $(sort ${CHECK_HOOKS_OBJS})

check_fc_checks_SOURCES = check_fc_checks.c ${FC_CHECKS_HEADS} ${CHECK_HOOKS_HEADS} ${MAPS_HEADS}
check_fc_checks_LDADD = @CHECK_LIBS@ $(sort ${FC_CHECKS_OBJS} ${CHECK_HOOKS_OBJS} ${MAPS_OBJS} ${UTIL_OBJS})

check_if_checks_SOURCES = check_if_checks.c test_utils.c ${IF_CHECKS_HEADS} ${CHECK_HOOKS_HEADS} ${MAPS_HEADS} ${TEST_UTILS_HEADS}
check_if_checks_LDADD = @CHECK_LIBS@ $(sort ${IF_CHECKS_OBJS} ${CHECK_HOOKS_OBJS} ${MAPS_OBJS} ${TEST_UTILS_OBJS})

check_te_checks_SOURCES = check_te_checks.c test_utils.c ${TE_CHECKS_HEADS} ${CHECK_HOOKS_HEADS} ${MAPS_HEADS} ${TEST_UTILS_HEADS} ${PERM_MACRO_HEADS}
check_te_checks_LDADD = @CHECK_LIBS@ $(sort ${TE_CHECKS_OBJS} ${CHECK_HOOKS_OBJS} ${MAPS_OBJS} ${TEST_UTILS_OBJS} ${PERM_MACRO_OBJS})

check_runner_SOURCES = check_runner.c ${STRING_LIST_HEADS} ${RUNNER_HEADS}
check_runner_LDADD = @CHECK_LIBS@ $(sort ${STRING_LIST_OBJS} ${RUNNER_OBJS})

check_ordering_SOURCES = check_ordering.c ${ORDERING_HEADS} ${RUNNER_HEADS} ${MAPS_HEADS}
check_ordering_LDADD = @CHECK_LIBS@ $(sort ${ORDERING_OBJS} ${RUNNER_OBJS} ${MAPS_OBJS})

check_perm_macro_SOURCES = check_perm_macro.c ${PERM_MACRO_HEADS} ${STARTUP_HEADS} ${SELINT_ERROR_HEADS} ${MAPS_HEADS}
check_perm_macro_LDADD = @CHECK_LIBS@ $(sort ${PERM_MACRO_OBJS} ${STARTUP_OBJS} ${MAPS_OBJS})

MOSTLYCLEANFILES = *.gcov *.gcda *.gcno
