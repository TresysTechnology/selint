#!/usr/bin/env/bats

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

SELINT_PATH=../../src/selint

do_test() {
	local CHECK_ID=$1
	local FILENAME=$2
	local EXPECT=$3
	local ARGS=$4
	run ${SELINT_PATH} -s -c tmp.conf ${ARGS} ./policies/check_triggers/${FILENAME} ./policies/check_triggers/modules.conf ./policies/check_triggers/obj_perm_sets.spt ./policies/check_triggers/access_vectors
	echo $output
	[ "$status" -eq 0 ]
	count=$(echo ${output} | grep -o ${CHECK_ID} | wc -l)
	echo "Status: $status, Count: $count (expected ${EXPECT})"
	[ "$count" -eq ${EXPECT} ]
}

test_one_check_expect() {
	local CHECK_ID=$1
	local FILENAME=$2
	local EXPECT=$3

	echo "disable = { $CHECK_ID } " > tmp.conf
	# E-010
	echo "custom_te_simple_macros = { ignored_bare_word }" >> tmp.conf

	do_test ${CHECK_ID} ${FILENAME} 0

	echo "enable_source = { $CHECK_ID }" >> tmp.conf
	do_test ${CHECK_ID} ${FILENAME} ${EXPECT}

	do_test ${CHECK_ID} ${FILENAME} 0 "-d $CHECK_ID"

	do_test ${CHECK_ID} ${FILENAME} ${EXPECT} "-e $CHECK_ID"

	do_test ${CHECK_ID} ${FILENAME} ${EXPECT} "-e $CHECK_ID -d $CHECK_ID"

	rm tmp.conf
}

test_ordering() {
	local CHECK_DIR="./policies/check_triggers/C-001/"
	local FILENAME_PREFIX=$1
	for ORDER_CONF in "ref" "lax"
	do
		echo "Checking ${FILENAME_PREFIX} in order ${ORDER_CONF}"
		run ${SELINT_PATH} -rs -c configs/order_${ORDER_CONF}.conf -e C-001 -E --context=${CHECK_DIR}interfaces ${CHECK_DIR}${FILENAME_PREFIX}.te ./policies/check_triggers/modules.conf
		echo ${output}
		while read p; do
			echo "Checking for $p"
			count=$(echo ${output} | grep -o ${p} | wc -l)
			[ "$count" -eq "1" ]
		done < "${CHECK_DIR}/${FILENAME_PREFIX}.expect.${ORDER_CONF}"
		local EXPECT_COUNT=$(cat ${CHECK_DIR}/${FILENAME_PREFIX}.expect.${ORDER_CONF} | wc -l)
		count=$(echo ${output} | grep -o C-001 | wc -l)
		echo "Expecting: ${EXPECT_COUNT}, got: $count"
		[ "$count" -eq "${EXPECT_COUNT}" ]
	done
}

test_one_check() {
	test_one_check_expect $1 $2 1
}

test_parse_error_run() {
	local USE_VALGRIND=$1

	test_parse_error_impl $USE_VALGRIND test1.te test1.output

	test_parse_error_impl $USE_VALGRIND test2.te test2.output

	printf "#comment\n    policy_module( 	     test2, 	\n    \n\n	    	0.0.1  \n  )	\n\n" > ./policies/parse_errors/test3_tmp.if
	test_parse_error_impl $USE_VALGRIND test3_tmp.if test3.output

	test_parse_error_impl $USE_VALGRIND test4.te test4.output

	printf "policy_module(test5, 0.0.1)\r\n\r\n# comment\r\nallow \r\n	source\r\ntarget	\r\n  clas\r\n 	   perm\r\n; # comment\r\n\r\n" > ./policies/parse_errors/test5_tmp.te
	test_parse_error_impl $USE_VALGRIND test5_tmp.te test5.output

	printf "#comment\r\n    policy_module( 	     test2, 	\r\n    \r\n\r\n	    	0.0.1  \r\n  )	\r\n\r\n" > ./policies/parse_errors/test6_tmp.if
	test_parse_error_impl $USE_VALGRIND test6_tmp.if test6.output

	test_parse_error_impl $USE_VALGRIND test7.if test7.output

	test_parse_error_impl $USE_VALGRIND test8.te test8.output

	test_parse_error_impl $USE_VALGRIND test9.te test9.output
}

test_parse_error_impl() {
	local USE_VALGRIND=$1
	local SOURCE_FILENAME=$2
	local OUTPUT_FILENAME=$3

	if [ $USE_VALGRIND -eq 1 ]; then
		run valgrind --leak-check=full --show-leak-kinds=all --errors-for-leak-kinds=all --error-exitcode=23 ${SELINT_PATH} -c configs/default.conf ./policies/parse_errors/${SOURCE_FILENAME}
		[ "$status" -eq 70 ]
	else
		run ${SELINT_PATH} -c configs/default.conf ./policies/parse_errors/${SOURCE_FILENAME}
		echo ${output}
		[ "$status" -eq 70 ]
		local EXPECTED_OUTPUT=$(cat ./policies/parse_errors/${OUTPUT_FILENAME})
		echo ${EXPECTED_OUTPUT}
		# compatibility for different bison versions and ignore NOTE output
		local NORMALIZED_OUTPUT=$(grep -vE '^Note: ' <<< "${output/ \$end/ end of file}")
		echo ${NORMALIZED_OUTPUT}
		[ "${NORMALIZED_OUTPUT}" == "${EXPECTED_OUTPUT}" ]
	fi
}

@test "C-001" {
	test_ordering "simple"
	test_ordering "interleaved"
	test_ordering "optional"
	test_ordering "role_ifs"
	test_ordering "types_in_requires"
	test_ordering "kernel_module_first"
	test_ordering "if_in_optional"
}

@test "C-004" {
	test_one_check "C-004" "c04.if"
}

@test "C-005" {
	test_one_check_expect "C-005" "c05.te" 2
	test_one_check "C-005" "c05.if"
}

@test "C-006" {
	test_one_check_expect "C-006" "c06.pass.if" 0
	test_one_check_expect "C-006" "c06.warn.if" 5
}

@test "C-007" {
	test_one_check "C-007" "c07.te"
	test_one_check "C-007" "c07.if"
}

@test "C-008" {
	test_one_check "C-008" "c08*.te"
}

@test "S-001" {
	test_one_check "S-001" "s01.te"
}

@test "S-002" {
	test_one_check "S-002" "s02*"
}

@test "S-003" {
	test_one_check "S-003" "s03.te"
}

@test "S-004" {
	test_one_check "S-004" "s04.*"
}

@test "S-005" {
	test_one_check "S-005" "s05.if"
}

@test "S-006" {
	test_one_check "S-006" "s06.te"
}

@test "S-007" {
	test_one_check "S-007" "s07.fc"
}

@test "S-008" {
	test_one_check "S-008" "s08.if"
}

@test "S-009" {
	test_one_check_expect "S-009" "s09.pass.te" 0
	test_one_check_expect "S-009" "s09.warn.te" 6
}

@test "W-001" {
	test_one_check_expect "W-001" "w01*" 5
}

@test "W-002" {
	test_one_check_expect "W-002" "w02.*" 2
	test_one_check "W-002" "w02_role.*"
}

@test "W-003" {
	test_one_check "W-003" "w03.if"
	test_one_check "W-003" "w03_role.if"
	test_one_check_expect "W-003" "w03_ta.if" 0
	test_one_check_expect "W-003" "w03_alias.if" 0
	test_one_check_expect "W-003" "w03_stub.if" 0
}

@test "W-004" {
	test_one_check "W-004" "w04.fc"
}

@test "W-005" {
	test_one_check "W-005" "w05*"
}

@test "W-006" {
	test_one_check "W-006" "w06.if"
}

@test "W-007" {
	test_one_check "W-007" "w07.if"
	test_one_check_expect "W-007" "w07.0.te" 0
	test_one_check "W-007" "w07.1.te"
}

@test "W-008" {
	test_one_check "W-008" "w08.1.te"
	test_one_check "W-008" "w08.2.te"
}

@test "W-009" {
	test_one_check "W-009" "w09.te"
}

@test "W-010" {
	test_one_check "W-010" "w10.warn.te"
	test_one_check_expect "W-010" "w10.pass.te" 0
}

@test "W-011" {
	test_one_check "W-011" "w11.*"
}

@test "W-012" {
	test_one_check "W-012" "w12.te"
}

@test "E-002" {
	test_one_check "E-002" "e02.fc"
}

@test "E-003" {
	test_one_check "E-003" "e03e04e05.fc"
}

@test "E-004" {
	test_one_check "E-004" "e03e04e05.fc"
}

@test "E-005" {
	test_one_check "E-005" "e03e04e05.fc"
}

@test "E-006" {
	test_one_check "E-006" "e06.*"
}

@test "E-007" {
	test_one_check_expect "E-007" "e07.warn.te" 5
	test_one_check_expect "E-007" "e07.pass.te" 0
}

@test "E-008" {
	test_one_check_expect "E-008" "e08.warn.te" 4
	test_one_check_expect "E-008" "e08.pass.te" 0
}

@test "E-009" {
	test_one_check_expect "E-009" "e09.te" 4
}

@test "E-010" {
	test_one_check_expect "E-010" "e10.warn.te" 9
	test_one_check_expect "E-010" "e10.pass.te" 0
}

@test "assume_user" {
	touch tmp.conf
	do_test "E-003" "e03e04e05.fc" 1 "-e E-003"
	echo "assume_users = { system_u }" >> tmp.conf
	do_test "E-003" "e03e04e05.fc" 0 "-e E-003"
	rm tmp.conf
}

@test "assume_role" {
	touch tmp.conf
	do_test "E-004" "e03e04e05.fc" 1 "-e E-004"
	echo "assume_roles = { object_r }" >> tmp.conf
	do_test "E-004" "e03e04e05.fc" 0 "-e E-004"
	rm tmp.conf
}

@test "usage" {
	run ${SELINT_PATH} -c configs/empty.conf
	[ "$status" -eq 64 ]
	usage_presence=$(echo ${output} | grep -o "^Usage" | wc -l)
	[ "$usage_presence" -eq 1 ]

	run ${SELINT_PATH} -c configs/empty.conf -Z
	[ "$status" -eq 64 ]
	usage_presence=$(echo ${output} | grep -o "Usage" | wc -l)
	[ "$usage_presence" -eq 1 ]
	message_presence=$(echo ${output} | grep -o "invalid option -- 'Z'" | wc -l)
	[ "$message_presence" -eq 1 ]
}

@test "Enable/disable" {
	run ${SELINT_PATH} -c configs/empty.conf -e W-002 -e W-003 -d S-002 -d C-002 -r -s policies/check_triggers
	[ "$status" -eq 0 ]
	count=$(echo ${output} | grep -o "S-002" | wc -l)
	[ "$count" -eq 0 ]
	count=$(echo ${output} | grep -o "C-002" | wc -l)
	[ "$count" -eq 0 ]
	count=$(echo ${output} | grep -o "W-002" | wc -l)
	[ "$count" -gt 0 ]
	count=$(echo ${output} | grep -o "W-003" | wc -l)
	[ "$count" -gt 0 ]
}

@test "verbose mode" {
	run ${SELINT_PATH} -c configs/default.conf -r -s -v policies/check_triggers
	[ "$status" -eq 0 ]
	verbose_presence=$(echo ${output} | grep -o "^Verbose" | wc -l)
	[ "$verbose_presence" -eq 1 ]
}

@test "valgrind" {
	run valgrind --leak-check=full --show-leak-kinds=all --errors-for-leak-kinds=all --error-exitcode=1 ${SELINT_PATH} -c configs/default.conf -r -s policies/check_triggers
	[ "$status" -eq 0 ]
}

@test "nesting_gen_req" {
	run ${SELINT_PATH} -c configs/default.conf -e W-002 -E -s policies/misc/nesting.*
	[ "$status" -eq 0 ]
	count=$(echo ${output} | grep -o "W-002" | wc -l)
	echo "Status: $status, Count: $count (expected 1)"
	echo $output
	[ "$count" -eq 1 ]
	count=$(echo ${output} | grep -o "foo_data_t" | wc -l)
	echo "Status: $status, Count: $count (expected 1)"
	echo $output
	[ "$count" -eq 1 ]
	count=$(echo ${output} | grep -o "foo_log_t" | wc -l)
	echo "Status: $status, Count: $count (expected 0)"
	echo $output
	[ "$count" -eq 0 ]
}

@test "disable comment" {
	run ${SELINT_PATH} -c configs/default.conf -F -e W-002 -E -s policies/misc/disable.*
	[ "$status" -eq 0 ]
	count=$(echo ${output} | grep -o "W-002" | wc -l)
	echo "Status: $status, Count: $count (expected 0)"
	echo $output
	[ "$count" -eq 0 ]

	run ${SELINT_PATH} -F -s -c configs/default.conf policies/misc/disable_multiple*
	[ "$status" -eq 0 ]

	run ${SELINT_PATH} -F -s -c configs/default.conf -d S-008 policies/misc/disable_require_start.*
	[ "$status" -eq 0 ]

	run ${SELINT_PATH} -F -s -c configs/default.conf policies/misc/disable_require_decl.*
	[ "$status" -eq 0 ]
}

@test "nonexistent file" {
	run ${SELINT_PATH} -s -c configs/default.conf doesnt_exist.te
	[ "$status" -eq 70 ]
	run ${SELINT_PATH} -s -c configs/default.conf doesnt_exist.if
	[ "$status" -eq 70 ]
	run ${SELINT_PATH} -s -c configs/default.conf doesnt_exist.fc
	[ "$status" -eq 70 ]
}

@test "Broken config" {
	run valgrind --leak-check=full --show-leak-kinds=all --errors-for-leak-kinds=all --error-exitcode=1 ${SELINT_PATH} -c configs/broken.conf -rs policies/check_triggers
	[ "$status" -eq 78 ]
}

@test "Bad check ids" {
	run ${SELINT_PATH} -s -c configs/default.conf policies/misc/no_issues.te
	count=$(echo ${output} | grep -o "Warning: Failed to locate modules.conf file." | wc -l)
	[ "$count" -eq 1 ] #"Failed to find a valid modules.conf"

	run ${SELINT_PATH} -s -c configs/default.conf -e foo policies/misc/no_issues.te
	count=$(echo ${output} | grep -o "not a valid check id" | wc -l)
	[ "$count" -eq 1 ]

	run ${SELINT_PATH} -s -c configs/default.conf -d foo policies/misc/no_issues.te
	count=$(echo ${output} | grep -o "not a valid check id" | wc -l)
	[ "$count" -eq 1 ]

	run ${SELINT_PATH} -s -c configs/bad_ids.conf policies/misc/no_issues.te
	count=$(echo ${output} | grep -o "not a valid check id" | wc -l)
	[ "$count" -eq 2 ]

	run ${SELINT_PATH} -s -c configs/bad_ids.conf -e foo -d bar -d baz policies/misc/no_issues.te
	count=$(echo ${output} | grep -o "not a valid check id" | wc -l)
	[ "$count" -eq 5 ]
}

@test "context flag" {
	touch tmp.conf
	do_test "W-001" "../misc/needs_context.te" 0
	do_test "W-001" "../misc/needs_context.te" 1 "--context=policies/context"
	do_test "W-001" "../misc/needs_context.te" 1 "--context=policies/context2"
	do_test "W-001" "../misc/needs_context.te" 2 "--context=policies/context --context=policies/context2"
	rm tmp.conf
}

@test "run_summary" {
	run ${SELINT_PATH} -c configs/default.conf -rsS policies/check_triggers
	count=$(echo ${output} | grep -o "Found the following issue counts" | wc -l)
	[ "$count" -eq 1 ]
	for SEV in "C" "S" "W" "E"
	do
		count=$(echo ${output} | grep -E -o "${SEV}-00[0-9]: [0-9]+" | wc -l)
		[ "$count" -ge 1 ]
	done
}

@test "custom_fc_macros" {
	run ${SELINT_PATH} -c configs/default.conf -s policies/misc/fc_macros.fc
	count=$(echo ${output} | grep -o "E-002" | wc -l)
	[ "$count" -eq 1 ]
	run ${SELINT_PATH} -c configs/fc_macros.conf -s policies/misc/fc_macros.fc
	count=$(echo ${output} | grep -o "E-002" | wc -l)
	echo ${output}
	[ "$count" -eq 0 ]
}

@test "parse_error_printing" {
	test_parse_error_run 0
}

@test "parse_error_printing_valgrind" {
	if [ -z ${BATS_TIME_EXPENSIVE} ]; then
		skip "BATS_TIME_EXPENSIVE not set"
	fi
	test_parse_error_run 1
}
