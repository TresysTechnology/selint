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

#ifndef TE_CHECKS_H
#define TE_CHECKS_H

#include "check_hooks.h"

/*********************************************
* Check for violations of te file ordering conventions.
* The refpolicy conventions (which is all that can be checked as of now are
* described at: https://github.com/SELinuxProject/refpolicy/wiki/StyleGuide
* Called on all nodes except fc file nodes, error nodes, NODE_IF_FILE and
* NODE_FC_FILE
* On NODE_TE_FILE nodes, it generates the ordering information for that file
* On other nodes, it checks the previously generated ordering information to
* determine whether to return an error.
* data - metadata about the file currently being scanned
* node - the node to check
* returns NULL if passed or check_result for issue C-001
*********************************************/
struct check_result *check_te_order(const struct check_data *data,
                                    const struct policy_node *node);

/*********************************************
* Check for unordered permissions in av rules and class declarations.
* Called on NODE_AV_RULE, NODE_XAV_RULE and NODE_DECL nodes.
* data - metadata about the file currently being scanned
* node - the node to check
* returns NULL if passed or check_result for issue C-005
*********************************************/
struct check_result *check_unordered_perms(const struct check_data *data,
                                           const struct policy_node *node);


/*********************************************
* Check for av rules which could use the self keyword but do not.
* Note that "av_rule attr_name self:..." and "av_rule attr_name attr_name:..."
* Are not identical in behavior, so this should only detect types, not
* attributes.
* data - metadata about the file currently being scanned
* node - the node to check
* returns NULL if passed or check_result for issue C-007
*********************************************/
struct check_result *check_no_self(const struct check_data *data,
                                   const struct policy_node *node);

/*********************************************
 * Check for identifiers in conditional expressions not declared in own module.
 * Called on NODE_BOOLEAN_POLICY and NODE_TUNABLE_POLICY nodes.
 * data - metadata about the file currently being scanned
 * node - the node to check
 * returns NULL if passed or check_result for issue C-008
*********************************************/
struct check_result *check_foreign_cond_id(const struct check_data
                                           *data,
                                           const struct policy_node
                                           *node);

/*********************************************
* Check for the presence of require blocks in TE files.
* Interface calls are to be preferred.
* Called on NODE_REQUIRE and NODE_GEN_REQ nodes.
* data - metadata about the file currently being scanned
* node - the node to check
* returns NULL if passed or check_result for issue S-001
*********************************************/
struct check_result *check_require_block(const struct check_data *data,
                                         const struct policy_node *node);

/*********************************************
* Check for useless semicolons after interface calls
* Called on IF_CALL nodes.
* data - metadata about the file currently being scanned
* node - the node to check
* returns NULL if passed or check_result for issue S-003
*********************************************/
struct check_result *check_useless_semicolon(const struct check_data *data,
                                             const struct policy_node *node);

/*********************************************
* Check for bare module statements
* Called on NODE_HEADER nodes.
* data - metadata about the file currently being scanned
* node - the node to check
* returns NULL if passed or check_result for issue S-006
*********************************************/
struct check_result *check_bare_module_statement(const struct check_data *data,
                                                 const struct policy_node *node);

/*********************************************
* Check for name mismatch between permission macro and class name.
* Called on NODE_AV_RULE nodes.
* data - metadata about the file currently being scanned
* node - the node to check
* returns NULL if passed or check_result for issue S-009
*********************************************/
struct check_result *check_perm_macro_class_mismatch(const struct check_data *data,
                                                     const struct policy_node *node);

/*********************************************
* Check for used permissions available by a permission macro
* Called on NODE_AV_RULE nodes.
* data - metadata about the file currently being scanned
* node - the node to check
* returns NULL if passed or check_result for issue S-010
*********************************************/
struct check_result *check_perm_macro_available(const struct check_data *data,
                                                const struct policy_node *node);

/*********************************************
* Check for references to types in te files without an explicit declaration.
* We don't check types in .if or .fc files because those are similar issues
* handled by W-002 and E-005 respectively.
* This situation typically results in a compilation error, but in the event
* that an earlier interface call required the type it would not.
* Called on allow rule and interface call nodes.
* data - metadata about the file currently being scanned
* node - the node to check
* returns NULL if passed or check_result for issue W-001
*********************************************/
struct check_result *check_no_explicit_declaration(const struct check_data *data,
                                                   const struct policy_node *node);

/*********************************************
* Check for situations where interface or template calls into modules are not
* in optional policy blocks
* Called on NODE_IF_CALL nodes.
* data - metadata about the file currently being scanned
* node - the node to check
* returns NULL if passed or check_result for issue W-005
*********************************************/
struct check_result *check_module_if_call_in_optional(const struct check_data
                                                      *data,
                                                      const struct policy_node
                                                      *node);

/*********************************************
* Check for interface calls with empty argument
* Called on NODE_IF_CALL nodes
* data - metadata about the file
* node - the node to check
* returns NULL if passed or check_result for issue W-006
*********************************************/
struct check_result *check_empty_if_call_arg(const struct
                                             check_data *data,
                                             const struct
                                             policy_node *node);

/*********************************************
* Check for unquoted space in argument of interface calls
* Called on NODE_IF_CALL nodes
* data - metadata about the file
* node - the node to check
* returns NULL if passed or check_result for issue W-007
*********************************************/
struct check_result *check_space_if_call_arg(const struct
                                             check_data *data,
                                             const struct
                                             policy_node *node);

/*********************************************
* Check for allow rule with complement or wildcard permission
* Called on NODE_AV_RULE nodes
* data - metadata about the file
* node - the node to check
* returns NULL if passed or check_result for issue W-008
*********************************************/
struct check_result *check_risky_allow_perm(const struct
                                            check_data *data,
                                            const struct
                                            policy_node *node);

/*********************************************
 * Check for mismatch of module and file names.
 * Called on NODE_HEADER nodes.
 * data - metadata about the file currently being scanned
 * node - the node to check
 * returns NULL if passed or check_result for issue W-009
*********************************************/
struct check_result *check_module_file_name_mismatch(const struct check_data
                                                     *data,
                                                     const struct policy_node
                                                     *node);

/*********************************************
 * Check for call of unknown interface.
 * Called on NODE_IF_CALL nodes.
 * data - metadata about the file currently being scanned
 * node - the node to check
 * returns NULL if passed or check_result for issue W-010
*********************************************/
struct check_result *check_unknown_interface_call(const struct check_data
                                                  *data,
                                                  const struct policy_node
                                                  *node);

/*********************************************
 * Check for unknown identifiers in conditional expressions.
 * Called on NODE_BOOLEAN_POLICY and NODE_TUNABLE_POLICY nodes.
 * data - metadata about the file currently being scanned
 * node - the node to check
 * returns NULL if passed or check_result for issue W-012
*********************************************/
struct check_result *check_unknown_cond_id(const struct check_data
                                           *data,
                                           const struct policy_node
                                           *node);

/*********************************************
 * Check for clash of declaration and interface names.
 * This will cause macro expansion to enter an endless loop
 * and consume all available memory.
 * Called on NODE_DECL nodes.
 * data - metadata about the file currently being scanned
 * node - the node to check
 * returns NULL if passed or check_result for issue E-006
*********************************************/
struct check_result *check_declaration_interface_nameclash(const struct check_data
                                                           *data,
                                                           const struct policy_node
                                                           *node);

/*********************************************
 * Verify whether the next check can be enabled.
*********************************************/
bool check_unknown_permission_condition(void);

/*********************************************
 * Check for usage of unknown permission or permission macro.
 * Called on NODE_AV_RULE nodes.
 * data - metadata about the file currently being scanned
 * node - the node to check
 * returns NULL if passed or check_result for issue E-007
*********************************************/
struct check_result *check_unknown_permission(const struct check_data
                                              *data,
                                              const struct policy_node
                                              *node);

/*********************************************
 * Verify whether the next check can be enabled.
*********************************************/
bool check_unknown_class_condition(void);

/*********************************************
 * Check for usage of unknown class.
 * Called on NODE_AV_RULE, NODE_RT_RULE and NODE_TT_RULE nodes.
 * data - metadata about the file currently being scanned
 * node - the node to check
 * returns NULL if passed or check_result for issue E-008
*********************************************/
struct check_result *check_unknown_class(const struct check_data
                                         *data,
                                         const struct policy_node
                                         *node);

/*********************************************
 * Check for empty optional and require macro blocks.
 * Called on NODE_OPTIONAL_POLICY, NODE_GEN_REQ and NODE_REQUIRE nodes.
 * data - metadata about the file currently being scanned
 * node - the node to check
 * returns NULL if passed or check_result for issue E-009
*********************************************/
struct check_result *check_empty_block(const struct check_data
                                       *data,
                                       const struct policy_node
                                       *node);

/*********************************************
 * Check for stray words.
 * Called on NODE_M4_SIMPLE_MACRO nodes.
 * data - metadata about the file currently being scanned
 * node - the node to check
 * returns NULL if passed or check_result for issue E-010
*********************************************/
struct check_result *check_stray_word(const struct check_data
                                      *data,
                                      const struct policy_node
                                      *node);

#endif
