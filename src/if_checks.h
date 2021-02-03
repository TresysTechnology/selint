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

#ifndef IF_CHECKS_H
#define IF_CHECKS_H

#include "check_hooks.h"

/*********************************************
* Check for unused interfaces and templates
* Called on NODE_INTERFACE_DEF and NODE_TEMP_DEF nodes.
* data - metadata about the file
* node - the node to check
* returns NULL if passed or check_result for issue X-001
*********************************************/
struct check_result *check_unused_interface(const struct
                                            check_data *data,
                                            const struct
                                            policy_node
                                            *node);

/*********************************************
* Check to make sure all interfaces and templates have a comment above them
* Called on NODE_INTERFACE_DEF and NODE_TEMP_DEF nodes.
* data - metadata about the file
* node - the node to check
* returns NULL if passed or check_result for issue C-004
*********************************************/
struct check_result *check_interface_definitions_have_comment(const struct
                                                              check_data *data,
                                                              const struct
                                                              policy_node
                                                              *node);

/*********************************************
* Check that declaration in require blocks are ordered
* Called on NODE_REQUIRE and NODE_GEN_REQ nodes.
* data - metadata about the file
* node - the node to check
* returns NULL if passed or check_result for issue C-006
*********************************************/
struct check_result *check_unordered_declaration_in_require(const struct
                                                            check_data *data,
                                                            const struct
                                                            policy_node
                                                            *node);

/*********************************************
* Check that interfaces do not call templates
* Called on NODE_IF_CALL nodes
* data - metadata about the file
* node - the node to check
* returns NULL if passed or check_result for issue S-004
*********************************************/
struct check_result *check_if_calls_template(const struct
                                             check_data *data,
                                             const struct
                                             policy_node *node);

/*********************************************
* Check that interfaces do contain declarations.
* Called on NODE_DECL nodes.
* data - metadata about the file
* node - the node to check
* returns NULL if passed or check_result for issue S-005
*********************************************/
struct check_result *check_decl_in_if(const struct
                                      check_data *data,
                                      const struct
                                      policy_node *node);

/*********************************************
* Check that gen_require blocks are quoted
* Called on NODE_GEN_REQ nodes
* data - metadata about the file
* node - the node to check
* returns NULL if passed or check_result for issue S-008
*********************************************/
struct check_result *check_unquoted_gen_require_block(const struct
                                                      check_data *data,
                                                      const struct
                                                      policy_node *node);

/*********************************************
* Check that all names referenced in interface are listed in its require block
* (or declared in that template)
* Called on NODE_AV_RULE, NODE_TT_RULE and NODE_IF_CALL nodes.
* data - metadata about the file
* node - the node to check
* returns NULL if passed or check_result for issue W-002
*********************************************/
struct check_result *check_name_used_but_not_required_in_if(const struct
                                                            check_data *data,
                                                            const struct
                                                            policy_node *node);

/*********************************************
* Check that all types listed in require block are actually used in the interface
* Called on NODE_DECL nodes
* data - metadata about the file
* node - the node to check
* returns NULL if passed or check_result for issue W-003
*********************************************/
struct check_result *check_name_required_but_not_used_in_if(const struct
                                                            check_data *data,
                                                            const struct
                                                            policy_node *node);

/*********************************************
* Check that all types listed in require block are declared in the same module
* Called on NODE_DECL nodes
* data - metadata about the file
* node - the node to check
* returns NULL if passed or check_result for issue W-011
*********************************************/
struct check_result *check_required_declaration_own(const struct
                                                    check_data *data,
                                                    const struct
                                                    policy_node *node);
#endif
