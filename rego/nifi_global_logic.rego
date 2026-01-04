package nifi_glob

import rego.v1
import data.nifi_inp

import data.nifi_global_policies.global_policies

# This rego file contains the logical rules in order to lookup 
# an entry in the nifi_global_policies abstraction layer


global_policy_types := [okey | okey := object.keys(global_policies)[_]] # returns the available keys of the nifi_global_policies abstraction layer
res_is_global_type := nifi_inp.resource_id in global_policy_types       # returns a boolean wether the resource is a global resource


# Searches user entry in the nifi_global_policies abstraction layer  
global_policy_user_has_permissions(res_id, user_name, action) := true if {
    res_id in object.keys(global_policies)
    user_name in object.keys(global_policies[res_id]["users"])
    global_policies[res_id]["users"][user_name] == action
}

# Searches user-group entry in the nifi_global_policies abstraction layer  
global_policy_group_has_permissions(res_id, user_groups, action) := true if {
    res_id in object.keys(global_policies)
    x := { trim(k, " ") | k = object.keys(global_policies[res_id]["groups"])[_] }
    y := { trim(k, " ") | k = user_groups[_] }
    count(x & y) > 0 # check if there is atleast one intersecting group
}


### READ
# true, if user is allowed to read on a given global policy
global_policy_read := true if {
    global_policy_user_has_permissions(
        nifi_inp.inherit_resource_id, 
        nifi_inp.user_name, 
        "READ")
}
# true, if user-group is allowed to read on a given global policy
global_policy_read := true if {
    global_policy_group_has_permissions(
        nifi_inp.inherit_resource_id, 
        nifi_inp.user_groups, 
        "READ")
}


### WRITE
# true, if user is allowed to write on a given global policy
global_policy_write := true if {
    global_policy_user_has_permissions(
        nifi_inp.inherit_resource_id, 
        nifi_inp.user_name, 
        "WRITE")
}
# true, if user-group is allowed to write on a given global policy
global_policy_write := true if {
    global_policy_group_has_permissions(
        nifi_inp.inherit_resource_id, 
        nifi_inp.user_groups, 
        "WRITE")
}


### FULL
# true, if user is allowed to read AND write on a given global policy
global_policy_full := true if {
    global_policy_user_has_permissions(
        nifi_inp.inherit_resource_id, 
        nifi_inp.user_name, 
        "FULL")
}
# true, if a user-group is allowed to read AND write on a given global policy
global_policy_full := true if {
    global_policy_group_has_permissions(
        nifi_inp.inherit_resource_id, 
        nifi_inp.user_groups, 
        "FULL")
}


### DENY
# true, if user is explicitly denied on a given global policy
global_policy_user_denied := true if {
    global_policy_user_has_permissions(
        nifi_inp.inherit_resource_id, 
        nifi_inp.user_name, 
        "DENY")
}

# true, if user-group is explicitly denied on a given global policy
global_policy_user_denied := true if {
    global_policy_group_has_permissions(
        nifi_inp.inherit_resource_id, 
        nifi_inp.user_groups, 
        "DENY")
}