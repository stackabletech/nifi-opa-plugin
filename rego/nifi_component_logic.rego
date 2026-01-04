package nifi_comp

import rego.v1
import data.nifi_inp

import data.nifi_root_policies.root_policies
import data.nifi_node_policies.node_policies

# Root Component Rules Logic
root_policy_types := [key | key := object.keys(root_policies)[_]]
get_root_type := rt if {
    comp_type = root_policy_types[_]
    startswith(nifi_inp.inherit_resource_id, comp_type)
    rt = comp_type
}
comp_is_root_type := get_root_type in root_policy_types

component_exists_in_root(comp_type, res_name) := true if {
    comp_type in object.keys(root_policies)
    res_name in object.keys(root_policies[comp_type])
}

root_policy_user_has_permissions(comp_type, res_name, user_name, action) := true if {
    component_exists_in_root(comp_type, res_name)
    user_name in root_policies[comp_type][res_name][action]["users"]
} 
root_policy_group_has_permissions(comp_type, res_name, user_groups, action) := true if {
    component_exists_in_root(comp_type, res_name)
    x := { trim(k, " ") | k = root_policies[comp_type][res_name][action]["groups"][_] }
    y := { trim(k, " ") | k = user_groups[_] }
    count(x & y) > 0
}


# node Component Rules Logic
node_policy_types := [key | key := object.keys(node_policies)[_]]
get_node_type := nt if {
    comp_type = node_policy_types[_]
    startswith(nifi_inp.inherit_resource_id, comp_type)
    nt = comp_type
}
comp_is_node_type := get_node_type in node_policy_types
compID := array.reverse(split(nifi_inp.resource_id, "/"))[0]
inheritCompID := array.reverse(split(nifi_inp.inherit_resource_id, "/"))[0]

component_exists_in_node(comp_type, res_ID) := true if {
    comp_type in object.keys(node_policies)
    res_ID in object.keys(node_policies[comp_type])
}

node_policy_user_has_permissions(comp_type, res_ID, user_name, action) := true if {
    component_exists_in_node(comp_type, res_ID)
    user_name in node_policies[comp_type][res_ID][action]["users"]
}
node_policy_group_has_permissions(comp_type, res_ID, user_groups, action) := true if {
    component_exists_in_node(comp_type, res_ID)
    x := { trim(k, " ") | k = node_policies[comp_type][res_ID][action]["groups"][_] }
    y := { trim(k, " ") | k = user_groups[_] }
    count(x & y) > 0
}


### "NiFi Flow" - Access
flow_allowed:= true if {
    root_policy_user_has_permissions(
        get_root_type, 
        "NiFi Flow",
        nifi_inp.user_name,
        nifi_inp.action)
}
flow_denied:= true if { # macht nur Sinn für Unter-Res zu denyn
    root_policy_user_has_permissions(
        get_root_type, 
        "NiFi Flow",
        nifi_inp.user_name,
        "deny")
}

### Root component access

root_comp_allowed := true if {
    root_policy_user_has_permissions(
        get_root_type, 
        nifi_inp.resource_name,
        nifi_inp.user_name,
        nifi_inp.action)
}
root_comp_allowed := true if {
    root_policy_group_has_permissions(
        get_root_type, 
        nifi_inp.resource_name,
        nifi_inp.user_groups,
        nifi_inp.action)
}

root_comp_denied := true if {
    root_policy_user_has_permissions(
        get_root_type, 
        nifi_inp.resource_name,
        nifi_inp.user_name,
        "deny")
}
root_comp_denied := true if {
    root_policy_group_has_permissions(
        get_root_type, 
        nifi_inp.resource_name,
        nifi_inp.user_groups,
        "deny")
}

root_inherit_comp_allowed := true if {
    root_policy_user_has_permissions(
        get_root_type, 
        nifi_inp.inherit_resource_name,
        nifi_inp.user_name,
        nifi_inp.action)
}
root_inherit_comp_allowed := true if {
    root_policy_group_has_permissions(
        get_root_type, 
        nifi_inp.inherit_resource_name,
        nifi_inp.user_groups,
        nifi_inp.action)
}

root_inherit_comp_denied := true if {
    root_policy_user_has_permissions(
        get_root_type, 
        nifi_inp.inherit_resource_name,
        nifi_inp.user_name,
        "deny")
}
root_inherit_comp_denied := true if {
    root_policy_group_has_permissions(
        get_root_type, 
        nifi_inp.inherit_resource_name,
        nifi_inp.user_groups,
        "deny")
}



### Node component access

node_comp_allowed := true if {
    node_policy_user_has_permissions(
        get_node_type, 
        compID,
        nifi_inp.user_name,
        nifi_inp.action)
}
node_comp_allowed := true if {
    node_policy_group_has_permissions(
        get_node_type, 
        compID,
        nifi_inp.user_groups,
        nifi_inp.action)
}

node_comp_denied := true if {
    node_policy_user_has_permissions(
        get_node_type, 
        compID,
        nifi_inp.user_name,
        "deny")
}
node_comp_denied := true if {
    node_policy_group_has_permissions(
        get_node_type, 
        compID,
        nifi_inp.user_groups,
        "deny")
}

node_inherit_comp_allowed := true if {
    node_policy_user_has_permissions(
        get_node_type, 
        inheritCompID,
        nifi_inp.user_name,
        nifi_inp.action)
}
node_inherit_comp_allowed := true if {
    node_policy_group_has_permissions(
        get_node_type, 
        inheritCompID,
        nifi_inp.user_groups,
        nifi_inp.action)
}

node_inherit_comp_denied := true if {
    node_policy_user_has_permissions(
        get_node_type, 
        inheritCompID,
        nifi_inp.user_name,
        "deny")
}
node_inherit_comp_denied := true if {
    node_policy_group_has_permissions(
        get_node_type, 
        inheritCompID,
        nifi_inp.user_groups,
        "deny")
}

node_comp_has_action := true if {
    component_exists_in_node(get_node_type, inheritCompID)
    not nifi_inp.action in object.keys(node_policies[get_node_type][inheritCompID])
}

inherit_comp_exists_as_root := true if {
    component_exists_in_root(get_root_type, nifi_inp.inherit_resource_name)
}

comp_exists_as_root := true if {
    component_exists_in_root(get_root_type, nifi_inp.resource_name)
}

inherit_comp_exists_as_node := true if {
    component_exists_in_node(get_node_type, inheritCompID)
}

comp_exists_as_node := true if {
    component_exists_in_node(get_node_type, compID)
}
