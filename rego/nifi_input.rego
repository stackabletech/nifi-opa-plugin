package nifi_inp

# Nifi Input
inherit_resource_id := input.resource.id
inherit_resource_name := input.resource.name
inherit_resource_safeDescr := input.resource.safeDescription
resource_id := input.requestedResource.id
resource_name := input.requestedResource.name
resource_safeDescr := input.requestedResource.safeDescription
resource_context := input.resourceContext
action := input.action.name
user_name := input.identity.name
user_groups := split(input.identity.groups, ",")
user_context := input.userContext
isAccessAttempt := input.properties.isAccessAttempt
isAnonymous := input.properties.isAnonymous