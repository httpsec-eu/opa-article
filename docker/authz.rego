# Default deny access to outside Docker repositories
# --------------------------------------------------
#
# This rule set denies access to Docker repositories
# that are outside the organization.
#
# Author: Denis Rendler <connect@rendler.net>

package docker.authz

import rego.v1

# Default deny any action
default allow := false

# Allow only if all conditions are met
allow if {
	not count(deny_create) != 0
	not count(deny_pull) != 0
	not count(deny_latest_tag) != 0
	not count(deny_root_mount) != 0
}

# Deny if container is created with an outside image
deny_create contains message if {
	input.Method == "POST"
	endswith(input.Path, "containers/create")
	not startswith(input.Body.Image, "harbor.httpsec.eu")
	message := sprintf("image '%v' is not allowed", [input.Body.Image])
}

# Deny image pull if image is from a repository outside company
deny_pull contains message if {
	input.Method == "POST"
	endswith(input.PathPlain, "images/create")
	every img in input.Query.fromImage {
		not startswith(img, "harbor.httpsec.eu")
	}
	message := sprintf("image '%v' is not allowed", input.Query.fromImage)
}

# Deny image pull for 'latest' tag as that can be 
# easily switched to a vulnerable image
deny_latest_tag contains message if {
	"latest" in input.Query.tag
	message := "tag 'latest' is not allowed due to policy"
}

deny_root_mount contains message if {
	input.Method == "POST"
	endswith(input.Path, "containers/create")
	every path in input.BindMounts {
		path.Source == "/"
	}
	message := "mounting root host fs is not allowed due to policy"
}
