package constant

import (
	"os"
	"strconv"
)

// HardenedEnv is set by the YueLink desktop service helper on the mihomo
// child it runs as root / SYSTEM. The config that child executes is written
// by an unprivileged user (and can be replaced at any time through the REST
// API), so every config surface that could act with the child's privileges
// outside its private home directory is disabled while it is set. The value
// comes from the helper's environment, which the user cannot influence.
const HardenedEnv = "YUELINK_HARDENED_CORE"

// Hardened reports whether this process runs under the privileged helper.
var Hardened = func() bool {
	v, _ := strconv.ParseBool(os.Getenv(HardenedEnv))
	return v
}()
