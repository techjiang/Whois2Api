package lookup

import "golang.org/x/sync/singleflight"

// singleflightGroup is a thin alias so the Service struct does not leak the
// dependency type into its documentation.
type singleflightGroup = singleflight.Group
