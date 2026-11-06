// Package pathsecurity describes the unchanged Apple temporary-permission
// oracle. Native error injection is separate from the real ACL/filesec APIs.
package pathsecurity

type Metadata struct {
	ModePresent             bool
	Mode                    uint32
	ACLCount                int
	FirstRights, FirstFlags uint32
	FirstTag                int
	FirstMatchesRealUID     bool
}

type Observation struct {
	Before                 Metadata
	Events                 []string
	Code, Errno            int
	RealEqualsEffectiveUID bool
	After                  *Metadata
}

type Case struct {
	Operation, Count, First, Flags, Mode, Fault int
	Native                                      Observation
}

type Fixture struct {
	Revision, Host, SourceSHA256, HelperSHA256 string
	Cases                                      []Case
}

// Cases selects actual empty/missing/maximum ACLs, exact and near-miss ACEs,
// inheritance flags, optional mode properties and failures in each provider
// used by the unchanged functions. Fault 3 is ENOTSUP; other faults are EIO.
func Cases() []Case {
	var cases []Case
	for _, count := range []int{-1, 0, 1, 127, 128} {
		for _, mode := range []int{0, 1} {
			for _, fault := range []int{0, 5, 6, 8, 9} {
				cases = append(cases, Case{Count: count, Mode: mode, Fault: fault})
			}
		}
	}
	for _, count := range []int{0, 1, 2, 128} {
		for _, first := range []int{0, 1, 2, 3} {
			for _, flags := range []int{0, 1, 31} {
				for fault := 0; fault <= 10; fault++ {
					cases = append(cases, Case{Operation: 1, Count: count, First: first, Flags: flags, Mode: 1, Fault: fault})
				}
			}
		}
	}
	cases = append(cases, Case{Operation: 2, Count: -1})
	return cases
}
