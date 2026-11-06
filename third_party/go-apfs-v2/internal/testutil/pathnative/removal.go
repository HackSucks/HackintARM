package pathnative

// RemovalContext records the native object and provider context surrounding one
// sequence of fremovexattr calls. Identity values are observations, not portable
// identifiers to synthesize on a receiving filesystem.
type RemovalContext struct {
	Device, Inode                                    uint64
	UID, GID, Mode, Flags                            uint32
	ProcessUID, ProcessEUID, ProcessGID, ProcessEGID uint32
	Sandboxed                                        bool
	FileSystem                                       string
	MountFlags                                       uint64
	OpenFlags, ACLErrno                              int
	ACLHex                                           string
}
type RemovalValue struct {
	Size, Read, SizeErrno, ReadErrno int
	Hex                              string
}
type RemovalOperation struct {
	InputHex      string
	NameHex       string
	Before, After RemovalValue
	Code, Errno   int
}
type RemovalCase struct {
	Symlink, Dangling                                  bool
	Operation                                          string
	Directory                                          bool
	RequestedMode, ACLKind, RequestedAccess, OpenErrno int
	BeforeContext, AfterContext                        RemovalContext
	NamesHex                                           string
	Operations                                         []RemovalOperation
	CleanupVerified                                    bool
}
type RemovalFixture struct {
	Revision, Host, HelperSHA256 string
	ProviderSHA256               string
	Cases                        []RemovalCase
}
