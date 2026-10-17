// Package ns names the resource namespaces termcp keeps off its ordinary
// surfaces.
//
// A namespace is carried on the resource itself (api.Session.Namespace) rather
// than held in a side table, for one reason: a session outlives the process that
// created it. The manager restores the manifests written by the previous run, so
// a tag that lived only in memory would come back untagged and a leftover
// extension session would reappear as an ordinary archived session. The value is
// what the external mapping is keyed on — resource kind + id resolve through the
// record, and this package owns the vocabulary that turns "who owns it" into the
// string everything else filters on.
package ns

import "strings"

// Extensions is the root of every namespace the extension layer owns. A session
// an extension is served by is not a session the user asked for: it is termcp's
// own infrastructure, kept warm on the extension's behalf, and it belongs to the
// extension column rather than on the session and archive cards.
const Extensions = "ext"

// ForExtensions renders the namespace of an extension group's session. The
// suffix is the host the group dials, so the namespace says not only "hidden"
// but which pile of extensions a session belongs to — which is what makes an
// unexpected one identifiable in a log.
//
// Two groups may share a suffix (the same host reached with different
// capabilities are two sessions), so this is a namespace, not an identity: the
// group key is what decides which extensions share a session.
func ForExtensions(target string) string {
	target = strings.TrimSpace(target)
	if target == "" {
		return Extensions
	}
	return Extensions + ":" + target
}

// IsExtensions reports whether a namespace belongs to the extension layer. It is
// the question the reconciler asks about a session it finds on disk: Hidden says
// "is this off the ordinary surfaces", which a second subsystem's namespaces also
// answer, so sweeping on Hidden would let the extension reconciler delete another
// subsystem's restored sessions.
func IsExtensions(namespace string) bool {
	return namespace == Extensions || strings.HasPrefix(namespace, Extensions+":")
}

// Hidden reports whether resources in this namespace stay off the ordinary
// session surfaces: the session and archive cards, the node cards' session
// counts, and the agent's session_list. An empty namespace is the default and is
// never hidden, so every session that existed before namespaces did keeps being
// listed exactly as it was.
func Hidden(namespace string) bool {
	return namespace != ""
}
