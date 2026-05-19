package leader

import metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

// metaObject builds the ObjectMeta the LeaseLock expects. Wrapped in a
// helper so leader.go stays focused on election logic rather than k8s
// metadata plumbing.
func metaObject(namespace, name string) metav1.ObjectMeta {
	return metav1.ObjectMeta{Namespace: namespace, Name: name}
}
