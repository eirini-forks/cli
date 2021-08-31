// Package sharedaction handles all operations that do not require a cloud
// controller
package sharedaction

// Actor handles all shared actions
type Actor struct {
	Config     Config
	isLoggedIn func(config Config) bool
}

// NewActor returns an Actor with default settings
func NewActor(config Config) *Actor {
	actor := &Actor{
		Config:     config,
		isLoggedIn: DefaultIsLoggedIn,
	}
	if config.IsKubernetes() {
		actor.isLoggedIn = KubernetesIsLoggedIn
	}
	return actor
}
