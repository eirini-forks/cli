package sharedaction

// IsLoggedIn checks whether a user has authenticated with CF
func (actor Actor) IsLoggedIn() bool {
	return actor.isLoggedIn(actor.Config)
}

func DefaultIsLoggedIn(config Config) bool {
	return config.AccessToken() != "" || config.RefreshToken() != ""
}

func KubernetesIsLoggedIn(config Config) bool {
	return config.KubernetesUser() != ""
}
