package configv3

func (c *Config) IsKubernetes() bool {
	return c.ConfigFile.Kubernetes
}

func (c *Config) KubernetesUser() string {
	return c.ConfigFile.KubernetesUser
}

func (c *Config) SetKubernetesUser(user string) {
	c.ConfigFile.KubernetesUser = user
}
