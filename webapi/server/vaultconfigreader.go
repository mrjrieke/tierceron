package server

import (
	"bitbucket.org/dexterchaney/whoville/vaulthelper/kv"
)

//GetConfig gets a configuration by env and path.
func (s *Server) GetConfig(env string, path string) (map[string]interface{}, error) {
	mod, err := kv.NewModifier(s.VaultToken, s.VaultAddr)
	if err != nil {
		return nil, err
	}
	mod.Env = env
	return mod.ReadData(path)
}