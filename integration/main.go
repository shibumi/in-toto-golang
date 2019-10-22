package main

import (
    "github.com/in-toto/in-toto-golang/in_toto"
    "os/exec"
	"os"
	"log"
)


func main() {
	validKey := `{"keytype": "ed25519", "scheme": "ed25519", "keyid": "308e3f53523b632983a988b72a2e39c85fe8fc967116043ce51fa8d92a6aef64", "keyid_hash_algorithms": ["sha256", "sha512"], "keyval": {"public": "8f93f549eb4cca8dc2142fb655ba2d0955d1824f79474f354e38d6a359e9d440", "private": "861fd1b466cfc6f73f8ed630f99d8eda250421f0e3a6123fd5c311cc001bda49"}}`
	key, err := in_toto.Parseed25519FromPrivateJSON(validKey)
	if err != nil {
		log.Fatal("Parseed25519FromPrivateJSON failed(%s)", err)
	}

	mbMemory := in_toto.Metablock{
		Signed: in_toto.Link{
			Type: "link",
			Name: "package",
			Command: []string{
				"tar",
				"zcvf",
				"foo.tar.gz",
				"foo.py",
			},
			Materials: map[string]interface{}{
				"foo.py": map[string]interface{}{
					"sha256": "74dc3727c6e89308b39e4dfedf787e37841198b1fa165a27c013544a60502549",
				},
			},
			Products: map[string]interface{}{
				"foo.tar.gz": map[string]interface{}{
					"sha256": "52947cb78b91ad01fe81cd6aef42d1f6817e92b9e6936c1e5aabb7c98514f355",
				}, },
			ByProducts: map[string]interface{}{
				"return-value": float64(0),
				"stderr":       "a foo.py\n",
				"stdout":       "",
			},
			Environment: map[string]interface{}{},
		},
		Signatures: []in_toto.Signature{},
	}
	pubkey := `{"keytype": "ed25519", "scheme": "ed25519", "keyid": "308e3f53523b632983a988b72a2e39c85fe8fc967116043ce51fa8d92a6aef64", "keyid_hash_algorithms": ["sha256", "sha512"], "keyval": {"public": "8f93f549eb4cca8dc2142fb655ba2d0955d1824f79474f354e38d6a359e9d440", "private": ""}}`
	file, err := os.Create("test.pub")
	if err != nil {
		log.Fatal("couldn't pubkey file for writing: %s", err)
	}
	file.Write([]byte(pubkey))

    mbMemory.Sign(key)
    mbMemory.Dump("test.link")
    cmd := exec.Command("in-toto-sign", "-f", "test.link", "--verify", "-k",
		"test.pub", "-t", "ed25519")

	err = cmd.Run()
	if err != nil {
		log.Fatal("command ran with error %v", err)
	}
}
