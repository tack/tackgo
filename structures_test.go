package main

import (
	"fmt"
	"log"
	"testing"
	"crypto/rand"
	"crypto/elliptic"
	"crypto/ecdsa"
	"tackgo/tack"
)

func TestStructures(test *testing.T) {
	tackStr := 
`
-----BEGIN TACK-----
JkpcUC1s4ETCyUFoujpfjpCZoa4Q52dcKmq8LoSS5kFdPard1BlGLwaIBikCyP84
kNgFVoSqYeirq8KwDSJ0BwAAAckZUzK2S2ZyeiBj5AZvO5WMsKruV2pezv2VM5m7
iHRzHZWHzDEj0rL1BJQ2/xumpCePIyywLQB8D9z3/X8k7P8jItKI2TEy1201W5dM
Hcip7C5zr98kfKjlw/UGG2y86KdCzQ==
-----END TACK-----
`
	t, err := tack.NewTackFromPem(tackStr)	
	if err != nil {test.Fatal(err)}
	
	// Test printing
	s := fmt.Sprint(t)
	if s != `key fingerprint = gv6qp.hmd4y.tsjxo.wcakm.sotjm
min_generation  = 0
generation      = 0
expiration      = 2026-12-16T01:55Z
target_hash     = 32b64b66727a2063e4066f3b958cb0aa
                  ee576a5ecefd953399bb8874731d9587
` {test.Fatal("tack print mismatch")}
	
	// Test verify
	if !t.Verify() {test.Fatal("bad verify")}

	// Test sign and verify
	curve := elliptic.P256()
	privKey, err := ecdsa.GenerateKey(curve, rand.Reader)
	if err=t.Sign(privKey); err != nil {test.Fatal(err)}
	if !t.Verify() {test.Fatal("bad verify #2")}

	// Test serialize and reparse
	s = t.SerializeAsPem()
	t2, err := tack.NewTackFromPem(s)
	if err != nil {test.Fatal(err)}
	s2 := t2.SerializeAsPem()
	if s != s2 {test.Fatal("tack string mismatch")}

	tackExtStr := 
`
-----BEGIN TACK EXTENSION-----
AUwmSlxQLWzgRMLJQWi6Ol+OkJmhrhDnZ1wqarwuhJLmQV09qt3UGUYvBogGKQLI
/ziQ2AVWhKph6KurwrANInQHAAAByRlTMrZLZnJ6IGPkBm87lYywqu5Xal7O/ZUz
mbuIdHMdlYfMMSPSsvUElDb/G6akJ48jLLAtAHwP3Pf9fyTs/yMi0ojZMTLXbTVb
l0wdyKnsLnOv3yR8qOXD9QYbbLzop0LNvaQcYI8ehsmaKxX8Ea3xI2HYfweoi6BP
pM00l9dVPx0ETNRTkGFcNGabQ33Ml1vaEI4Q2UEmJvQjQ0qBaig6nGT+Acke8zK2
S2ZyeiBj5AZvO5WMsKruV2pezv2VM5m7iHRzHZWH5UeQpow6aJweikYRq6NNPA7r
29ok8aGVudp5SB7o5Va8VGPysFjrcFgZSnx5K22yAKlhWqTbDNt+fOT+ZrPM+gA=
-----END TACK EXTENSION-----
`	
	te, err := tack.NewTackExtensionFromPem(tackExtStr)
	if err != nil {test.Fatal(err)}
	
	s = fmt.Sprint(te)
	if s != `key fingerprint = gv6qp.hmd4y.tsjxo.wcakm.sotjm
min_generation  = 0
generation      = 0
expiration      = 2026-12-16T01:55Z
target_hash     = 32b64b66727a2063e4066f3b958cb0aa
                  ee576a5ecefd953399bb8874731d9587
key fingerprint = w6v4n.wofh4.cqtjq.adcxi.teugp
min_generation  = 100
generation      = 254
expiration      = 2026-12-17T01:55Z
target_hash     = 32b64b66727a2063e4066f3b958cb0aa
                  ee576a5ecefd953399bb8874731d9587
activation_flags = 0
` {
		log.Println(s)
		test.Fatal("tack ext print mismatch")
	}

	s = te.SerializeAsPem()
	te2, err := tack.NewTackExtensionFromPem(s)
	if err != nil {test.Fatal(err)}
	s2 = te2.SerializeAsPem()
	if s != s2 {test.Fatal("tack ext string mismatch")}	
}

func TestStore(test *testing.T) {
	s := `[
["alpha.com", "aaaaa.kfbj5.oweph.mdyxi.wvbch", 0, 22468065, 22468074],
["beta.com", "xxxxx.qqqqq.wwwww.eeeee.rrrrr", 1, 22468065, 22468074],
["test.tack.io", "j6det.kfbj5.oweph.mdyxi.wvbch", 255, 0, 30000000]
]`
	store, err := tack.NewDefaultStoreFromJSON(s)
	if err != nil {test.Fatal(err)}
	s2 := store.String()
	if s != s2 {test.Fatal("store string mismatch")}

	s = `[
["alpha.com", "aaaaa.kfbj5.oweph.mdyxi.wvbch", 0, 22468065],
["beta.com", "xxxxx.qqqqq.wwwww.eeeee.rrrrr", 1, 22468065, 22468074],
["test.tack.io", "j6det.kfbj5.oweph.mdyxi.wvbch", 255, 0, 30000000]
]`

	store, err = tack.NewDefaultStoreFromJSON(s)
	if _,ok := err.(tack.PinListError); !ok {test.Fatal("wrong error for pin store")}
}