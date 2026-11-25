package netns_test

import (
	"testing"

	"github.com/txber/corral/internal/netns"
	"github.com/txber/corral/internal/scope"
)

// targetTexts are good and bad targets, including near misses that a
// careless parser would accept.
var targetTexts = []string{
	"10.10.4.7:tcp:445",
	"10.10.4.0/24:tcp:1-1024",
	"10.10.4.7:udp:53",
	"10.10.4.7/32:udp:1-65535",
	"10.0.0.0/8:tcp:22",
	"192.0.2.1:tcp:65535",
	"10.10.4.0/255.255.255.0:tcp:80",
	"::1:tcp:80",
	"::ffff:10.10.4.7:tcp:80",
	"example.com:tcp:80",
	"0.0.0.0/0:tcp:80",
	"10.0.0.0/7:tcp:80",
	"10.10.4.7:tcp:0",
	"10.10.4.7:tcp:70000",
	"10.10.4.7:tcp:90-80",
	"10.10.4.7:icmp:1",
	"10.10.4.7/24:tcp:80",
	"10.10.4.7/33:tcp:80",
	"10.10.4.7/08:tcp:80",
	"10.10.4.7:tcp",
	"",
	"10.10.4.7:tcp:80;x",
	"10.10.4.7:TCP:80",
	"10.10.4.7:tcp:080",
	"10.10.4.7:tcp:+80",
	" 10.10.4.7:tcp:80",
	"10.10.4.7:tcp:80-",
	"10.10.4.7:tcp:-80",
	"10.10.4.7:tcp:80-90-100",
	"010.10.4.7:tcp:80",
	"10.10.4.7:tcp:８０",
	"10.10.4.7:tcp:٨٠",
	"10.10.4.7:tcp:80:x",
	"10.10.4.7%eth0:tcp:80",
}

func TestTargetParserAgreesWithScope(t *testing.T) {
	for _, text := range targetTexts {
		checkAgreement(t, text)
	}
}

func FuzzTargetParserAgreesWithScope(f *testing.F) {
	for _, text := range targetTexts {
		f.Add(text)
	}
	f.Fuzz(checkAgreement)
}

func checkAgreement(t *testing.T, text string) {
	want, wantErr := scope.ParseTarget(text)
	got, err := netns.ParseTarget(text)
	if (err == nil) != (wantErr == nil) {
		t.Fatalf("%q: netns error %v, scope error %v", text, err, wantErr)
	}
	if err != nil {
		return
	}
	if got.Network != want.Network || got.Proto != want.Proto || got.First != want.First || got.Last != want.Last {
		t.Fatalf("%q: netns %+v, scope %+v", text, got, want)
	}
}
