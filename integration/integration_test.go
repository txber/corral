package integration

import (
	"strings"
	"testing"
)

// The fakes embed the interface they stand for, so they satisfy it without
// implementing methods these tests never call.
type fakeSandbox struct {
	Sandbox
	options map[string]any
}

type fakeKeyProxy struct {
	KeyProxy
	options map[string]any
}

type fakeRuntime struct {
	Runtime
	options map[string]any
}

func TestRegistryBuildsWhatTheFactoryReturns(t *testing.T) {
	RegisterSandbox("test-build", func(options map[string]any) (Sandbox, error) {
		return &fakeSandbox{options: options}, nil
	})
	RegisterKeyProxy("test-build", func(options map[string]any) (KeyProxy, error) {
		return &fakeKeyProxy{options: options}, nil
	})
	RegisterRuntime("test-build", func(options map[string]any) (Runtime, error) {
		return &fakeRuntime{options: options}, nil
	})
	options := map[string]any{"marker": "x"}

	sandbox, err := NewSandbox("test-build", options)
	if err != nil {
		t.Fatal(err)
	}
	if s, ok := sandbox.(*fakeSandbox); !ok || s.options["marker"] != "x" {
		t.Errorf("NewSandbox = %#v, want the fake built with the options", sandbox)
	}

	proxy, err := NewKeyProxy("test-build", options)
	if err != nil {
		t.Fatal(err)
	}
	if p, ok := proxy.(*fakeKeyProxy); !ok || p.options["marker"] != "x" {
		t.Errorf("NewKeyProxy = %#v, want the fake built with the options", proxy)
	}

	runtime, err := NewRuntime("test-build", options)
	if err != nil {
		t.Fatal(err)
	}
	if r, ok := runtime.(*fakeRuntime); !ok || r.options["marker"] != "x" {
		t.Errorf("NewRuntime = %#v, want the fake built with the options", runtime)
	}
}

func TestUnknownNameListsTheRegisteredOnes(t *testing.T) {
	RegisterRuntime("test-list-b", func(map[string]any) (Runtime, error) { return &fakeRuntime{}, nil })
	RegisterRuntime("test-list-a", func(map[string]any) (Runtime, error) { return &fakeRuntime{}, nil })

	runtime, err := NewRuntime("missing", nil)
	if err == nil {
		t.Fatalf("NewRuntime(missing) = %#v, want an error", runtime)
	}
	if runtime != nil {
		t.Errorf("NewRuntime(missing) returned %#v with the error, want nil", runtime)
	}
	msg := err.Error()
	if !strings.Contains(msg, `"missing"`) {
		t.Errorf("error %q does not name the unknown name", msg)
	}
	a, b := strings.Index(msg, "test-list-a"), strings.Index(msg, "test-list-b")
	if a < 0 || b < 0 || a > b {
		t.Errorf("error %q does not list the registered names in sorted order", msg)
	}

	if _, err := NewSandbox("missing", nil); err == nil {
		t.Error("NewSandbox(missing) succeeded, want an error")
	}
	if _, err := NewKeyProxy("missing", nil); err == nil {
		t.Error("NewKeyProxy(missing) succeeded, want an error")
	}
}

func TestRegisteringTwicePanics(t *testing.T) {
	factory := func(map[string]any) (Sandbox, error) { return &fakeSandbox{}, nil }
	RegisterSandbox("test-twice", factory)
	defer func() {
		if recover() == nil {
			t.Error("registering a name twice did not panic")
		}
	}()
	RegisterSandbox("test-twice", factory)
}
