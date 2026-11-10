package session

import (
	"context"
	"testing"
	"time"

	"github.com/hostinger/hcdn-connector/internal/h2srv"
	"github.com/hostinger/hcdn-connector/internal/proto"
	"github.com/hostinger/hcdn-connector/internal/testpki"
)

func reachManager(t *testing.T) *Manager {
	t.Helper()
	m := &Manager{Creds: newCreds(t, testpki.NewCA(t), "127.0.0.1")}
	m.Init()
	t.Cleanup(m.Close)
	return m
}

func waitReach(t *testing.T, m *Manager, wait time.Duration) (Reach, error) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	return m.WaitReachable(ctx, wait)
}

func TestWaitReachable(t *testing.T) {
	featured := h2srv.Hello{EdgeNode: "bnk-edge1", EdgeFeatures: []string{"ws", proto.EdgeFeatureVisible}}
	plain := h2srv.Hello{EdgeNode: "fast-edge2"}

	t.Run("visible wins over the wait", func(t *testing.T) {
		m := reachManager(t)
		m.noteHello("bnk", featured)
		go func() {
			time.Sleep(50 * time.Millisecond)
			m.noteVisible("bnk", h2srv.Visible{Scope: proto.VisibleScopeNode, EdgeNode: "bnk-edge1", At: time.Now()})
		}()
		r, err := waitReach(t, m, time.Minute)
		if err != nil || r.Scope != proto.VisibleScopeNode || r.Pop != "bnk" || r.EdgeNode != "bnk-edge1" {
			t.Fatalf("%+v %v", r, err)
		}
		// The first signal stays.
		m.noteVisible("fast", h2srv.Visible{Scope: proto.VisibleScopePop})
		if r, _ := waitReach(t, m, time.Minute); r.Scope != proto.VisibleScopeNode {
			t.Fatalf("%+v", r)
		}
	})
	t.Run("visible before any hello", func(t *testing.T) {
		m := reachManager(t)
		m.noteVisible("bnk", h2srv.Visible{Scope: proto.VisibleScopePop})
		if r, err := waitReach(t, m, time.Minute); err != nil || r.Scope != proto.VisibleScopePop {
			t.Fatalf("%+v %v", r, err)
		}
	})
	t.Run("edge without the feature", func(t *testing.T) {
		m := reachManager(t)
		m.noteHello("bnk", featured)
		m.noteHello("fast", plain)
		r, err := waitReach(t, m, time.Minute)
		if err != nil || r.Scope != ScopeSession || r.Pop != "fast" {
			t.Fatalf("%+v %v", r, err)
		}
	})
	t.Run("visible wait runs out", func(t *testing.T) {
		m := reachManager(t)
		start := time.Now()
		go func() { time.Sleep(50 * time.Millisecond); m.noteHello("bnk", featured) }()
		r, err := waitReach(t, m, 200*time.Millisecond)
		if err != nil || r.Scope != ScopeSession || r.Pop != "bnk" {
			t.Fatalf("%+v %v", r, err)
		}
		if d := time.Since(start); d < 250*time.Millisecond {
			t.Fatalf("resolved after %s", d)
		}
	})
	t.Run("ctx ends", func(t *testing.T) {
		m := reachManager(t)
		ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
		defer cancel()
		if _, err := m.WaitReachable(ctx, time.Minute); err != context.DeadlineExceeded {
			t.Fatalf("err %v", err)
		}
	})
}
