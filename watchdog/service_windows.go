//go:build windows && amd64

// SCM dispatcher: install / remove / run for the lockguard-svc service.
// Adapted from kiosk-exit-guard's service_windows.go.

package main

import (
	"fmt"
	"os"
	"time"

	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/mgr"
)

const (
	svcName        = "lockguard-svc"
	svcDisplayName = "Lockguard Watchdog Service"
	svcDescription = "Re-enforces Lockguard policy and respawns the kernel driver if it stops."
)

func serviceInstall() error {
	exe, err := os.Executable()
	if err != nil {
		return err
	}

	m, err := mgr.Connect()
	if err != nil {
		return err
	}
	defer m.Disconnect()

	if s, err := m.OpenService(svcName); err == nil {
		s.Close()
		return fmt.Errorf("service %s already exists; remove it first", svcName)
	}

	s, err := m.CreateService(svcName, exe, mgr.Config{
		ServiceType:    0x10, // SERVICE_WIN32_OWN_PROCESS
		StartType:      mgr.StartAutomatic,
		ErrorControl:   mgr.ErrorNormal,
		DisplayName:    svcDisplayName,
		Description:    svcDescription,
		BinaryPathName: fmt.Sprintf(`"%s" --service-run`, exe),
	}, "--service-run")
	if err != nil {
		return err
	}
	defer s.Close()

	// Restart on failure, three quick attempts.
	r := []mgr.RecoveryAction{
		{Type: mgr.ServiceRestart, Delay: 5 * time.Second},
		{Type: mgr.ServiceRestart, Delay: 5 * time.Second},
		{Type: mgr.ServiceRestart, Delay: 30 * time.Second},
	}
	if err := s.SetRecoveryActions(r, 0); err != nil {
		return err
	}

	// Start it.
	if err := s.Start(); err != nil {
		return fmt.Errorf("created but failed to start: %w", err)
	}
	return nil
}

func serviceRemove() error {
	m, err := mgr.Connect()
	if err != nil {
		return err
	}
	defer m.Disconnect()

	s, err := m.OpenService(svcName)
	if err != nil {
		return err
	}
	defer s.Close()

	if _, err := s.Control(svc.Stop); err != nil {
		// Ignore — service may not be running.
	}
	return s.Delete()
}

// ---------- SCM dispatcher -------------------------------------------------

type lockguardSvc struct{}

func (lockguardSvc) Execute(args []string, r <-chan svc.ChangeRequest, status chan<- svc.Status) (bool, uint32) {
	// Deliberately omit svc.AcceptStop: the watchdog must resist `sc stop lockguard-svc`
	// and Services.msc termination, even by an admin. Only OS shutdown can stop us cleanly.
	const accepts = svc.AcceptShutdown

	status <- svc.Status{State: svc.StartPending}

	// Start enforcement loop on a background goroutine.
	stop := make(chan struct{})
	done := make(chan struct{})
	go func() {
		enforceLoop(stop)
		close(done)
	}()

	status <- svc.Status{State: svc.Running, Accepts: accepts}

	for {
		c := <-r
		switch c.Cmd {
		case svc.Interrogate:
			status <- c.CurrentStatus
		case svc.Shutdown:
			status <- svc.Status{State: svc.StopPending}
			close(stop)
			<-done
			status <- svc.Status{State: svc.Stopped}
			return false, 0
		case svc.Stop:
			// AcceptStop is not advertised, so SCM should not deliver svc.Stop.
			// If it arrives anyway (malformed control packet), refuse it and stay running.
			status <- svc.Status{State: svc.Running, Accepts: accepts}
		}
	}
}

func serviceRun() {
	if err := svc.Run(svcName, lockguardSvc{}); err != nil {
		fmt.Fprintf(os.Stderr, "service.Run failed: %v\n", err)
		os.Exit(1)
	}
}
