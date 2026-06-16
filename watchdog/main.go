// lockguard-svc — the watchdog Windows service.
//
// Subcommands:
//
//	lockguard-svc.exe --service-install   register as Auto + restart-on-failure
//	lockguard-svc.exe --service-remove    unregister
//	lockguard-svc.exe --service-run       invoked by SCM only
//	lockguard-svc.exe --once               run one enforcement pass (debug)
//
// Run with no args from a console: prints help.
package main

import (
	"flag"
	"fmt"
	"os"
)

func main() {
	install := flag.Bool("service-install", false, "register the Lockguard watchdog service")
	remove := flag.Bool("service-remove", false, "unregister the Lockguard watchdog service")
	run := flag.Bool("service-run", false, "run as a Windows service (SCM only)")
	once := flag.Bool("once", false, "run a single enforcement pass and exit (debug)")
	flag.Parse()

	switch {
	case *install:
		if err := serviceInstall(); err != nil {
			fmt.Fprintf(os.Stderr, "install failed: %v\n", err)
			os.Exit(1)
		}
		fmt.Println("lockguard-svc installed (Auto, restart-on-failure)")
	case *remove:
		if err := serviceRemove(); err != nil {
			fmt.Fprintf(os.Stderr, "remove failed: %v\n", err)
			os.Exit(1)
		}
		fmt.Println("lockguard-svc removed")
	case *run:
		serviceRun()
	case *once:
		enforceOnce()
	default:
		fmt.Println("lockguard-svc: watchdog for the Lockguard kernel driver.")
		fmt.Println("Usage:")
		flag.PrintDefaults()
		os.Exit(2)
	}
}
