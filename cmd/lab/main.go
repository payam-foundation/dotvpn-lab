// Command lab runs the profile x carrier matrix and renders or diffs its
// report. It shells out to `go test` so the harness stays the single owner of
// binary builds and process management.
package main

import (
	"flag"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"

	"github.com/payam-foundation/dotvpn-lab/internal/report"
)

func main() {
	if len(os.Args) < 2 {
		usage()
	}
	switch os.Args[1] {
	case "matrix":
		fs := flag.NewFlagSet("matrix", flag.ExitOnError)
		out := fs.String("out", "out", "output directory (relative to the module)")
		update := fs.Bool("update", false, "rewrite profiles/baseline.json from this run")
		_ = fs.Parse(os.Args[2:])
		cmd := exec.Command("go", "test", "-count=1", "-timeout", "20m", "-run", "TestMatrix", "./suites/matrix/")
		cmd.Env = append(os.Environ(), "LAB_MATRIX=1", "LAB_OUT="+*out)
		if *update {
			cmd.Env = append(cmd.Env, "LAB_UPDATE=1")
		}
		cmd.Stdout, cmd.Stderr = os.Stdout, os.Stderr
		runErr := cmd.Run()
		if err := render(filepath.Join(*out, "matrix.json"), "profiles/baseline.json", filepath.Join(*out, "matrix.md")); err != nil {
			fmt.Fprintln(os.Stderr, err)
		}
		if runErr != nil {
			os.Exit(1)
		}
	case "report":
		fs := flag.NewFlagSet("report", flag.ExitOnError)
		mp := fs.String("matrix", "out/matrix.json", "matrix.json")
		bp := fs.String("baseline", "profiles/baseline.json", "baseline.json")
		md := fs.String("md", "", "also write markdown here")
		_ = fs.Parse(os.Args[2:])
		m, err := report.ReadMatrix(*mp)
		check(err)
		b, err := report.ReadBaseline(*bp)
		check(err)
		changed, added, missing := report.Diff(m, b)
		for _, s := range changed {
			fmt.Println("CHANGED", s)
		}
		for _, s := range added {
			fmt.Println("NEW    ", s)
		}
		for _, s := range missing {
			fmt.Println("MISSING", s)
		}
		if *md != "" {
			check(render(*mp, *bp, *md))
		}
		if len(changed)+len(added)+len(missing) > 0 {
			os.Exit(1)
		}
		fmt.Println("matrix matches baseline")
	default:
		usage()
	}
}

func render(mp, bp, out string) error {
	m, err := report.ReadMatrix(mp)
	if err != nil {
		return err
	}
	b, _ := report.ReadBaseline(bp)
	return os.WriteFile(out, []byte(report.Markdown(m, b)), 0o644)
}

func check(err error) {
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}
}

func usage() {
	fmt.Fprintln(os.Stderr, "usage: lab matrix [-out dir] [-update] | lab report [-matrix f] [-baseline f] [-md f]")
	os.Exit(2)
}
