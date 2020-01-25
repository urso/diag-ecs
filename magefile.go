//+build mage

package main

import (
	"context"
	"fmt"
	"os"
	"path/filepath"

	"github.com/magefile/mage/mg"
	"github.com/magefile/mage/sh"
	"github.com/urso/magetools/clitool"
	"github.com/urso/magetools/fs"
	"github.com/urso/magetools/gotool"
	"github.com/urso/magetools/mgenv"
	"gopkg.in/src-d/go-git.v4"
)

const defaultVersion = "1.4.0"
const defaultVersionTag = "v" + defaultVersion
const ecsRepositoryURL = "https://github.com/elastic/ecs.git"

var buildDir = mgenv.String("BUILD_DIR", "build", "set build directory to load temporary files into")
var version = mgenv.String("VERSION", defaultVersion, "set ecs version tag to check out")
var checkout = mgenv.String("USE_REF", defaultVersionTag, "set tag or branch name to checkout")
var repoURL = mgenv.String("REPOSITORY", ecsRepositoryURL, "URL used to clone the ECS repository")

var ecsDir = filepath.Join(buildDir, "ecs")

// Info namespace is used to print additional docs, help messages, and other info.
type Info mg.Namespace

// Prepare namespace is used to prepare/download/build common depenendencies for other tasks to run.
type Prepare mg.Namespace

// Env prints environment info
func (Info) Env() {
	printTitle("Mage environment variables")
	for _, k := range mgenv.Keys() {
		v, _ := mgenv.Find(k)
		fmt.Printf("%v=%v\n", k, v.Get())
	}
	fmt.Println()

	printTitle("Go info")
	sh.RunV(mg.GoCmd(), "env")
	fmt.Println()
}

// Vars prints the list of registered environment variables
func (Info) Vars() {
	for _, k := range mgenv.Keys() {
		v, _ := mgenv.Find(k)
		fmt.Printf("%v=%v  : %v\n", k, v.Default(), v.Doc())
	}
}

func (Prepare) Mkdirs() error {
	if !fs.Exists(buildDir) {
		return fs.MakeDirs(buildDir)
	}
	return nil
}

func (Prepare) Clone(ctx context.Context) error {
	mg.Deps(Prepare.Mkdirs)

	if fs.ExistsDir(ecsDir) {
		return nil
	}

	_, err := git.PlainCloneContext(ctx, ecsDir, false, &git.CloneOptions{
		URL:        repoURL,
		RemoteName: "upstream",
		Progress:   os.Stdout,
	})
	return err
}

func (Prepare) Checkout() error {
	mg.Deps(Prepare.Mkdirs, Prepare.Clone)

	repo, err := git.PlainOpen(ecsDir)
	if err != nil {
		return err
	}

	ref, err := repo.Tag(checkout)
	if err != nil {
		return fmt.Errorf("failed to query '%v' reference: %+w", version, err)
	}

	tree, err := repo.Worktree()
	if err != nil {
		return fmt.Errorf("failed to access worktree: %+w", err)
	}

	return tree.Checkout(&git.CheckoutOptions{
		Branch: ref.Name(),
	})
}

func (Prepare) All() error {
	mg.Deps(Prepare.Mkdirs, Prepare.Clone, Prepare.Checkout)
	return nil
}

func Clean() {
	os.RemoveAll(buildDir)
}

func Build(ctx context.Context) error {
	mg.Deps(Prepare.All)

	gobin := gotool.New(clitool.NewCLIExecutor(true), mg.GoCmd())
	return gobin.Run(ctx,
		gobin.Run.Script("./internal/scripts/genfields/main.go"),
		gobin.Run.ScriptArgs(
			clitool.BoolFlag("-fmt", true),
			clitool.Flag("-version", defaultVersion),
			clitool.Flag("-out", "ecs/ecs.go"),
			clitool.Flag("-schema", filepath.Join(ecsDir, "schemas")),
		),
	)
}

func printTitle(s string) {
	fmt.Println(s)
	for range s {
		fmt.Print("=")
	}
	fmt.Println()
}
