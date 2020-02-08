// Copyright 2014 The rkt Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package main

import (
	"bytes"
	"errors"
	"flag"
	"fmt"
	"io/ioutil"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"syscall"

	"github.com/appc/spec/schema/types"
	"github.com/hashicorp/errwrap"

	stage1common "github.com/rkt/rkt/stage1/common"
	stage1commontypes "github.com/rkt/rkt/stage1/common/types"
	stage1initcommon "github.com/rkt/rkt/stage1/init/common"

	"github.com/rkt/rkt/common"
	commonnet "github.com/rkt/rkt/common/networking"
	"github.com/sstabellini/rkt/networking"
	pkgflag "github.com/rkt/rkt/pkg/flag"
	rktlog "github.com/rkt/rkt/pkg/log"
	"github.com/rkt/rkt/pkg/sys"
)

var (
	debug       bool
	localhostIP net.IP
	localConfig string
	log         *rktlog.Logger
	diag        *rktlog.Logger
	interpBin   string // Path to the interpreter within the stage1 rootfs, set by the linker
)

func parseFlags() *stage1commontypes.RuntimePod {
	rp := stage1commontypes.RuntimePod{}

	flag.BoolVar(&debug, "debug", false, "Run in debug mode")
	flag.StringVar(&localConfig, "local-config", common.DefaultLocalConfigDir, "Local config path")

	// These flags are persisted in the PodRuntime
	flag.BoolVar(&rp.Interactive, "interactive", false, "The pod is interactive")
	flag.BoolVar(&rp.Mutable, "mutable", false, "Enable mutable operations on this pod, including starting an empty one")
	flag.Var(&rp.NetList, "net", "Setup networking")
	flag.StringVar(&rp.PrivateUsers, "private-users", "", "Run within user namespace. Can be set to [=UIDBASE[:NUIDS]]")
	flag.StringVar(&rp.MDSToken, "mds-token", "", "MDS auth token")
	flag.StringVar(&rp.Hostname, "hostname", "", "Hostname of the pod")
	flag.BoolVar(&rp.InsecureOptions.DisableCapabilities, "disable-capabilities-restriction", false, "Disable capability restrictions")
	flag.BoolVar(&rp.InsecureOptions.DisablePaths, "disable-paths", false, "Disable paths restrictions")
	flag.BoolVar(&rp.InsecureOptions.DisableSeccomp, "disable-seccomp", false, "Disable seccomp restrictions")
	dnsConfMode := pkgflag.MustNewPairList(map[string][]string{
		"resolv": {"host", "stage0", "none", "default"},
		"hosts":  {"host", "stage0", "default"},
	}, map[string]string{
		"resolv": "default",
		"hosts":  "default",
	})
	flag.Var(dnsConfMode, "dns-conf-mode", "DNS config file modes")

	flag.Parse()

	rp.Debug = debug
	rp.ResolvConfMode = dnsConfMode.Pairs["resolv"]
	rp.EtcHostsMode = dnsConfMode.Pairs["hosts"]

	return &rp
}

func init() {
	// this ensures that main runs only on main thread (thread group leader).
	// since namespace ops (unshare, setns) are done for a single thread, we
	// must ensure that the goroutine does not jump from OS thread to thread
	runtime.LockOSThread()

	// We'll need this later
	localhostIP = net.ParseIP("127.0.0.1")
	if localhostIP == nil {
		panic("localhost IP failed to parse")
	}
}

// getArgsEnv returns the nspawn or lkvm args and env according to the flavor
// as the first two return values respectively.
func getArgsEnv(p *stage1commontypes.Pod, flavor string, debug bool, n *networking.Networking) ([]string, []string, error) {
	var args []string
	env := os.Environ()

	// We store the pod's flavor so we can later garbage collect it correctly
	if err := os.Symlink(flavor, filepath.Join(p.Root, stage1initcommon.FlavorFile)); err != nil {
		return nil, nil, errwrap.Wrap(errors.New("failed to create flavor symlink"), err)
	}

	switch flavor {
	case "xen":
		args = append(args, filepath.Join(common.Stage1RootfsPath(p.Root), "run"))
		if p.Interactive {
			args = append(args, "--interactive")
		}
		if n == nil {
				args = append(args, fmt.Sprintf("pvcalls"))
		} else {
			for _, nd := range n.GetActiveNetworks() {
				args = append(args, fmt.Sprintf("ip=%s bridge=%s", nd.GuestIP(), nd.IfName()))

				for _, route := range nd.Routes() {
					gw := route.GW
					if gw == nil {
						gw = nd.Gateway()
					}

					args = append(args, fmt.Sprintf("route=%s gw=%s", route.Dst.String(), gw.String()))
				}
				break
			}
		}
		args = append(args, p.UUID.String())
		return args, env, nil
	default:
		return nil, nil, fmt.Errorf("unrecognized stage1 flavor: %q", flavor)
	}
}

func stage1(rp *stage1commontypes.RuntimePod) int {
	uuid, err := types.NewUUID(flag.Arg(0))
	if err != nil {
		log.FatalE("UUID is missing or malformed", err)
	}

	root := "."
	p, err := stage1commontypes.LoadPod(root, uuid, rp)
	if err != nil {
		log.FatalE("failed to load pod", err)
	}

	if err := p.SaveRuntime(); err != nil {
		log.FatalE("failed to save runtime parameters", err)
	}

	// set close-on-exec flag on RKT_LOCK_FD so it gets correctly closed when invoking
	// network plugins
	lfd, err := common.GetRktLockFD()
	if err != nil {
		log.FatalE("failed to get rkt lock fd", err)
	}

	if err := sys.CloseOnExec(lfd, true); err != nil {
		log.FatalE("failed to set FD_CLOEXEC on rkt lock", err)
	}

	flavor, _, err := stage1initcommon.GetFlavor(p)
	if err != nil {
		log.FatalE("failed to get stage1 flavor", err)
	}

	var n *networking.Networking
	if p.NetList.Contained() {
		fps, err := commonnet.ForwardedPorts(p.Manifest)
		if err != nil {
			log.FatalE("error initializing forwarding ports", err)
		}

		noDNS := p.ResolvConfMode != "default" // force ignore CNI DNS results
		n, err = networking.Setup(root, p.UUID, fps, p.NetList, localConfig, flavor, noDNS, debug)
		if err != nil {
			log.FatalE("failed to setup network", err)
		}

		if err = n.Save(); err != nil {
			log.PrintE("failed to save networking state", err)
			n.Teardown(flavor, debug)
			return 254
		}

		if len(p.MDSToken) > 0 {
			hostIP, err := n.GetForwardableNetHostIP()
			if err != nil {
				log.FatalE("failed to get default Host IP", err)
			}

			p.MetadataServiceURL = common.MetadataServicePublicURL(hostIP, p.MDSToken)
		}
	} else {
		if len(p.MDSToken) > 0 {
			p.MetadataServiceURL = common.MetadataServicePublicURL(localhostIP, p.MDSToken)
		}
	}

	ra := p.Manifest.Apps[0]
	appEnv := composeEnvironment(ra.App.Environment)
	appsPath := common.AppPath(p.Root, ra.Name)

	if err := writeEnvFile(appsPath, appEnv); err != nil {
		log.PrintE("can't write env", err)
		return 254
	}

	args, env, err := getArgsEnv(p, flavor, debug, n)
	if err != nil {
		log.FatalE("cannot get environment", err)
	}
	diag.Printf("args %q", args)
	diag.Printf("env %q", env)

	pid_filename := "ppid"
	if err = stage1common.WritePid(os.Getpid(), pid_filename); err != nil {
		log.FatalE("error writing pid", err)
	}
	err = stage1common.WithClearedCloExec(lfd, func() error {
		return syscall.Exec(args[0], args, env)
	})

	if err != nil {
		log.FatalE(fmt.Sprintf("failed to execute %q", args[0]), err)
	}


	return 0
}

// writeEnvFile creates an external-environment file under appDir
// with entries from PodManifest.App.Environments
func writeEnvFile(appDir string, environment types.Environment) error {
	envFilePath := filepath.Join(appDir, "external-environment")
	ef := bytes.Buffer{}

	//If environment is nil, then empty file will be created
	if environment != nil {
		for _, env := range environment {
			fmt.Fprintf(&ef, "export %s='%s'\n", env.Name, env.Value)
		}
	}

	if err := os.MkdirAll(filepath.Dir(envFilePath), 0755); err != nil {
		return err
	}

	if err := ioutil.WriteFile(envFilePath, ef.Bytes(), 0644); err != nil {
		return err
	}
	return nil
}

// composeEnvironment formats the environment into a slice of types.Environment.
func composeEnvironment(env types.Environment) types.Environment {
	var composed types.Environment
	var defaultEnv = map[string]string{
		"PATH":    "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
		"SHELL":   "/bin/sh",
		"USER":    "root",
		"LOGNAME": "root",
		"HOME":    "/root",
	}

	for dk, dv := range defaultEnv {
		if _, exists := env.Get(dk); !exists {
			composed = append(composed, types.EnvironmentVariable{Name:dk, Value:dv})
		}
	}

	composed = append(composed, env...)
	return composed
}

func main() {
	rp := parseFlags()
	stage1initcommon.InitDebug(debug)

	log, diag, _ = rktlog.NewLogSet("stage1", debug)
	if !debug {
		diag.SetOutput(ioutil.Discard)
	}

	// move code into stage1() helper so deferred fns get run
	os.Exit(stage1(rp))
}
