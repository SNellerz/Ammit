// Command ammit is an extremely lightweight container debugging sidecar.
//
// It attaches (logically, via the Docker API) to a target container and
// reports its configuration, networks, memory and IO usage, offers tuning
// recommendations, and runs security scans - all from a single static binary
// that runs on any distribution.
package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"sort"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/SvenNellerz/ammit/internal/docker"
	"github.com/SvenNellerz/ammit/internal/inspect"
	"github.com/SvenNellerz/ammit/internal/render"
	"github.com/SvenNellerz/ammit/internal/scan"
)

const version = "0.1.0"
const appName = "ammit"

const (
	errInvalidFlags    = "AMMIT_E_INVALID_FLAGS"
	errUnknownCommand  = "AMMIT_E_UNKNOWN_COMMAND"
	errTargetRequired  = "AMMIT_E_TARGET_REQUIRED"
	errTargetNotFound  = "AMMIT_E_TARGET_NOT_FOUND"
	errTargetAmbiguous = "AMMIT_E_TARGET_AMBIGUOUS"
	errDockerHost      = "AMMIT_E_DOCKER_HOST"
	errDockerConnect   = "AMMIT_E_DOCKER_CONNECT"
	errDockerAPI       = "AMMIT_E_DOCKER_API"
	errInternal        = "AMMIT_E_INTERNAL"
)

var cliJSON bool

type appError struct {
	Code    string
	Message string
	Cause   error
}

func (e *appError) Error() string {
	if e == nil {
		return ""
	}
	if e.Message != "" {
		return e.Message
	}
	if e.Cause != nil {
		return e.Cause.Error()
	}
	return "unknown error"
}

func (e *appError) Unwrap() error {
	if e == nil {
		return nil
	}
	return e.Cause
}

type jsonEnvelope struct {
	Tool    string      `json:"tool"`
	Version string      `json:"version"`
	OK      bool        `json:"ok"`
	Command string      `json:"command,omitempty"`
	Target  string      `json:"target,omitempty"`
	Output  string      `json:"output,omitempty"`
	Data    any         `json:"data,omitempty"`
	Error   *jsonErrObj `json:"error,omitempty"`
}

type jsonErrObj struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}

func main() {
	if err := run(os.Args[1:]); err != nil {
		if cliJSON {
			_ = emitJSON(jsonEnvelope{
				Tool:    appName,
				Version: version,
				OK:      false,
				Error: &jsonErrObj{
					Code:    errorCode(err),
					Message: err.Error(),
				},
			}, os.Stderr)
		} else {
			fmt.Fprintln(os.Stderr, render.Red("error: ")+"["+errorCode(err)+"] "+err.Error())
		}
		os.Exit(exitCode(err))
	}
}

func usageText() string {
	return appName + ` ` + version + ` - devourer of unworthy containers

USAGE:
    ammit [global flags] <command> [target]

COMMANDS:
    ls                 List containers (the targets you can debug)
    config <target>    Show configuration: image, env, mounts, caps, limits
    net <target>       Show network settings and live traffic counters
    stats <target>     Show live memory, CPU and IO usage with bars
    recommend <target> Suggest configuration and tuning improvements
    scan <target>      Security scan: config checks (+ CVEs if trivy present)
    all <target>       Run config, net, stats, recommend and scan together

GLOBAL FLAGS:
    -H, --host string   Docker host (default: $DOCKER_HOST or unix socket)
        --no-color      Disable coloured output
        --json          Emit machine-readable JSON output
        --cve           In scan/all, also run CVE scan via trivy
		--watch         Stream live stats (stats command only)
		--watch-interval duration
						Refresh interval for --watch (default: 2s)
    -h, --help          Show this help
    -v, --version       Show version

EXAMPLES:
    ammit ls
    ammit all my-api
    ammit stats 3f9a
	ammit --watch stats 3f9a
	ammit --watch --watch-interval 1s stats 3f9a
    ammit scan --cve nginx-prod
    ammit --json scan api

The target is a container name or (short) ID.
`
}

func usage() {
	fmt.Print(usageText())
}

func run(args []string) error {
	cliJSON = wantsJSON(args)

	fs := flag.NewFlagSet(appName, flag.ContinueOnError)
	if cliJSON {
		fs.SetOutput(io.Discard)
	} else {
		fs.SetOutput(os.Stderr)
	}
	fs.Usage = usage

	var host string
	var noColor, showVer, withCVE, jsonOut, watch bool
	watchInterval := 2 * time.Second
	fs.StringVar(&host, "host", "", "Docker host")
	fs.StringVar(&host, "H", "", "Docker host (shorthand)")
	fs.BoolVar(&noColor, "no-color", false, "disable colour")
	fs.BoolVar(&jsonOut, "json", false, "emit json output")
	fs.BoolVar(&showVer, "version", false, "show version")
	fs.BoolVar(&showVer, "v", false, "show version")
	fs.BoolVar(&withCVE, "cve", false, "run CVE scan via trivy")
	fs.BoolVar(&watch, "watch", false, "stream live stats (stats command only)")
	fs.DurationVar(&watchInterval, "watch-interval", watchInterval, "refresh interval for --watch")

	if err := fs.Parse(args); err != nil {
		return &appError{Code: errInvalidFlags, Message: err.Error(), Cause: err}
	}
	cliJSON = jsonOut
	if jsonOut {
		render.SetColor(false)
	}
	if noColor {
		render.SetColor(false)
	}
	if showVer {
		if jsonOut {
			return emitJSON(jsonEnvelope{
				Tool:    appName,
				Version: version,
				OK:      true,
				Command: "version",
				Output:  appName + " " + version + "\n",
				Data: map[string]any{
					"name":    appName,
					"version": version,
				},
			}, os.Stdout)
		}
		fmt.Println(appName + " " + version)
		return nil
	}

	rest := fs.Args()
	if len(rest) == 0 {
		if jsonOut {
			return emitJSON(jsonEnvelope{
				Tool:    appName,
				Version: version,
				OK:      true,
				Command: "help",
				Output:  usageText(),
				Data: map[string]any{
					"usage": usageText(),
				},
			}, os.Stdout)
		}
		usage()
		return nil
	}
	cmd := rest[0]
	target := ""
	if len(rest) > 1 {
		target = rest[1]
	}
	if watch && cmd != "stats" {
		return &appError{Code: errInvalidFlags, Message: "--watch is only supported with the stats command"}
	}
	if watch && jsonOut {
		return &appError{Code: errInvalidFlags, Message: "--watch cannot be combined with --json"}
	}
	if watch && watchInterval <= 0 {
		return &appError{Code: errInvalidFlags, Message: "--watch-interval must be greater than 0"}
	}

	cli, err := docker.New(host)
	if err != nil {
		return &appError{Code: errDockerHost, Message: err.Error(), Cause: err}
	}
	ctx := context.Background()
	if err := cli.Ping(ctx); err != nil {
		return &appError{
			Code:    errDockerConnect,
			Message: fmt.Sprintf("cannot reach Docker daemon: %v\nMount the socket with -v /var/run/docker.sock:/var/run/docker.sock", err),
			Cause:   err,
		}
	}

	var execute func() error
	var buildData func() (any, error)
	switch cmd {
	case "ls":
		execute = func() error { return cmdLs(ctx, cli) }
		buildData = func() (any, error) { return buildLsData(ctx, cli) }
	case "config":
		execute = func() error { return withTarget(ctx, cli, target, cmdConfig) }
		buildData = func() (any, error) {
			ins, err := resolveInspection(ctx, cli, target)
			if err != nil {
				return nil, err
			}
			return buildConfigData(ins), nil
		}
	case "net":
		execute = func() error { return withTarget(ctx, cli, target, cmdNet) }
		buildData = func() (any, error) {
			ins, err := resolveInspection(ctx, cli, target)
			if err != nil {
				return nil, err
			}
			return buildNetData(ctx, cli, ins), nil
		}
	case "stats":
		execute = func() error {
			if watch {
				return withTarget(ctx, cli, target, func(ctx context.Context, cli *docker.Client, ins *docker.Inspection) error {
					return cmdStatsWatch(ctx, cli, ins, watchInterval)
				})
			}
			return withTarget(ctx, cli, target, cmdStats)
		}
		buildData = func() (any, error) {
			ins, err := resolveInspection(ctx, cli, target)
			if err != nil {
				return nil, err
			}
			return buildStatsData(ctx, cli, ins)
		}
	case "recommend":
		execute = func() error { return withTarget(ctx, cli, target, cmdRecommend) }
		buildData = func() (any, error) {
			ins, err := resolveInspection(ctx, cli, target)
			if err != nil {
				return nil, err
			}
			return buildRecommendData(ctx, cli, ins), nil
		}
	case "scan":
		execute = func() error {
			return withTarget(ctx, cli, target, func(ctx context.Context, cli *docker.Client, ins *docker.Inspection) error {
				return cmdScan(ctx, cli, ins, withCVE)
			})
		}
		buildData = func() (any, error) {
			ins, err := resolveInspection(ctx, cli, target)
			if err != nil {
				return nil, err
			}
			return buildScanData(ctx, ins, withCVE), nil
		}
	case "all":
		execute = func() error {
			return withTarget(ctx, cli, target, func(ctx context.Context, cli *docker.Client, ins *docker.Inspection) error {
				if err := cmdConfig(ctx, cli, ins); err != nil {
					return err
				}
				if err := cmdNet(ctx, cli, ins); err != nil {
					return err
				}
				if err := cmdStats(ctx, cli, ins); err != nil {
					return err
				}
				if err := cmdRecommend(ctx, cli, ins); err != nil {
					return err
				}
				return cmdScan(ctx, cli, ins, withCVE)
			})
		}
		buildData = func() (any, error) {
			ins, err := resolveInspection(ctx, cli, target)
			if err != nil {
				return nil, err
			}
			return buildAllData(ctx, cli, ins, withCVE), nil
		}
	case "help":
		execute = func() error {
			usage()
			return nil
		}
		buildData = func() (any, error) {
			return map[string]any{"usage": usageText()}, nil
		}
	default:
		if !jsonOut {
			usage()
		}
		return &appError{Code: errUnknownCommand, Message: fmt.Sprintf("unknown command %q", cmd)}
	}

	if jsonOut {
		out, err := captureStdout(execute)
		if err != nil {
			return err
		}
		var data any
		if buildData != nil {
			data, err = buildData()
			if err != nil {
				return err
			}
		}
		return emitJSON(jsonEnvelope{
			Tool:    appName,
			Version: version,
			OK:      true,
			Command: cmd,
			Target:  target,
			Output:  out,
			Data:    data,
		}, os.Stdout)
	}

	return execute()
}

func captureStdout(fn func() error) (string, error) {
	oldStdout := os.Stdout
	r, w, err := os.Pipe()
	if err != nil {
		return "", &appError{Code: errInternal, Message: "failed to create stdout pipe", Cause: err}
	}
	type readResult struct {
		buf bytes.Buffer
		err error
	}
	resCh := make(chan readResult, 1)
	go func() {
		defer r.Close()
		var rr readResult
		_, rr.err = io.Copy(&rr.buf, r)
		resCh <- rr
	}()

	os.Stdout = w
	runErr := fn()
	_ = w.Close()
	os.Stdout = oldStdout

	rr := <-resCh
	if rr.err != nil {
		if runErr != nil {
			return "", runErr
		}
		return "", &appError{Code: errInternal, Message: "failed to capture command output", Cause: rr.err}
	}
	if runErr != nil {
		return "", runErr
	}
	return rr.buf.String(), nil
}

func emitJSON(v jsonEnvelope, out io.Writer) error {
	enc := json.NewEncoder(out)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(v); err != nil {
		return &appError{Code: errInternal, Message: "failed to encode json output", Cause: err}
	}
	return nil
}

func errorCode(err error) string {
	var ae *appError
	if errors.As(err, &ae) && ae.Code != "" {
		return ae.Code
	}
	return errInternal
}

func exitCode(err error) int {
	switch errorCode(err) {
	case errInvalidFlags:
		return 2
	case errUnknownCommand:
		return 3
	case errTargetRequired:
		return 4
	case errTargetNotFound:
		return 5
	case errTargetAmbiguous:
		return 6
	case errDockerHost:
		return 10
	case errDockerConnect:
		return 11
	case errDockerAPI:
		return 12
	default:
		return 1
	}
}

func wantsJSON(args []string) bool {
	for _, a := range args {
		if a == "--json" {
			return true
		}
	}
	return false
}

// withTarget resolves a target ref, inspects it, and hands the inspection to fn.
func withTarget(ctx context.Context, cli *docker.Client, target string,
	fn func(context.Context, *docker.Client, *docker.Inspection) error) error {
	ins, err := resolveInspection(ctx, cli, target)
	if err != nil {
		return err
	}
	return fn(ctx, cli, ins)
}

func resolveInspection(ctx context.Context, cli *docker.Client, target string) (*docker.Inspection, error) {
	if target == "" {
		return nil, &appError{Code: errTargetRequired, Message: "this command needs a target container (name or ID); try 'ammit ls'"}
	}
	sum, err := cli.Resolve(ctx, target)
	if err != nil {
		if strings.Contains(err.Error(), "ambiguous") {
			return nil, &appError{Code: errTargetAmbiguous, Message: err.Error(), Cause: err}
		}
		return nil, &appError{Code: errTargetNotFound, Message: err.Error(), Cause: err}
	}
	ins, err := cli.Inspect(ctx, sum.ID)
	if err != nil {
		if errors.Is(err, docker.ErrNotFound) {
			return nil, &appError{Code: errTargetNotFound, Message: err.Error(), Cause: err}
		}
		return nil, &appError{Code: errDockerAPI, Message: err.Error(), Cause: err}
	}
	return ins, nil
}

func buildLsData(ctx context.Context, cli *docker.Client) (any, error) {
	list, err := cli.List(ctx, true)
	if err != nil {
		return nil, &appError{Code: errDockerAPI, Message: err.Error(), Cause: err}
	}
	containers := make([]map[string]any, 0, len(list))
	for _, c := range list {
		name := ""
		if len(c.Names) > 0 {
			name = strings.TrimPrefix(c.Names[0], "/")
		}
		id := c.ID
		if len(id) > 12 {
			id = id[:12]
		}
		containers = append(containers, map[string]any{
			"id":      id,
			"name":    name,
			"image":   c.Image,
			"state":   c.State,
			"status":  c.Status,
			"full_id": c.ID,
		})
	}
	return map[string]any{"containers": containers}, nil
}

func buildConfigData(ins *docker.Inspection) map[string]any {
	env := make([]string, 0, len(ins.Config.Env))
	for _, e := range ins.Config.Env {
		env = append(env, maskSecret(e))
	}
	mounts := make([]map[string]any, 0, len(ins.Mounts))
	for _, m := range ins.Mounts {
		mounts = append(mounts, map[string]any{
			"type":        m.Type,
			"source":      m.Source,
			"destination": m.Destination,
			"mode":        m.Mode,
			"rw":          m.RW,
		})
	}
	return map[string]any{
		"id":               ins.ID,
		"name":             strings.TrimPrefix(ins.Name, "/"),
		"image":            ins.Config.Image,
		"image_digest":     ins.Image,
		"created":          ins.Created,
		"state":            ins.State.Status,
		"entrypoint":       ins.Config.Entrypoint,
		"cmd":              ins.Config.Cmd,
		"working_dir":      ins.Config.WorkingDir,
		"user":             ins.Config.User,
		"restart_policy":   ins.HostConfig.RestartPolicy.Name,
		"memory_limit":     ins.HostConfig.Memory,
		"nano_cpus":        ins.HostConfig.NanoCpus,
		"env":              env,
		"mounts":           mounts,
		"cap_add":          ins.HostConfig.CapAdd,
		"cap_drop":         ins.HostConfig.CapDrop,
		"readonly_rootfs":  ins.HostConfig.ReadonlyRootfs,
		"security_options": ins.HostConfig.SecurityOpt,
	}
}

func buildNetData(ctx context.Context, cli *docker.Client, ins *docker.Inspection) map[string]any {
	networks := map[string]map[string]any{}
	for name, n := range ins.NetworkSettings.Networks {
		networks[name] = map[string]any{
			"ip_address":    n.IPAddress,
			"gateway":       n.Gateway,
			"mac_address":   n.MacAddress,
			"network_id":    n.NetworkID,
			"ip_prefix_len": n.IPPrefixLen,
		}
	}
	portBindings := map[string][]map[string]string{}
	for port, binds := range ins.HostConfig.PortBindings {
		rows := make([]map[string]string, 0, len(binds))
		for _, b := range binds {
			rows = append(rows, map[string]string{"host_ip": orAll(b.HostIP), "host_port": b.HostPort})
		}
		portBindings[port] = rows
	}

	data := map[string]any{
		"network_mode":    ins.HostConfig.NetworkMode,
		"networks":        networks,
		"port_bindings":   portBindings,
		"traffic_present": false,
	}
	if st, err := cli.Stats(ctx, ins.ID); err == nil {
		m := inspect.Compute(st)
		data["traffic_present"] = true
		data["traffic"] = map[string]any{
			"rx_bytes":   m.NetRxBytes,
			"tx_bytes":   m.NetTxBytes,
			"rx_errors":  m.NetRxErrors,
			"tx_errors":  m.NetTxErrors,
			"rx_dropped": m.NetRxDropped,
			"tx_dropped": m.NetTxDropped,
		}
	}
	return data
}

func buildStatsData(ctx context.Context, cli *docker.Client, ins *docker.Inspection) (any, error) {
	if !ins.State.Running {
		return map[string]any{
			"running": false,
			"reason":  "container is not running; no live stats available",
		}, nil
	}
	st, err := cli.Stats(ctx, ins.ID)
	if err != nil {
		return nil, &appError{Code: errDockerAPI, Message: err.Error(), Cause: err}
	}
	m := inspect.Compute(st)
	return map[string]any{
		"running":         true,
		"cpu_percent":     m.CPUPercent,
		"online_cpus":     m.OnlineCPUs,
		"mem_usage":       m.MemUsage,
		"mem_limit":       m.MemLimit,
		"mem_percent":     m.MemPercent,
		"blk_read_bytes":  m.BlkReadBytes,
		"blk_write_bytes": m.BlkWriteBytes,
		"net_rx_bytes":    m.NetRxBytes,
		"net_tx_bytes":    m.NetTxBytes,
		"net_rx_errors":   m.NetRxErrors,
		"net_tx_errors":   m.NetTxErrors,
		"net_rx_dropped":  m.NetRxDropped,
		"net_tx_dropped":  m.NetTxDropped,
	}, nil
}

func buildRecommendData(ctx context.Context, cli *docker.Client, ins *docker.Inspection) map[string]any {
	var m inspect.Metrics
	statsPresent := false
	if ins.State.Running {
		if st, err := cli.Stats(ctx, ins.ID); err == nil {
			m = inspect.Compute(st)
			statsPresent = true
		}
	}
	recs := inspect.Recommend(ins, m)
	rows := make([]map[string]string, 0, len(recs))
	for _, r := range recs {
		rows = append(rows, map[string]string{
			"severity": r.Severity,
			"title":    r.Title,
			"detail":   r.Detail,
		})
	}
	return map[string]any{
		"stats_present":   statsPresent,
		"recommendations": rows,
	}
}

func buildScanData(ctx context.Context, ins *docker.Inspection, withCVE bool) map[string]any {
	configFindings := scan.Config(ins)
	configRows := make([]map[string]string, 0, len(configFindings))
	for _, f := range configFindings {
		configRows = append(configRows, map[string]string{
			"severity": f.Severity,
			"check":    f.Check,
			"detail":   f.Detail,
		})
	}
	data := map[string]any{
		"config_findings": configRows,
		"config_summary":  scan.Summarise(configFindings),
		"cve_enabled":     withCVE,
	}
	if !withCVE {
		return data
	}
	if !scan.TrivyAvailable() {
		data["cve_status"] = "trivy_not_found"
		return data
	}
	cves, err := scan.CVEs(ctx, ins.Config.Image)
	if err != nil {
		data["cve_status"] = "scan_failed"
		data["cve_error"] = err.Error()
		return data
	}
	cveRows := make([]map[string]string, 0, len(cves))
	for _, f := range cves {
		cveRows = append(cveRows, map[string]string{
			"severity": f.Severity,
			"check":    f.Check,
			"detail":   f.Detail,
		})
	}
	data["cve_status"] = "ok"
	data["cve_findings"] = cveRows
	data["cve_summary"] = scan.Summarise(cves)
	return data
}

func buildAllData(ctx context.Context, cli *docker.Client, ins *docker.Inspection, withCVE bool) map[string]any {
	statsData, statsErr := buildStatsData(ctx, cli, ins)
	all := map[string]any{
		"config":      buildConfigData(ins),
		"net":         buildNetData(ctx, cli, ins),
		"recommend":   buildRecommendData(ctx, cli, ins),
		"scan":        buildScanData(ctx, ins, withCVE),
		"stats_error": "",
	}
	if statsErr != nil {
		all["stats_error"] = statsErr.Error()
	} else {
		all["stats"] = statsData
	}
	return all
}

func cmdLs(ctx context.Context, cli *docker.Client) error {
	list, err := cli.List(ctx, true)
	if err != nil {
		return &appError{Code: errDockerAPI, Message: err.Error(), Cause: err}
	}
	if len(list) == 0 {
		fmt.Println("No containers found.")
		return nil
	}
	w := tabwriter.NewWriter(os.Stdout, 0, 2, 2, ' ', 0)
	fmt.Fprintln(w, render.Bold("CONTAINER ID\tNAME\tIMAGE\tSTATE\tSTATUS"))
	for _, c := range list {
		name := ""
		if len(c.Names) > 0 {
			name = strings.TrimPrefix(c.Names[0], "/")
		}
		state := c.State
		if state == "running" {
			state = render.Green(state)
		} else {
			state = render.Dim(state)
		}
		id := c.ID
		if len(id) > 12 {
			id = id[:12]
		}
		fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\n", id, name, c.Image, state, c.Status)
	}
	return w.Flush()
}

func cmdConfig(ctx context.Context, cli *docker.Client, ins *docker.Inspection) error {
	render.Section("Configuration: " + strings.TrimPrefix(ins.Name, "/"))
	render.KV("Image", ins.Config.Image)
	render.KV("Image digest", short(ins.Image, 24))
	render.KV("Created", ins.Created)
	render.KV("State", stateStr(ins))
	render.KV("Entrypoint", joinOr(ins.Config.Entrypoint, "(image default)"))
	render.KV("Cmd", joinOr(ins.Config.Cmd, "(image default)"))
	render.KV("Working dir", orDash(ins.Config.WorkingDir))
	render.KV("User", orDash(ins.Config.User))
	render.KV("Restart policy", orDash(ins.HostConfig.RestartPolicy.Name))
	if ins.HostConfig.Memory > 0 {
		render.KV("Memory limit", render.Bytes(uint64(ins.HostConfig.Memory)))
	} else {
		render.KV("Memory limit", render.Dim("unlimited"))
	}
	if ins.HostConfig.NanoCpus > 0 {
		render.KV("CPU limit", fmt.Sprintf("%.2f cpus", float64(ins.HostConfig.NanoCpus)/1e9))
	} else {
		render.KV("CPU limit", render.Dim("unlimited"))
	}
	render.EndSection()

	if len(ins.Config.Env) > 0 {
		render.Section("Environment")
		for _, e := range ins.Config.Env {
			render.Line(maskSecret(e))
		}
		render.EndSection()
	}

	if len(ins.Mounts) > 0 {
		render.Section("Mounts")
		for _, m := range ins.Mounts {
			rw := "ro"
			if m.RW {
				rw = "rw"
			}
			render.Line(fmt.Sprintf("%s -> %s (%s, %s)", orDash(m.Source), m.Destination, m.Type, rw))
		}
		render.EndSection()
	}

	if len(ins.HostConfig.CapAdd) > 0 || len(ins.HostConfig.CapDrop) > 0 {
		render.Section("Capabilities")
		if len(ins.HostConfig.CapAdd) > 0 {
			render.KV("Added", strings.Join(ins.HostConfig.CapAdd, ", "))
		}
		if len(ins.HostConfig.CapDrop) > 0 {
			render.KV("Dropped", strings.Join(ins.HostConfig.CapDrop, ", "))
		}
		render.EndSection()
	}
	return nil
}

func cmdNet(ctx context.Context, cli *docker.Client, ins *docker.Inspection) error {
	render.Section("Networks")
	render.KV("Network mode", orDash(ins.HostConfig.NetworkMode))
	if len(ins.NetworkSettings.Networks) == 0 {
		render.Line(render.Dim("no attached networks"))
	}
	networkNames := make([]string, 0, len(ins.NetworkSettings.Networks))
	for networkName := range ins.NetworkSettings.Networks {
		networkNames = append(networkNames, networkName)
	}
	sort.Strings(networkNames)
	for _, networkName := range networkNames {
		n := ins.NetworkSettings.Networks[networkName]
		render.KV(networkName, fmt.Sprintf("ip=%s/%d gw=%s mac=%s", orDash(n.IPAddress), n.IPPrefixLen, orDash(n.Gateway), orDash(n.MacAddress)))
	}
	if len(ins.HostConfig.PortBindings) > 0 {
		render.Line(render.Dim("port bindings:"))
		ports := make([]string, 0, len(ins.HostConfig.PortBindings))
		for port := range ins.HostConfig.PortBindings {
			ports = append(ports, port)
		}
		sort.Strings(ports)
		for _, port := range ports {
			binds := ins.HostConfig.PortBindings[port]
			sort.SliceStable(binds, func(i, j int) bool {
				if binds[i].HostIP == binds[j].HostIP {
					return binds[i].HostPort < binds[j].HostPort
				}
				return binds[i].HostIP < binds[j].HostIP
			})
			for _, b := range binds {
				render.Line(fmt.Sprintf("  %s -> %s:%s", port, orAll(b.HostIP), b.HostPort))
			}
		}
	}
	render.EndSection()

	st, err := cli.Stats(ctx, ins.ID)
	if err == nil {
		m := inspect.Compute(st)
		render.Section("Live network traffic")
		render.KV("Received", fmt.Sprintf("%s  (%d errors, %d dropped)", render.Bytes(m.NetRxBytes), m.NetRxErrors, m.NetRxDropped))
		render.KV("Transmitted", fmt.Sprintf("%s  (%d errors, %d dropped)", render.Bytes(m.NetTxBytes), m.NetTxErrors, m.NetTxDropped))
		render.EndSection()
	}
	return nil
}

func cmdStats(ctx context.Context, cli *docker.Client, ins *docker.Inspection) error {
	if !ins.State.Running {
		render.Section("Live usage")
		render.Line(render.Dim("container is not running; no live stats available"))
		render.EndSection()
		return nil
	}
	st, err := cli.Stats(ctx, ins.ID)
	if err != nil {
		return &appError{Code: errDockerAPI, Message: err.Error(), Cause: err}
	}
	m := inspect.Compute(st)

	render.Section("Live usage: " + strings.TrimPrefix(ins.Name, "/"))
	render.KV("CPU", render.Bar(m.CPUPercent/100.0, 24)+fmt.Sprintf("  (%d cpus)", m.OnlineCPUs))
	if m.MemLimit > 0 {
		render.KV("Memory", render.Bar(m.MemPercent/100.0, 24)+fmt.Sprintf("  %s / %s", render.Bytes(m.MemUsage), render.Bytes(m.MemLimit)))
	} else {
		render.KV("Memory", fmt.Sprintf("%s (no limit)", render.Bytes(m.MemUsage)))
	}
	render.KV("Block I/O read", render.Bytes(m.BlkReadBytes))
	render.KV("Block I/O write", render.Bytes(m.BlkWriteBytes))
	render.KV("Net RX / TX", fmt.Sprintf("%s / %s", render.Bytes(m.NetRxBytes), render.Bytes(m.NetTxBytes)))
	render.EndSection()
	return nil
}

func cmdStatsWatch(ctx context.Context, cli *docker.Client, ins *docker.Inspection, interval time.Duration) error {
	if interval <= 0 {
		return &appError{Code: errInvalidFlags, Message: "--watch-interval must be greater than 0"}
	}
	if err := cmdStats(ctx, cli, ins); err != nil {
		return err
	}
	if !ins.State.Running {
		return nil
	}

	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return nil
		case ts := <-ticker.C:
			fmt.Println(render.Dim("updated " + ts.Format(time.RFC3339) + " (press Ctrl+C to stop)"))
			if err := cmdStats(ctx, cli, ins); err != nil {
				return err
			}
		}
	}
}

func cmdRecommend(ctx context.Context, cli *docker.Client, ins *docker.Inspection) error {
	var m inspect.Metrics
	if ins.State.Running {
		if st, err := cli.Stats(ctx, ins.ID); err == nil {
			m = inspect.Compute(st)
		}
	}
	recs := inspect.Recommend(ins, m)
	render.Section("Recommendations")
	order := map[string]int{"HIGH": 0, "MEDIUM": 1, "LOW": 2, "INFO": 3}
	sort.SliceStable(recs, func(i, j int) bool { return order[recs[i].Severity] < order[recs[j].Severity] })
	for _, r := range recs {
		render.Line(fmt.Sprintf("[%s] %s", render.Severity(r.Severity), render.Bold(r.Title)))
		render.Line("    " + render.Dim(r.Detail))
	}
	render.EndSection()
	return nil
}

func cmdScan(ctx context.Context, cli *docker.Client, ins *docker.Inspection, withCVE bool) error {
	findings := scan.Config(ins)
	render.Section("Security: configuration checks")
	order := map[string]int{"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "PASS": 4}
	sort.SliceStable(findings, func(i, j int) bool {
		return order[strings.ToUpper(findings[i].Severity)] < order[strings.ToUpper(findings[j].Severity)]
	})
	for _, f := range findings {
		render.Line(fmt.Sprintf("[%-8s] %s", render.Severity(f.Severity), render.Bold(f.Check)))
		if strings.ToUpper(f.Severity) != "PASS" {
			render.Line("    " + render.Dim(f.Detail))
		}
	}
	c := scan.Summarise(findings)
	render.Line("")
	render.Line(fmt.Sprintf("Verdict tally: %d devoured, %d high, %d medium, %d low",
		c["CRITICAL"], c["HIGH"], c["MEDIUM"], c["LOW"]))
	render.EndSection()

	if withCVE {
		render.Section("Security: image CVEs (trivy)")
		if !scan.TrivyAvailable() {
			render.Line(render.Yellow("trivy not found on PATH - skipping CVE scan."))
			render.Line(render.Dim("Install trivy to enable, or omit --cve."))
			render.EndSection()
			return nil
		}
		render.Line(render.Dim("scanning " + ins.Config.Image + " (first run downloads the vuln DB)..."))
		cves, err := scan.CVEs(ctx, ins.Config.Image)
		if err != nil {
			render.Line(render.Red("CVE scan failed: ") + err.Error())
			render.EndSection()
			return nil
		}
		if len(cves) == 0 {
			render.Line(render.Green("No known vulnerabilities found."))
		}
		cc := scan.Summarise(cves)
		render.Line(fmt.Sprintf("Vulnerability tally: %d devoured, %d high, %d medium, %d low",
			cc["CRITICAL"], cc["HIGH"], cc["MEDIUM"], cc["LOW"]))
		shown := 0
		for _, f := range cves {
			s := strings.ToUpper(f.Severity)
			if s == "CRITICAL" || s == "HIGH" {
				render.Line(fmt.Sprintf("[%-8s] %s - %s", render.Severity(f.Severity), f.Check, render.Dim(f.Detail)))
				shown++
			}
			if shown >= 25 {
				render.Line(render.Dim("... (truncated; run trivy directly for the full list)"))
				break
			}
		}
		render.EndSection()
	}
	return nil
}

func stateStr(ins *docker.Inspection) string {
	s := ins.State.Status
	switch {
	case ins.State.Running:
		return render.Green(s)
	case ins.State.OOMKilled:
		return render.Red(s + " (OOM-killed)")
	default:
		return render.Dim(s)
	}
}

func joinOr(parts []string, fallback string) string {
	if len(parts) == 0 {
		return render.Dim(fallback)
	}
	return strings.Join(parts, " ")
}

func orDash(s string) string {
	if s == "" {
		return render.Dim("-")
	}
	return s
}

func orAll(ip string) string {
	if ip == "" {
		return "0.0.0.0"
	}
	return ip
}

func short(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}

func maskSecret(env string) string {
	i := strings.Index(env, "=")
	if i < 0 {
		return env
	}
	key, val := env[:i], env[i+1:]
	if shouldMaskEnv(key, val) {
		return key + "=" + render.Dim("******(masked)")
	}
	return env
}

func shouldMaskEnv(key, val string) bool {
	if val == "" {
		return false
	}
	up := strings.ToUpper(strings.TrimSpace(key))
	if up == "" {
		return false
	}

	allow := csvSet(envOr("AMMIT_ENV_UNMASK", "CDEBUG_ENV_UNMASK"))
	if allow[up] {
		return false
	}

	if strings.EqualFold(strings.TrimSpace(envOr("AMMIT_MASK_ENV", "CDEBUG_MASK_ENV")), "strict") {
		return true
	}

	deny := csvSet(envOr("AMMIT_ENV_MASK", "CDEBUG_ENV_MASK"))
	if deny[up] {
		return true
	}

	for _, hint := range []string{"SECRET", "PASSWORD", "TOKEN", "KEY", "CREDENTIAL", "PASSWD", "PWD", "PRIVATE", "AUTH", "SESSION", "COOKIE"} {
		if strings.Contains(up, hint) {
			return true
		}
	}
	return false
}

func csvSet(raw string) map[string]bool {
	set := map[string]bool{}
	for _, item := range strings.Split(raw, ",") {
		item = strings.ToUpper(strings.TrimSpace(item))
		if item != "" {
			set[item] = true
		}
	}
	return set
}

func envOr(primary, legacy string) string {
	if v := strings.TrimSpace(os.Getenv(primary)); v != "" {
		return v
	}
	return os.Getenv(legacy)
}
