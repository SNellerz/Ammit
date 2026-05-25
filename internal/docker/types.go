package docker

// Inspection models the subset of GET /containers/{id}/json we care about.
// Fields we don't model are simply ignored by the JSON decoder.
type Inspection struct {
	ID      string   `json:"Id"`
	Name    string   `json:"Name"`
	Created string   `json:"Created"`
	Path    string   `json:"Path"`
	Args    []string `json:"Args"`

	State struct {
		Status     string `json:"Status"`
		Running    bool   `json:"Running"`
		Paused     bool   `json:"Paused"`
		Restarting bool   `json:"Restarting"`
		OOMKilled  bool   `json:"OOMKilled"`
		Dead       bool   `json:"Dead"`
		Pid        int    `json:"Pid"`
		ExitCode   int    `json:"ExitCode"`
		Error      string `json:"Error"`
		StartedAt  string `json:"StartedAt"`
		Health     *struct {
			Status        string `json:"Status"`
			FailingStreak int    `json:"FailingStreak"`
		} `json:"Health"`
	} `json:"State"`

	Image  string `json:"Image"`
	Config struct {
		Hostname     string              `json:"Hostname"`
		User         string              `json:"User"`
		Env          []string            `json:"Env"`
		Cmd          []string            `json:"Cmd"`
		Image        string              `json:"Image"`
		Entrypoint   []string            `json:"Entrypoint"`
		WorkingDir   string              `json:"WorkingDir"`
		Labels       map[string]string   `json:"Labels"`
		ExposedPorts map[string]struct{} `json:"ExposedPorts"`
		Healthcheck  *struct {
			Test []string `json:"Test"`
		} `json:"Healthcheck"`
	} `json:"Config"`

	HostConfig struct {
		Privileged     bool     `json:"Privileged"`
		NetworkMode    string   `json:"NetworkMode"`
		PidMode        string   `json:"PidMode"`
		IpcMode        string   `json:"IpcMode"`
		CapAdd         []string `json:"CapAdd"`
		CapDrop        []string `json:"CapDrop"`
		ReadonlyRootfs bool     `json:"ReadonlyRootfs"`
		SecurityOpt    []string `json:"SecurityOpt"`
		Memory         int64    `json:"Memory"`
		NanoCpus       int64    `json:"NanoCpus"`
		RestartPolicy  struct {
			Name string `json:"Name"`
		} `json:"RestartPolicy"`
		Binds        []string `json:"Binds"`
		PortBindings map[string][]struct {
			HostIP   string `json:"HostIp"`
			HostPort string `json:"HostPort"`
		} `json:"PortBindings"`
	} `json:"HostConfig"`

	Mounts []struct {
		Type        string `json:"Type"`
		Source      string `json:"Source"`
		Destination string `json:"Destination"`
		Mode        string `json:"Mode"`
		RW          bool   `json:"RW"`
	} `json:"Mounts"`

	NetworkSettings struct {
		IPAddress string `json:"IPAddress"`
		Networks  map[string]struct {
			IPAddress   string `json:"IPAddress"`
			Gateway     string `json:"Gateway"`
			MacAddress  string `json:"MacAddress"`
			NetworkID   string `json:"NetworkID"`
			IPPrefixLen int    `json:"IPPrefixLen"`
		} `json:"Networks"`
	} `json:"NetworkSettings"`
}

// StatsSample models the single-shot stats payload. cgroup v1 and v2 daemons
// both populate these fields.
type StatsSample struct {
	Read string `json:"read"`

	MemoryStats struct {
		Usage uint64 `json:"usage"`
		Limit uint64 `json:"limit"`
		Stats struct {
			// cgroup v1
			Cache uint64 `json:"cache"`
			Rss   uint64 `json:"rss"`
			// cgroup v2
			InactiveFile uint64 `json:"inactive_file"`
			AnonV2       uint64 `json:"anon"`
			FileV2       uint64 `json:"file"`
		} `json:"stats"`
	} `json:"memory_stats"`

	CPUStats    cpuStats `json:"cpu_stats"`
	PreCPUStats cpuStats `json:"precpu_stats"`

	BlkioStats struct {
		IoServiceBytesRecursive []blkioEntry `json:"io_service_bytes_recursive"`
	} `json:"blkio_stats"`

	Networks map[string]struct {
		RxBytes   uint64 `json:"rx_bytes"`
		TxBytes   uint64 `json:"tx_bytes"`
		RxPackets uint64 `json:"rx_packets"`
		TxPackets uint64 `json:"tx_packets"`
		RxErrors  uint64 `json:"rx_errors"`
		TxErrors  uint64 `json:"tx_errors"`
		RxDropped uint64 `json:"rx_dropped"`
		TxDropped uint64 `json:"tx_dropped"`
	} `json:"networks"`
}

type cpuStats struct {
	CPUUsage struct {
		TotalUsage  uint64   `json:"total_usage"`
		PercpuUsage []uint64 `json:"percpu_usage"`
	} `json:"cpu_usage"`
	SystemCPUUsage uint64 `json:"system_cpu_usage"`
	OnlineCPUs     uint32 `json:"online_cpus"`
}

type blkioEntry struct {
	Major uint64 `json:"major"`
	Minor uint64 `json:"minor"`
	Op    string `json:"op"`
	Value uint64 `json:"value"`
}
