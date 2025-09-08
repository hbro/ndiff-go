package main

import (
	"encoding/xml"
	"flag"
	"fmt"
	"io/ioutil"
	"os"
	"sort"
	"strings"
)

const (
	// Exit codes matching original ndiff
	ExitEqual     = 0
	ExitDifferent = 1
	ExitError     = 2
)

// NmapRun represents the root element of an Nmap XML file
type NmapRun struct {
	XMLName xml.Name `xml:"nmaprun"`
	Scanner string   `xml:"scanner,attr"`
	Args    string   `xml:"args,attr"`
	Start   string   `xml:"start,attr"`
	Version string   `xml:"version,attr"`
	Hosts   []Host   `xml:"host"`
}

// Host represents a scanned host
type Host struct {
	Status    Status     `xml:"status"`
	Addresses []Address  `xml:"address"`
	Hostnames []Hostname `xml:"hostnames>hostname"`
	Ports     Ports      `xml:"ports"`
	OS        OSInfo     `xml:"os"`
}

// Status represents host status (up/down)
type Status struct {
	State  string `xml:"state,attr"`
	Reason string `xml:"reason,attr"`
}

// Address represents host IP or MAC address
type Address struct {
	Addr     string `xml:"addr,attr"`
	AddrType string `xml:"addrtype,attr"`
}

// Hostname represents a hostname
type Hostname struct {
	Name string `xml:"name,attr"`
	Type string `xml:"type,attr"`
}

// Ports contains port information
type Ports struct {
	ExtraPorts ExtraPorts `xml:"extraports"`
	Ports      []Port     `xml:"port"`
}

// ExtraPorts represents ports not shown
type ExtraPorts struct {
	State string `xml:"state,attr"`
	Count string `xml:"count,attr"`
}

// Port represents a single port
type Port struct {
	Protocol string `xml:"protocol,attr"`
	PortID   string `xml:"portid,attr"`
	State    State  `xml:"state"`
	Service  Service `xml:"service"`
	Scripts  []Script `xml:"script"`
}

// State represents port state
type State struct {
	State  string `xml:"state,attr"`
	Reason string `xml:"reason,attr"`
}

// Service represents service detection info
type Service struct {
	Name    string `xml:"name,attr"`
	Product string `xml:"product,attr"`
	Version string `xml:"version,attr"`
	Method  string `xml:"method,attr"`
}

// Script represents NSE script output
type Script struct {
	ID     string `xml:"id,attr"`
	Output string `xml:"output,attr"`
}

// OSInfo contains OS detection information
type OSInfo struct {
	OSMatches []OSMatch `xml:"osmatch"`
}

// OSMatch represents an OS match
type OSMatch struct {
	Name     string `xml:"name,attr"`
	Accuracy string `xml:"accuracy,attr"`
}

// Diff represents differences between two scans
type Diff struct {
	ScanAInfo    string
	ScanBInfo    string
	HostChanges  []HostDiff
	NewHosts     []*Host
	RemovedHosts []*Host
}

// HostDiff represents differences for a single host
type HostDiff struct {
	Address      string
	HostA        *Host
	HostB        *Host
	StatusChange *StatusChange
	PortChanges  []PortChange
	OSChanges    []string
}

// StatusChange represents host status change
type StatusChange struct {
	OldStatus string
	NewStatus string
}

// PortChange represents port state change
type PortChange struct {
	Port       string
	Protocol   string
	OldState   string
	NewState   string
	OldService string
	NewService string
}

var (
	verbose bool
	xmlOut  bool
	textOut bool
	// Version is set at build time using ldflags
	version = "1.0-dev"
)

// Load and parse an Nmap XML file
func loadScan(filename string) (*NmapRun, error) {
	data, err := ioutil.ReadFile(filename)
	if err != nil {
		return nil, err
	}

	var scan NmapRun
	err = xml.Unmarshal(data, &scan)
	if err != nil {
		return nil, err
	}

	return &scan, nil
}

// Create a map of hosts indexed by IP address
func createHostMap(scan *NmapRun) map[string]*Host {
	hostMap := make(map[string]*Host)

	for i := range scan.Hosts {
		host := &scan.Hosts[i]
		for _, addr := range host.Addresses {
			if addr.AddrType == "ipv4" || addr.AddrType == "ipv6" {
				hostMap[addr.Addr] = host
				break
			}
		}
	}

	return hostMap
}

// Compare two scans and generate diff
func compareScan(scanA, scanB *NmapRun) *Diff {
	diff := &Diff{
		ScanAInfo: fmt.Sprintf("Nmap %s at %s", scanA.Version, formatTimestamp(scanA.Start)),
		ScanBInfo: fmt.Sprintf("Nmap %s at %s", scanB.Version, formatTimestamp(scanB.Start)),
	}

	hostsA := createHostMap(scanA)
	hostsB := createHostMap(scanB)

	// Find removed and changed hosts
	for addr, hostA := range hostsA {
		hostB, exists := hostsB[addr]
		if !exists {
			diff.RemovedHosts = append(diff.RemovedHosts, hostA)
		} else {
			changes := compareHosts(hostA, hostB)
			if changes != nil {
				diff.HostChanges = append(diff.HostChanges, *changes)
			}
		}
	}

	// Find new hosts
	for addr, hostB := range hostsB {
		if _, exists := hostsA[addr]; !exists {
			diff.NewHosts = append(diff.NewHosts, hostB)
		}
	}

	return diff
}

// Compare two hosts and find differences
func compareHosts(hostA, hostB *Host) *HostDiff {
	var changes HostDiff
	changes.HostA = hostA
	changes.HostB = hostB
	changes.Address = getIPAddress(hostA)
	hasChanges := false

	// Check status change
	if hostA.Status.State != hostB.Status.State {
		changes.StatusChange = &StatusChange{
			OldStatus: hostA.Status.State,
			NewStatus: hostB.Status.State,
		}
		hasChanges = true
	}

	// Compare ports
	portsA := createPortMap(hostA.Ports.Ports)
	portsB := createPortMap(hostB.Ports.Ports)

	for key, portA := range portsA {
		portB, exists := portsB[key]
		if !exists {
			// Port removed
			changes.PortChanges = append(changes.PortChanges, PortChange{
				Port:       portA.PortID,
				Protocol:   portA.Protocol,
				OldState:   portA.State.State,
				NewState:   "removed",
				OldService: formatService(&portA.Service),
			})
			hasChanges = true
		} else if portA.State.State != portB.State.State ||
			formatService(&portA.Service) != formatService(&portB.Service) {
			// Port changed
			changes.PortChanges = append(changes.PortChanges, PortChange{
				Port:       portA.PortID,
				Protocol:   portA.Protocol,
				OldState:   portA.State.State,
				NewState:   portB.State.State,
				OldService: formatService(&portA.Service),
				NewService: formatService(&portB.Service),
			})
			hasChanges = true
		}
	}

	// Find new ports
	for key, portB := range portsB {
		if _, exists := portsA[key]; !exists {
			changes.PortChanges = append(changes.PortChanges, PortChange{
				Port:       portB.PortID,
				Protocol:   portB.Protocol,
				OldState:   "new",
				NewState:   portB.State.State,
				NewService: formatService(&portB.Service),
			})
			hasChanges = true
		}
	}

	// Compare OS detection
	osChanges := compareOS(&hostA.OS, &hostB.OS)
	if len(osChanges) > 0 {
		changes.OSChanges = osChanges
		hasChanges = true
	}

	if hasChanges {
		return &changes
	}
	return nil
}

// Create a map of ports indexed by "protocol:port"
func createPortMap(ports []Port) map[string]Port {
	portMap := make(map[string]Port)
	for _, port := range ports {
		key := fmt.Sprintf("%s:%s", port.Protocol, port.PortID)
		portMap[key] = port
	}
	return portMap
}

// Format service information as string
func formatService(service *Service) string {
	if service.Name == "" {
		return ""
	}
	parts := []string{service.Name}
	if service.Product != "" {
		parts = append(parts, service.Product)
	}
	if service.Version != "" {
		parts = append(parts, service.Version)
	}
	return strings.Join(parts, " ")
}

// Compare OS detection results
func compareOS(osA, osB *OSInfo) []string {
	var changes []string

	osMapA := make(map[string]bool)
	osMapB := make(map[string]bool)

	for _, match := range osA.OSMatches {
		osMapA[match.Name] = true
	}
	for _, match := range osB.OSMatches {
		osMapB[match.Name] = true
	}

	// Find removed OS matches
	for name := range osMapA {
		if !osMapB[name] {
			changes = append(changes, fmt.Sprintf("-%s", name))
		}
	}

	// Find new OS matches
	for name := range osMapB {
		if !osMapA[name] {
			changes = append(changes, fmt.Sprintf("+%s", name))
		}
	}

	return changes
}

// Format Unix timestamp to readable date
func formatTimestamp(timestamp string) string {
	// Try to parse the timestamp
	if timestamp == "" {
		return "unknown"
	}
	return timestamp
}

// printTextDiff prints diff in text format
func printTextDiff(diff *Diff) {
	// Print scan info changes
	if diff.ScanAInfo != diff.ScanBInfo {
		fmt.Printf("-%s\n", diff.ScanAInfo)
		fmt.Printf("+%s\n", diff.ScanBInfo)
		fmt.Println()
	}

	// Print removed hosts
	for _, host := range diff.RemovedHosts {
		fmt.Printf("-%s: Host is down\n", formatHostDisplayName(host))
	}

	// Print new hosts
	for _, host := range diff.NewHosts {
		fmt.Printf("+%s: Host is up\n", formatHostDisplayName(host))
	}

	// Print host changes
	for _, hostDiff := range diff.HostChanges {
		fmt.Printf("\n%s:\n", formatHostDisplayName(hostDiff.HostB))

		if hostDiff.StatusChange != nil {
			fmt.Printf("  Status: %s -> %s\n",
				hostDiff.StatusChange.OldStatus,
				hostDiff.StatusChange.NewStatus)
		}

		// Sort port changes for consistent output
		sort.Slice(hostDiff.PortChanges, func(i, j int) bool {
			return hostDiff.PortChanges[i].Port < hostDiff.PortChanges[j].Port
		})

		for _, portChange := range hostDiff.PortChanges {
			if portChange.OldState == "new" {
				fmt.Printf("  +%s/%s %s", portChange.Port, portChange.Protocol, portChange.NewState)
				if portChange.NewService != "" {
					fmt.Printf(" %s", portChange.NewService)
				}
				fmt.Println()
			} else if portChange.NewState == "removed" {
				fmt.Printf("  -%s/%s %s", portChange.Port, portChange.Protocol, portChange.OldState)
				if portChange.OldService != "" {
					fmt.Printf(" %s", portChange.OldService)
				}
				fmt.Println()
			} else {
				fmt.Printf("  %s/%s: %s -> %s",
					portChange.Port, portChange.Protocol,
					portChange.OldState, portChange.NewState)
				if portChange.OldService != portChange.NewService {
					fmt.Printf(" (%s -> %s)", portChange.OldService, portChange.NewService)
				}
				fmt.Println()
			}
		}

		// Print OS changes
		if len(hostDiff.OSChanges) > 0 {
			fmt.Println("  OS details:")
			for _, change := range hostDiff.OSChanges {
				fmt.Printf("    %s\n", change)
			}
		}
	}
}

// getFQDN returns the FQDN of a host if available.
func getFQDN(h *Host) string {
	for _, hn := range h.Hostnames {
		if hn.Type == "PTR" || hn.Type == "" {
			return hn.Name
		}
	}
	return ""
}

// getIPAddress returns the IPv4 or IPv6 address of a host if available.
func getIPAddress(h *Host) string {
	for _, addr := range h.Addresses {
		if addr.AddrType == "ipv4" || addr.AddrType == "ipv6" {
			return addr.Addr
		}
	}
	return ""
}

// getMACAddress returns the MAC address of a host if available.
func getMACAddress(h *Host) string {
	for _, addr := range h.Addresses {
		if addr.AddrType == "mac" {
			return addr.Addr
		}
	}
	return ""
}

// formatHostDisplayName returns a formatted display name for a given Host
// struct based on the provided logic.
func formatHostDisplayName(h *Host) string {
	fqdn := getFQDN(h)
	ip := getIPAddress(h)
	mac := getMACAddress(h)

	if fqdn != "" {
		if ip != "" && mac != "" {
			return fmt.Sprintf("%s (%s, %s)", fqdn, ip, mac)
		}
		if ip != "" {
			return fmt.Sprintf("%s (%s)", fqdn, ip)
		}
		if mac != "" {
			return fmt.Sprintf("%s (%s)", fqdn, mac)
		}
		return fqdn
	}

	if ip != "" {
		if mac != "" {
			return fmt.Sprintf("%s (%s)", ip, mac)
		}
		return ip
	}

	if mac != "" {
		return mac
	}

	return "unknown host"
}

// Check if any differences exist
func hasDifferences(diff *Diff) bool {
	return len(diff.NewHosts) > 0 ||
		len(diff.RemovedHosts) > 0 ||
		len(diff.HostChanges) > 0
}

func usage() {
	fmt.Fprintf(os.Stderr, `Usage: %s [options] FILE1 FILE2
Compare two Nmap XML files and display a list of their differences.

Options:
  -h, --help     display this help
  --version      display version information
  -v, --verbose  also show hosts and ports that haven't changed
  --text         display output in text format (default)
  --xml          display output in XML format (not implemented)
`, os.Args[0])
}

func main() {
	// Parse command line arguments
	flag.BoolVar(&verbose, "v", false, "verbose output")
	flag.BoolVar(&verbose, "verbose", false, "verbose output")
	flag.BoolVar(&textOut, "text", true, "text output")
	flag.BoolVar(&xmlOut, "xml", false, "XML output")

	versionFlag := flag.Bool("version", false, "show version")
	help := flag.Bool("h", false, "show help")
	helpLong := flag.Bool("help", false, "show help")

	flag.Parse()

	if *versionFlag {
		fmt.Println(version)
		os.Exit(0)
	}

	if *help || *helpLong {
		usage()
		os.Exit(0)
	}

	if flag.NArg() != 2 {
		fmt.Fprintf(os.Stderr, "Error: exactly two XML files must be specified\n")
		usage()
		os.Exit(ExitError)
	}

	file1 := flag.Arg(0)
	file2 := flag.Arg(1)

	// Load both scan files
	scan1, err := loadScan(file1)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error loading %s: %v\n", file1, err)
		os.Exit(ExitError)
	}

	scan2, err := loadScan(file2)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error loading %s: %v\n", file2, err)
		os.Exit(ExitError)
	}

	// Compare scans
	diff := compareScan(scan1, scan2)

	// Print results
	if xmlOut {
		fmt.Fprintf(os.Stderr, "XML output not yet implemented\n")
		os.Exit(ExitError)
	} else {
		printTextDiff(diff)
	}

	// Set exit code based on differences
	if hasDifferences(diff) {
		os.Exit(ExitDifferent)
	}
	os.Exit(ExitEqual)
}
