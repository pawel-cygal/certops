package main

import (
	"flag"
	"fmt"
	"os"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"
)

type inventoryHostRow struct {
	Group        string `json:"group" yaml:"group"`
	Name         string `json:"name" yaml:"name"`
	Address      string `json:"address" yaml:"address"`
	User         string `json:"user,omitempty" yaml:"user,omitempty"`
	Port         string `json:"port,omitempty" yaml:"port,omitempty"`
	IdentityFile string `json:"identity_file,omitempty" yaml:"identity_file,omitempty"`
	OS           string `json:"os,omitempty" yaml:"os,omitempty"`
}

func cmdInventory(args []string) {
	if len(args) < 1 {
		fatal("usage: certops inventory <list|show> -f certops.yaml")
	}
	switch strings.ToLower(strings.TrimSpace(args[0])) {
	case "list":
		cmdInventoryList(args[1:])
	case "show":
		cmdInventoryShow(args[1:])
	default:
		fatal("unknown inventory command: " + args[0])
	}
}

func cmdInventoryList(args []string) {
	args = normalizeFlagArgs(args, map[string]bool{"-f": true})
	fs := flag.NewFlagSet("inventory list", flag.ExitOnError)
	file := fs.String("f", "certops.yaml", "config file")
	jsonOut := fs.Bool("json", false, "emit JSON")
	yamlOut := fs.Bool("yaml", false, "emit YAML")
	fs.Parse(args)
	format, err := resolveOutput(*jsonOut, *yamlOut, false)
	if err != nil {
		fatal(err.Error())
	}
	cfg, err := loadConfig(*file)
	if err != nil {
		fatal(err.Error())
	}
	rows := inventoryRows(cfg)
	printInventoryRows(rows, format)
}

func cmdInventoryShow(args []string) {
	args = normalizeFlagArgs(args, map[string]bool{"-f": true})
	fs := flag.NewFlagSet("inventory show", flag.ExitOnError)
	file := fs.String("f", "certops.yaml", "config file")
	jsonOut := fs.Bool("json", false, "emit JSON")
	yamlOut := fs.Bool("yaml", false, "emit YAML")
	fs.Parse(args)
	if fs.NArg() != 1 {
		fatal("usage: certops inventory show <host|group> -f certops.yaml")
	}
	format, err := resolveOutput(*jsonOut, *yamlOut, false)
	if err != nil {
		fatal(err.Error())
	}
	cfg, err := loadConfig(*file)
	if err != nil {
		fatal(err.Error())
	}
	want := fs.Arg(0)
	rows := filterInventoryRows(cfg, want)
	if len(rows) == 0 {
		fatal("inventory target not found: " + want)
	}
	printInventoryRows(rows, format)
}

func inventoryRows(cfg certopsConfig) []inventoryHostRow {
	rows := []inventoryHostRow{}
	groups := make([]string, 0, len(cfg.Inventory.Groups))
	for name := range cfg.Inventory.Groups {
		groups = append(groups, name)
	}
	sort.Strings(groups)
	for _, groupName := range groups {
		group := cfg.Inventory.Groups[groupName]
		hosts := make([]string, 0, len(group.Hosts))
		for name := range group.Hosts {
			hosts = append(hosts, name)
		}
		sort.Strings(hosts)
		for _, hostName := range hosts {
			host := group.Hosts[hostName]
			rows = append(rows, inventoryHostRow{Group: groupName, Name: hostName, Address: host.Address, User: host.User, Port: host.Port, IdentityFile: host.IdentityFile, OS: host.OS})
		}
	}
	return rows
}

func filterInventoryRows(cfg certopsConfig, target string) []inventoryHostRow {
	if group, ok := cfg.Inventory.Groups[target]; ok {
		return inventoryRows(certopsConfig{Inventory: configInventory{Groups: map[string]configGroup{target: group}}})
	}
	rows := []inventoryHostRow{}
	for _, row := range inventoryRows(cfg) {
		if row.Name == target {
			rows = append(rows, row)
		}
	}
	return rows
}

func printInventoryRows(rows []inventoryHostRow, format outputFormat) {
	switch format {
	case outputJSON:
		printJSON(rows)
	case outputYAML:
		enc := yaml.NewEncoder(os.Stdout)
		defer enc.Close()
		if err := enc.Encode(rows); err != nil {
			fatal(err.Error())
		}
	default:
		table := make([][]string, 0, len(rows))
		for _, row := range rows {
			table = append(table, []string{row.Group, row.Name, row.Address, emptyDash(row.User), emptyDash(row.Port), emptyDash(row.OS)})
		}
		renderTable([]string{"group", "host", "address", "user", "port", "os"}, table)
		fmt.Printf("\nsummary: hosts=%d\n", len(rows))
	}
}
