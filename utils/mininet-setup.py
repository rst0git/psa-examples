#!/usr/bin/env python
import os
import json
import subprocess
import argparse
from time import sleep

from p4_mininet import P4Switch, P4Host

from mininet.net import Mininet
from mininet.topo import Topo
from mininet.link import TCLink
from mininet.cli import CLI

def configure_switch(**switch_args):
    """ Helper class that is called by mininet to initialize
        the virtual P4 switches.
    """
    class ConfiguredP4Switch(P4Switch):
        next_thrift_port = 9090
        def __init__(self, *opts, **kwargs):
            global next_thrift_port
            kwargs.update(switch_args)
            kwargs['thrift_port'] = ConfiguredP4Switch.next_thrift_port
            ConfiguredP4Switch.next_thrift_port += 1
            P4Switch.__init__(self, *opts, **kwargs)

        def describe(self):
            print(("%s -> Thrift port: %d" % (self.name, self.thrift_port)))

    return ConfiguredP4Switch


class ExerciseTopo(Topo):
    """ The mininet topology class for the P4 tutorial exercises.
    """
    def __init__(self, hosts, switches, links, log_dir, bmv2_exe, pcap_dir, **opts):
        Topo.__init__(self, **opts)
        host_links = []
        switch_links = []

        # assumes host always comes first for host<-->switch links
        for link in links:
            if link['node1'][0] == 'h':
                host_links.append(link)
            else:
                switch_links.append(link)

        for sw, params in switches.items():
            self.addSwitch(sw, log_file="%s/%s.log" %(log_dir, sw), cls=None)

        for link in host_links:
            host_name = link['node1']
            sw_name, sw_port = self.parse_switch_node(link['node2'])
            host_ip = hosts[host_name]['ip']
            host_mac = hosts[host_name]['mac']
            self.addHost(host_name, ip=host_ip, mac=host_mac)
            self.addLink(host_name, sw_name,
                         delay=link['latency'], bw=link['bandwidth'],
                         port2=sw_port)

        for link in switch_links:
            sw1_name, sw1_port = self.parse_switch_node(link['node1'])
            sw2_name, sw2_port = self.parse_switch_node(link['node2'])
            self.addLink(sw1_name, sw2_name, port1=sw1_port, port2=sw2_port,
                         delay=link['latency'], bw=link['bandwidth'])

    def parse_switch_node(self, node):
        sw_name, sw_port = node.split('-')
        try:
            sw_port = int(sw_port[1:])
        except:
            raise Exception('Invalid switch node in topology file: {}'.format(node))
        return sw_name, sw_port


class ExerciseRunner:
    """
        Attributes:
            log_dir  : string   // directory for mininet log files
            pcap_dir : string   // directory for mininet switch pcap files
            quiet    : bool     // determines if we print logger messages
            hosts    : dict<string, dict> // mininet host names and their associated properties
            switches : dict<string, dict> // mininet switch names and their associated properties
            links    : list<dict>         // list of mininet link properties
            switch_json : string // json of the compiled p4 example
            bmv2_exe    : string // name or path of the p4 switch binary
            topo : Topo object   // The mininet topology instance
            net : Mininet object // The mininet instance
    """
    def __init__(self, topo_file, log_dir, pcap_dir, switch_json,
                 bmv2_exe='simple_switch', quiet=False):
        """Initialise attributes and read the topology json.

            Arguments:
                topo_file:   string  A json file describing mininet topology.
                log_dir :    string  Path to a directory for storing exercise logs
                pcap_dir:    string  Ditto, but for mininet switch pcap files
                switch_json: string  Path to a compiled p4 json for bmv2
                bmv2_exe:    string  Path to the p4 behavioral binary
                quiet:       bool    Enable/disable script debug messages
        """
        self.quiet = quiet
        self.logger('Reading topology file.')
        with open(topo_file, 'r') as f:
            topo = json.load(f)
        self.hosts = topo['hosts']
        self.switches = topo['switches']
        self.links = self.parse_links(topo['links'])

        # Ensure all the needed directories exist and are directories
        for dir_name in [log_dir, pcap_dir]:
            if not os.path.isdir(dir_name):
                if os.path.exists(dir_name):
                    raise Exception("'%s' exists and is not a directory!" % dir_name)
                os.mkdir(dir_name)
        self.log_dir = log_dir
        self.pcap_dir = pcap_dir
        self.switch_json = switch_json
        self.bmv2_exe = bmv2_exe

    def logger(self, *items):
        if not self.quiet:
            print((' '.join(items)))

    def format_latency(self, l):
        """ Helper method for parsing link latencies from the topology json. """
        if isinstance(l, str):
            return l
        return str(l) + "ms"

    def run_exercise(self):
        """ Sets up the mininet instance, programs the switches,
            and starts the mininet CLI. This is the main method to run after
            initializing the object.
        """
        # Initialize mininet with the topology specified by the config
        self.create_network()
        self.net.start()
        sleep(1)

        # some programming that must happen after the net has started
        self.program_hosts()
        self.program_switches()

        # wait for that to finish. Not sure how to do this better
        sleep(1)

        self.do_net_cli()
        self.net.stop()  # stop right after the CLI is exited

    def parse_links(self, unparsed_links):
        """ Parse a given list of links in the following format,
            with the latency and bandwidth being optional:
                [node1, node2, latency, bandwidth]
            Returns the parsed list.
        """
        links = []
        for link in unparsed_links:
            link_len = len(link)
            # make sure each link's endpoints are ordered alphabetically
            s, t, = link[0], link[1]
            if s > t:
                s, t = t, s

            if s.startswith('h'):
                assert t.startswith('s'), 'Hosts should be connected to switches, not ' + t
            link_dict = {
                'node1': s,
                'node2': t,
                'latency': '0ms',
                'bandwidth': None,
            }
            if link_len > 2:
                link_dict['latency'] = self.format_latency(link[2])
            if link_len > 3:
                link_dict['bandwidth'] = link[3]
            links.append(link_dict)
        return links

    def create_network(self):
        """ Create a mininet network object and topology instance """
        self.logger("Building mininet topology.")

        defaultSwitchClass = configure_switch(
            sw_path=self.bmv2_exe,
            json_path=self.switch_json,
            log_console=True,
            pcap_dump=self.pcap_dir,
        )

        self.topo = ExerciseTopo(
            self.hosts,
            self.switches,
            self.links,
            self.log_dir,
            self.bmv2_exe,
            self.pcap_dir,
        )

        self.net = Mininet(
            topo=self.topo,
            link=TCLink,
            host=P4Host,
            switch=defaultSwitchClass,
            controller=None
        )

    def program_switch_cli(self, sw_name, sw_dict):
        """ This method will start up the CLI and use the contents of the
            command files as input.
        """
        sw_obj = self.net.get(sw_name)
        cli_input_commands = sw_dict['cli_input']
        self.logger('Configuring switch %s with file %s' % (sw_name, cli_input_commands))

        with open(cli_input_commands, 'r') as fin:
            cli_outfile = os.path.join(self.log_dir, sw_name + '_cli_output.log')
            with open(cli_outfile, 'w') as fout:
                subprocess.Popen(
                    ['psa_switch_CLI', '--thrift-port', str(sw_obj.thrift_port)],
                    stdin=fin, stdout=fout)

    def program_switches(self):
        """ This method will program each switch using the BMv2 CLI and/or
            P4Runtime, depending if any command or runtime JSON files were
            provided for the switches.
        """
        for sw_name, sw_dict in self.switches.items():
            if 'cli_input' in sw_dict:
                self.program_switch_cli(sw_name, sw_dict)

    def program_hosts(self):
        """ Execute any commands provided in the topology.json file on each Mininet host
        """
        for host_name, host_info in list(self.hosts.items()):
            h = self.net.get(host_name)
            if "commands" in host_info:
                for cmd in host_info["commands"]:
                    h.cmd(cmd)

    def do_net_cli(self):
        """ Starts up the mininet CLI and prints some helpful output.

            Assumes:
                - A mininet instance is stored as self.net and self.net.start() has
                  been called.
        """
        for s in self.net.switches:
            s.describe()
        for h in self.net.hosts:
            h.describe()
        self.logger("Starting mininet CLI")

        line = "=" * 50 + "\n"
        print(line + "Welcome to the BMV2 Mininet CLI!\n" + line +
              "Your P4 program is installed into the BMV2 software switch\n"
              "and your initial runtime configuration is loaded. You can interact\n"
              "with the network using the mininet CLI below.\n")

        if self.switch_json:
            print("To inspect or change the switch configuration, connect to\n"
                  "its CLI from your host operating system using this command:\n"
                  "   psa_switch_CLI --thrift-port <switch thrift port>\n")

        print("To view a switch log, run this command from your host OS:\n"
              "  tail -f %s/<switchname>.log\n\n"
              "To view the switch output pcap, check the pcap files in %s:\n"
              "  sudo tcpdump -xxx -r s1-eth1.pcap\n" % (self.log_dir, self.pcap_dir))
        if 'grpc' in self.bmv2_exe:
            print("To view the P4Runtime requests sent to the switch,\n"
                  " check the corresponding txt file in %s:\n"
                  "  cat %s/s1-p4runtime-requests.txt\n" % (self.log_dir, self.log_dir))

        CLI(self.net)


def get_args():
    cwd = os.getcwd()
    default_logs = os.path.join(cwd, 'logs')
    default_pcaps = os.path.join(cwd, 'pcaps')
    parser = argparse.ArgumentParser()
    parser.add_argument('-q', '--quiet', help='Suppress log messages',
                        action='store_true', required=False, default=False)
    parser.add_argument('-t', '--topo', help='Path to topology json',
                        type=str, required=False, default='./topology.json')
    parser.add_argument('-l', '--log-dir', help='Path to a directory for storing logs',
                        type=str, required=False, default=default_logs)
    parser.add_argument('-p', '--pcap-dir',
                        help='Path to directory for mininet switch pcap files',
                        type=str, required=False, default=default_pcaps)
    parser.add_argument('-j', '--switch-json', help='Path to a compiled P4 json for bmv2',
                        type=str, required=False)
    parser.add_argument('-b', '--behavioral-exe', help='Path to the P4 behavioral binary',
                        type=str, required=False, default='psa_switch')
    return parser.parse_args()


if __name__ == '__main__':
    args = get_args()
    exercise = ExerciseRunner(args.topo, args.log_dir, args.pcap_dir,
                              args.switch_json, args.behavioral_exe, args.quiet)

    exercise.run_exercise()

