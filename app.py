import argparse

from src.Network_API_l import NetworkAPI
from src.AppRunner import AppRunner
from src.networking import create_int_collection_network
import os

def get_args():
    """Parses command line options.
    Returns:
        argparse.Namespace: namespace containing all the argument parsed.
    Here is a complete list of the command line invocation options available with ``p4run``:
    - ``--config`` is the path to configuration (if it is not specified,
      it is assumed to be ``./p4app.json``).
    - ``--log-dir`` is the path to log files (if it is not specified,
      it is assumed to be ``./log``).
    - ``--pcap-dir`` is the path to the ``.pcap`` files generated for each switch interface
      (if it is not specified, it is assumed to be ``./pcap``).
    - __ verbosity_
    
      ``--verbosity`` specifies the desired verbosity of the output (if it is not specified,
      it is assumed to be set to ``info``). Valid verbosity values are listed `here`__.
    - ``--no-cli`` disables the *Mininet* client (it is enabled by default).
    - ``--clean`` cleans old log files, if specified.
    - ``--clean-dir`` cleans old log files and closes, if specified.
    """

    cwd = os.getcwd()
    default_log = os.path.join(cwd, './log')
    default_pcap = os.path.join(cwd, './pcap')

    parser = argparse.ArgumentParser()

    parser.add_argument('--config', help='Path to configuration.',
                        type=str, required=False, default='./p4app.json')
    parser.add_argument('--log-dir', help='Generate logs in the specified folder.',
                        type=str, required=False, default=default_log)
    parser.add_argument('--pcap-dir', help='Generate .pcap files for interfaces.',
                        type=str, required=False, default=default_pcap)
    parser.add_argument('--verbosity', help='Set messages verbosity.',
                        type=str, required=False, default='info')
    parser.add_argument('--no-cli', help='Do not run the Mininet CLI.',
                        action='store_true', required=False, default=False)
    parser.add_argument('--clean', help='Cleans old log files.',
                        action='store_true', required=False, default=False)
    parser.add_argument('--clean-dir', help='Cleans old log files and closes.',
                        action='store_true', required=False, default=False)
    parser.add_argument('--influx', help='INT collector DB access (InfluxDB host:port)', const="InfluxDB 0.0.0.0:8086",
                    type=str, action="store", nargs='?')          

    return parser.parse_args()


args = get_args()
app = AppRunner(args.config,
    cli_enabled=(not args.no_cli),
    log_dir=args.log_dir,
    pcap_dir=args.pcap_dir,
    verbosity=args.verbosity)

app.startNetwork()
print("pkill -f \"python3 ./src/int_collector_influx.py\"")
os.system("pkill -f \"python3 ./src/int_collector_influx.py\"")
print("ip a | grep -o \"\\([[:alnum:]]\\+\\_\\)\\?[[:alnum:]]\\+\\_[[:alnum:]]\\+@[[:alnum:]]\\+\" | sed 's/\\@.*$//' | while read line ; do sudo ip link delete \"$line\"; done")
os.system("ip a | grep -o \"\\([[:alnum:]]\\+\\_\\)\\?[[:alnum:]]\\+\\_[[:alnum:]]\\+@[[:alnum:]]\\+\" | sed 's/\\@.*$//' | while read line ; do sudo ip link delete \"$line\"; done")