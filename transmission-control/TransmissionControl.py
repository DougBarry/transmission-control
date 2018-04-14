import logging
import os
import sys
import re
import argparse
import json

import transmissionrpc
from transmissionrpc.utils import *


class TransmissionControlError(Exception):
    pass


class TransmissionControlConfigurationError(TransmissionControlError):
    pass


class TransmissionControl(object):

    dry_run = False
    verbose = False
    silent = False

    filename = 'transmission-control.worklist'
    worklist_filename = ''
    move_rules = {}
    suppress_move_warnings = False

    def __init__(self):

        self.__app_path = os.path.dirname(os.path.realpath(__file__))
        self.name = self.__class__.__name__
        self.logger = logging.getLogger(self.name)

        self.host_address = ''
        self.host_port = 9091
        self.username = ''
        self.password = ''

    def touch(self, fname):
        self.logger.warning("Touching file: " + fname)
        if os.path.exists(fname):
            os.utime(fname, None)
        else:
            self.logger.warning("Creating empty file: " + fname)
            open(fname, 'a').close()

    def validate_rule(self, pattern, destination):
        try:
            repattern = re.compile(pattern)
        except Exception as e:
            self.logger.exception(e)
            self.logger.info("Exception compiling move rule regex: " + pattern)
            return False
        return True

    def load_rules(self, fname):
        rules = {}
        try:
            with open(fname) as f:
                data = json.load(f)
                for rule in data:
                    pattern = rule['pattern']
                    destination = rule['destination']
                    result = self.validate_rule(pattern, destination)
                    if result:
                        rules[pattern]=destination
        except Exception as e:
            self.logger.exception(e)
            self.logger.info("Failed to load rules from: " + fname)
            return None
        return rules

    def load_trackers(self, fname):
        trackers = []
        try:
            with open(fname) as f:
                trackers = f.read().splitlines()
        except Exception as e:
            self.logger.exception(e)
            self.logger.info("Failed to load trackers list from: " + fname)
            return None
        return trackers

    def save_rules(self, fname, rules):
        json.dump(rules, fname)

    def run(self, configuration):

        torrents = None
        tc = None

        if not isinstance(configuration, dict):
            raise TransmissionControlConfigurationError("configuration object passed was not dictionary")

        try:
            self.worklist_filename = configuration.get("worklist_filename", os.path.join(self.__app_path, self.filename))
            self.logger.debug("Using workfile: " + self.worklist_filename)

            self.move_rules = configuration.get("move_rules", {})
            if not isinstance(self.move_rules,dict):
                raise TransmissionControlConfigurationError("Move rules in configuration was not a dictionary")
            self.logger.debug("Loaded " + str(len(self.move_rules)) + " move rules")

            self.suppress_move_warnings = configuration.get("suppress_move_warnings", False)
            self.logger.debug("Suppress move warnings: " + str(self.suppress_move_warnings))

            self.host_address = configuration.get("host_address", "localhost")
            if self.host_address is '':
                raise TransmissionControlConfigurationError("host_address is empty")
            self.logger.debug("Using host address: " + self.host_address)

            self.host_port = configuration.get("host_port", 9091)
            self.logger.debug("Using host port: " + str(self.host_port))

            self.username = configuration.get("username", "transmission")
            if self.username is '':
                raise TransmissionControlConfigurationError("Username is empty")
            self.logger.debug("Using username: " + self.username)

            self.password = configuration.get("password", "password")
            self.logger.debug("Using a password (" + '*'*len(self.password) + ")")

            self.verbose = configuration.get("verbose", False)
            self.logger.debug("Using verbose flag: " + str(self.verbose))

            self.dry_run = configuration.get("dry_run", False)
            self.logger.debug("Using dry run flag: " + str(self.dry_run))

            self.silent = configuration.get("silent", False)
            self.logger.debug("Using silent flag: " + str(self.silent))

            self.trackers_list = configuration.get("trackers_list", None)
            self.logger.debug("Tracker list contains " + str(len(self.trackers_list)) + " entries.")
        except Exception as e:
            raise TransmissionControlConfigurationError("Failed to interpret configuration dictionary", e)

        if not os.path.isfile(self.worklist_filename):
            self.touch(self.worklist_filename)

        self.logger.debug("Connecting to transmission-daemon")
        try:
            tc = transmissionrpc.Client(
                self.host_address,
                port=self.host_port,
                user=self.username,
                password=self.password
            )
        except transmissionrpc.error.TransmissionError as te:
            self.logger.fatal("Failed to connect to transmission")
            self.logger.exception(te)
            sys.exit(1)

        self.logger.debug("Collecting torrent info from transmission-daemon")
        try:
            torrents = tc.get_torrents()
        except Exception as e:
            self.logger.fatal("Error obtaining torrents info from RPC")
            self.logger.exception(e)
            sys.exit(1)

        count_torrents_processed = count_torrents_moved = count_torrents_removed = count_torrents_resumed = count_torrents_in_checking = 0

        for pattern, destination in self.move_rules.iteritems():

            if not os.path.exists(destination):
                # this could be a problem
                if not self.suppress_move_warnings:
                    self.logger.debug("Destination path '" + destination + "' does not exist or is not accessible by this module, this may cause transmission-daemon's move to fail")

            try:
                repattern = re.compile(pattern)
            except Exception as e:
                self.logger.exception(e)
                self.logger.info("Exception compiling move rule regex: " + pattern)
                continue

            for torrent in torrents:

                try:
                    if trackers_list is not None:
                        if len(trackers_list) >= 1:
                            this_torrents_new_trackers = []
                            for ftracker in trackers_list:
                                if len(filter (lambda x : x == ftracker, torrent.trackers)) == 0:
                                    this_torrents_new_trackers.append(ftracker)

                            if len(this_torrents_new_trackers) > 0:
                                tc.change_torrent(ids=torrent.id, trackerAdd=this_torrents_new_trackers)
                except Exception as e:
                    pass

                result = repattern.search(torrent.downloadDir)
                if result is None:
                    continue

                self.logger.debug("Torrent ID(" + str(torrent.id) + "),Hashstring(\'" + torrent.hashString + "\'),Name:(\'" + torrent.name + "\')")
                if torrent.status == 'checking':
                    self.logger.debug("Torrent status: checking, skipping")
                    continue
                if torrent.status == 'check pending':
                    self.logger.debug("Torrent status: check pending, skipping")
                    continue

                count_torrents_processed += 1

                if os.stat(self.worklist_filename).st_size > 0:
                    if str(torrent.hashString) in open(self.worklist_filename).read():
                        # is status still 100%?
                        if torrent.progress >= 100:
                            # checked and still good! move?

                            self.logger.info("Check complete, file OK: " + torrent.name)
                            if not self.dry_run:
                                self.remove_hash(torrent.hashString)

                            self.logger.info("Moving " + torrent.name + " to " + destination)
                            if not self.dry_run:
                                tc.move_torrent_data(torrent.id, destination)

                            self.logger.info("Removing " + torrent.name)
                            if not self.dry_run:
                                tc.remove_torrent(torrent.id, False)

                            count_torrents_moved += 1
                            count_torrents_removed += 1
                            continue
                        else:
                            # torrent progress is bad...

                            self.logger.warning("Check failed, resuming: " + torrent.name)
                            if not self.dry_run:
                                tc.start_torrent(torrent.id)

                            count_torrents_resumed += 1
                            continue

                if torrent.progress >= 100:

                    self.logger.info("Stopping and checking: " + torrent.name)
                    if not self.dry_run:
                        tc.stop_torrent(torrent.id)
                        tc.verify_torrent(torrent.id)
                        self.add_hash(torrent.hashString)

                    count_torrents_in_checking += 1

        if not (count_torrents_moved == count_torrents_removed == count_torrents_resumed == count_torrents_in_checking == 0):
            self.logger.info("count_torrents_processed=%s count_torrents_moved=%s count_torrents_removed=%s count_torrents_resumed=%s count_torrents_in_checking=%s", count_torrents_processed, count_torrents_moved, count_torrents_removed, count_torrents_resumed, count_torrents_in_checking)

    def add_hash(self, hash):
        if not self.dry_run:
            worklist = open(self.worklist_filename, 'a')
            worklist.write(str(hash) + "\n")
            worklist.close()
            worklist = None
        self.logger.debug("Added hash: " + str(hash) + " to worklist")

    def remove_hash(self, hash):
        if not self.dry_run:
            worklist = open(self.worklist_filename, 'r')
            lines = worklist.readlines()
            worklist.close()
            worklist = open(self.worklist_filename, 'w')
            for line in lines:
                if not line.startswith(str(hash)):
                    worklist.write(line)
            worklist.close()
            worklist = None
        self.logger.debug("Removed hash: " + str(hash) + " from worklist")


if __name__ == '__main__':

    parser = argparse.ArgumentParser(prog=os.path.basename(sys.argv[0]), description='Launch options')

    connection_group = parser.add_argument_group(title='Connection settings')

    connection_group.add_argument('-t', '--host-address', help='Transmission-daemon host address. Default: localhost',
                                  type=str, dest='host_address', default="localhost")
    connection_group.add_argument('-p', '--host-port', help='Transmission-daemon host port. Default: 9091', type=int,
                                  dest='host_port', default=9091)
    connection_group.add_argument('-u', '--username', help='RPC username. Default: transmission', type=str,
                                  dest='username', default='transmission')
    connection_group.add_argument('-w', '--password', help='RPC password. Default: password', type=str, dest='password',
                                  default='password')

    debug_group = parser.add_argument_group(title='Debug settings')

    debug_group.add_argument('-d', '--dry-run', help='Test only, perform no actions', action='store_true',
                             dest='dry_run', default=False)

    debug_group2 = debug_group.add_mutually_exclusive_group()
    debug_group2.add_argument('-v', '--verbose', help='Verbose output', action='store_true', dest='verbose',
                              default=False)
    debug_group2.add_argument('-q', '--quiet', help='Suppress all logging output. Silent mode.', action='store_true',
                              dest='silent', default=False)

    rules_group = parser.add_argument_group(title='Rules operations')

    rules_group.add_argument('-r', '--rules-file', help='Rules definition input file', type=str, dest='move_rules_file',
                             default=None)
    rules_group.add_argument('-e', '--example', help='Output example rules file to stdout', action='store_true',
                             dest='rules_example', default=False)
    rules_group.add_argument('-s', '--suppress-warnings', help='Suppress warnings about destination directories',
                             action='store_true', dest='suppress_move_warnings')

    trackers_group = parser.add_argument_group(title='Trackers operations')

    trackers_group.add_argument('-a', '--trackers-file', help='Default extra trackers input file', type=str,
                                dest='tracker_file', default='')


    rootLogger = logging.getLogger()
    if args.verbose:
        rootLogger.setLevel(logging.DEBUG)
    else:
        rootLogger.setLevel(logging.INFO)

    rootLogger.disabled = args.silent

    stdout_logger = logging.StreamHandler(sys.stdout)
    stdout_logger.setLevel(logging.DEBUG)
    stdout_logger_formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
    stdout_logger.setFormatter(stdout_logger_formatter)
    rootLogger.addHandler(stdout_logger)

    tcontrol = TransmissionControl()

    move_rules = {}
    trackers_list = []
    tconfiguration = {}

    if args.rules_example:
        example_rules = [
            {
                'pattern': '(.*)iso$',
                'destination': "/smb/storage/iso",
            },
            {
                'pattern': '(.*)ebook$',
                "destination": "/smb/ebooks-unsorted",
            }
        ]
        tcontrol.save_rules(sys.stdout, example_rules)
        sys.exit(0)

    operation_rules = False
    operation_trackers = False

    if args.move_rules_file is not None:
        if os.path.isfile(args.move_rules_file):
            move_rules = tcontrol.load_rules(args.move_rules_file)
            operation_rules = True
        else:
            operation_rules = False
    else:
        operation_rules = False

    if args.tracker_file is not None:
        if os.path.isfile(args.tracker_file):
            trackers_list = tcontrol.load_trackers(args.tracker_file)
            operation_trackers = True
        else:
            operation_trackers = False
    else:
        operation_trackers = False

    if (operation_rules is False) and (operation_trackers is False):
        logging.error('No operations to carry out.')
        parser.print_help()
        sys.exit(2)

    tconfiguration = {
        "dry_run": args.dry_run,
        "verbose": args.verbose,
        "silent": args.silent,
        "host_address": args.host_address,
        "host_port": args.host_port,
        "username": args.username,
        "password": args.password,
        "move_rules": move_rules,
        "suppress_move_warnings": args.suppress_move_warnings,
        "trackers_list": trackers_list
    }

    logging.info(os.path.basename(sys.argv[0]) + " started")

    try:
        tcontrol.run(tconfiguration)
    except Exception as e:
        logging.exception(e)
        sys.exit(1)

    logging.info(os.path.basename(sys.argv[0]) + " finished")
