#!/usr/bin/env python3
# (re-)start rilproxy
from argparse import ArgumentParser
from shlex import split
from subprocess import run, PIPE
from swbridge import main
from time import sleep


VM = 'Componolit'
REBOOT_CMD = 'adb reboot'
GETPROP_CMD = 'adb shell getprop sys.boot_completed'
STARTVM_CMD = 'VBoxManage startvm '


# Configure command line parser
parser = ArgumentParser(
    description='(Re-)start proxying of packets between AP VM and BP phone')

parser.add_argument('-l', '--logging', default='info', type=str,
                    choices=['verbose', 'debug', 'info', 'warning',
                             'error'],
                    help='log level (default=info)')
parser.add_argument('-p', '--proxy-only', action='store_true',
                    help='Do not filter non-UDP packets and allow all calls')

args = parser.parse_args()

run(split('VBoxManage controlvm ' + VM + ' poweroff'))
run(split(REBOOT_CMD))
sleep(14)  # Wait 13 seconds for restart
while run(split(GETPROP_CMD), stdout=PIPE).stdout != b'1\n':
    sleep(1)
run(split(STARTVM_CMD + VM))

main(args.proxy_only, args.logging)
