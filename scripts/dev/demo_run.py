#!/usr/bin/env python3
# restart rilproxy
from shlex import split
from subprocess import run, PIPE
from swbridge import main
from time import sleep

REBOOT_CMD = 'adb reboot'
GETPROP_CMD = 'adb shell getprop sys.boot_completed'
STARTVM_CMD = 'VBoxManage startvm Componolit'

run(split(REBOOT_CMD))
sleep(13)  # Wait 10 seconds for restart
while run(split(GETPROP_CMD), stdout=PIPE).stdout != b'1\n':
    sleep(1)
run(split(STARTVM_CMD))
main()
