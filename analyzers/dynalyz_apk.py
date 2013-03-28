#!/usr/bin/env python3
import subprocess
import datetime
import time

# Copyright 2012-2013 Alexey Karyabkin
# Not for commercial use
#

#init variables
install_apk = 0

def create_virtual_dev(name_dev):
	sp = subprocess.Popen([r"android-sdk\tools\android.bat", "create", "avd", "--force","-n", name_dev, "-t", "1"],stdin=subprocess.PIPE, stdout=subprocess.PIPE)
	sp.stdin.write("n\n")
	for l in sp.stdout.xreadlines():
		print l
	return 0

def start_virtual_dev(name_dev):
	subprocess.Popen([r"android-sdk\tools\emulator-arm", name_dev], stdout=subprocess.PIPE)
	return 0

def get_process_list():
	pslist = subprocess.Popen([r"android-sdk\platform-tools\adb","shell","ps"], stdout=subprocess.PIPE)
	for l in pslist.stdout.xreadlines():
		print l
	return 0

def install_malware_apk(apk_name):
	loginstall = subprocess.Popen([r"android-sdk\platform-tools\adb","install",apk_name], stdout=subprocess.PIPE)
	global install_apk
	install_apk = 2
	for l in loginstall.stdout.xreadlines():
		print l
	return 0

def check_sysload(str):
	if str.find('I/LegacyContactImporter')>-1:
		global install_apk
		install_apk = 1
		print("OS load!")
	return 0

def analyze_syslog(str):
	#if str.find('E/sdman')>-1:
	#	print str
	#if str.find('D/SMS')>-1:
	#	print str
	#if str.find('D/RILJ')>-1:
	#	print str
	#if str.find('D/RIL')>-1:
	#	print str
	#if str.find('D/AT')>-1:
	#	print str
	#if str.find('W/System.err')>-1:	I/am_create_service	I/am_destroy_service	I/am_on_resume_called(  316): pmjwjd.ijtyuoo.fornafde	I/ActivityManager

	print str
	return 0

def start_mon_virtual_dev():
	global install_apk
	syslog = subprocess.Popen([r"android-sdk\platform-tools\adb","logcat","-b","main","-b","events","-b","radio"], stdout=subprocess.PIPE)
	for l in syslog.stdout.xreadlines():
		analyze_syslog(l)
		if install_apk == 0:
			check_sysload(l)
		if install_apk == 1:
			get_process_list()
			install_malware_apk(r"malware_apk\5c6294447a1e5a539ee282a8015b6518a91992d2")
			get_process_list()
	return 0

#display banner
print ("Android-emulator service| dynamic analyze *.apk =)")

#create android virtual device (force|overwrite the existing)
create_virtual_dev("test5")

#start android virtual device
start_virtual_dev("@test5")

#start monitoring syslog android virtual device
start_mon_virtual_dev()

