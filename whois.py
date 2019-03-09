#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
IPv4 Whois data collection and analysis tool

"""

import ipaddress
import argparse
from random import randint

def handle_args():
	"""
	Handles the arguments.

	Returns:
		argparse object: the script arguments and details.
	"""
	p = argparse.ArgumentParser()
	p.add_argument('action', type=str, nargs=1, metavar='action', \
		help='Action to take.  Valid options are "collect" or "stats"')
	p.add_argument('--sleep-min', type=int, dest='sleep_min', \
		help="Minimum thread sleep value in seconds.", \
		default=randint(1, 5))
	p.add_argument('--sleep-max', type=int, dest='sleep_max', \
		help="Maximum thread sleep value in seconds.", \
		default=randint(1, 5))
	p.add_argument('-t', '--threads', type=int, dest='num_threads', \
		help="Number of threads to use.")
	p.add_argument('-e', '--eleastic-url', dest='elastic_url', \
		help="URL for the elasticsearch server, including port.")
	p.add_argument('-i', '--elastic-index', dest='elastic_index', \
		help="Eleasticsearch document index.")
	p.add_argument('-d', '--elastic-doc', dest='elastic_doc', \
		help="Elasticsearch document name.")
	a = p.parse_args()
	return a


def get_next_ip(_ipaddress):
	""" 
	gets the next ip address
	- all of the heavy lifting is done in the 
		ipaddress module
	
	Parameters:
		ipaddress (str): a string representing a valid IP address
	
	Returns:
		_ (str): a string representing the next IP address
	"""
	return ipaddress.IPv4Address(_ipaddress) + 1

def get_netrange_end(asn_cidr):
	"""
	gets the end of the cidr
	- again all of the heavy lifting has handled by these
		ipaddress module
	
	Parameters:
		asn_cidr
def main():
	"""
	Get the whois data for IPv4 addresses
	"""

	args = handle_args()

	if 'collect' in args.action:
		print("Got action collect.")
		# these shouldn't be need now since we're handling with
		# argparse.  But leave it for now, remove once proven.
		#sleep_min = int(args.sleep_min) \
		#	if args.sleep_min is not None else randint(1, 5)
		#sleep_max = int(args.sleep_max) \
		#	if args.sleep_max is not None else randint(1, 5)

		if args.sleep_min > args.sleep_max:
			args.sleep_min, args.sleep_max = args.sleep_max, args.sleep_min
		print("sleep-min: {0} sleep-max: {1}".format(args.sleep_min, \
		args.sleep_max))

		starting_ip = ipaddress.IPv4Address('24.255.255.255')
		#print(str(dir(starting_ip)))
		print("Starting IP: {0}, Next IP: {1}".format(starting_ip, \
			starting_ip + 1))
    
	elif 'stats' in args.action:
		print("Got action stats.")
		pass
	else:
		print("Got undefined action: {0}".format(args.action))

if __name__=='__main__':
	main()
