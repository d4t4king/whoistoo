#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
IPv4 Whois data collection and analysis tool

"""

import ipaddress
import argparse
from random import randint
from pyelasticsearch import ElasticSearch
from pyelasticsearch.exceptions import \
	ElasticHttpError, ElasticHttpNotFoundError

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
		help="Number of threads to use.", default=8)
	p.add_argument('-e', '--elastic-url', dest='elastic_url', \
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

def break_up_ipv4_address_space(num_threads):
	"""
	breaks up the total IP address space into
	manageable chunks

	Parameters:
		num_threads (int): the number of threads to distribute
			the IP space amongst

	Returns:
		ranges (list): returns the list of tuples
			representing ranges to check
	"""
	ranges = []
	multiplier = 256 / num_threads
	for marker in range(0, num_threads):
		starting_class_a = (marker * multiplier)
		ending_class_a = ((marker +1) * multiplier) - 1
		ranges.append(('%d.0.0.0' % starting_class_a,
						'%d.255.255.255' % ending_class_a))
	return ranges

def get_netranges(starting_ip = '1.0.0.0',
					last_ip='2.0.0.0',
					elastic_search_url='http://127.0.0.1:9200/',
					index_name='netblocks',
					doc_name='netblock', sleep_min=1, sleep_max=5):
	"""
	gets the end of the cidr
	- again all of the heavy lifting has handled by these
		ipaddress module

	Parameters:
		asn_cidr (str): the ASN CIDR string from the whois data
	"""
	connection = ElasticSearch(elastic_search_url)
	current_ip = starting_ip

	while True:
		# See if we've finished the range of work
		if ipaddress.ip_network(current_ip) > ipaddress.ip_network(last_ip):
			return

		print("{0}".format(current_ip))

		whois_resp = ipwhois.IPWhois(current_ip).lookup_rdap()

		if 'asn_cidr' in whois_resp and \
			whois_resp['asn_cidr'] is not None and \
			whois_resp['asn_cidr'].count('.') == 3:
			last_netrange_ip = get_netrange_end(whois_resp['asn_cidr'])
		else:
			last_netrange_ip = \
				whois_resp['nets'][0]['range'].split('-')[-1].strip()
			assert last_netrange_ip.count('.') == 3

		assert last_netrange_ip is not None and \
			last_netrange_ip.count('.') == 3, \
			'Unable to find last netrange ip for %s: %s' % (current_ip,
															whois_resp)
		# a bunch of elasticsearch stuff we'll get to

		if current_ip is None:
			return # No more undefined ip addresses

		gevent.sleep(randint(sleep_min, sleep_max))

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

		for starting_ip, ending_ip in \
			break_up_ipv4_address_space(args.num_threads):
			print("Start: {0} End: {1}".format(starting_ip, \
				ending_ip))

			#addr = u'24.255.255.255'
			print("addr is a type {0}".format(type(starting_ip.decode('utf-8'))))
			starting_ip = ipaddress.ip_address(starting_ip.decode('utf-8'))
			#print(str(dir(starting_ip)))
			print("Starting IP: {0}, Next IP: {1}".format(starting_ip, \
				starting_ip + 1))

		get_netranges(starting_ip, ending_ip, args.elastic_url, \
			args.elastic_index, args.elastic_doc, args.sleep_min, \
			args.sleep_max)

	elif 'stats' in args.action:
		print("Got action stats.")
		pass
	else:
		print("Got undefined action: {0}".format(args.action))

if __name__=='__main__':
	main()
