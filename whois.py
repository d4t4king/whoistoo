#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
IPv4 Whois data collection and analysis tool

"""

import json
import netaddr
import pprint
import gevent
import ipcalc
import ipwhois
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
		help="URL for the elasticsearch server, including port.", \
		default='http://127.0.0.1:9200')
	p.add_argument('-i', '--elastic-index', dest='elastic_index', \
		help="Eleasticsearch document index.", \
		default='netranges')
	p.add_argument('-d', '--elastic-doc', dest='elastic_doc', \
		help="Elasticsearch document name.", default='netrange')
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
	if 'IPv4Address' in str(type(_ipaddress)):
		return str(_ipaddress + 1)
	elif 'unicode' in str(type(_ipaddress)):
		return str(ipaddress.ip_address(_ipaddress) + 1)
	elif 'str' in str(type(_ipaddress)):
		return str(ipaddress.ip_address(_ipaddress.decode('utf-8')) + 1)
	else:
		raise TypeError("Unrecognized type given for _ipaddress: {0}".format(type(_ipaddress)))

def get_netrange_end(asn_cidr):
	"""
	gets the last address in the cidr

	Parameters:
		asn_cidr (str): ASN CIDR

	Returns:
		ip (str): last IP address in cidr
	"""
	return ipaddress.ip_network(asn_cidr.decode('utf-8')).broadcast_address

def get_next_undefined_address(ip):
	"""
	get the next non-private IPv4 address if the address sent is private

	Parameters:
		ip (str): IPv4 address

	Returns:
		rip (str): IPv4 address of net non-private address
	"""

	if 'str' not in str(type(ip)):
		ip = str(ip)

	try:
		# Should weed out any invalid IP Addresses
		ipcalc.Network(ip)
	except ValueError as err:
		return None

	defined_networks = (
		'0.0.0.0/8',
		'10.0.0.0/8',
		'127.0.0.0/8',
		'169.254.0.0/16',
		'192.0.0.0/24',
		'192.0.2.0/24', 
		'192.88.99.0/24',
		'192.168.0.0/16',
		'198.18.0.0/15',
		'198.51.100.0/20',
		'203.0.113.0/24',
		'224.0.0.0/4',
		'240.0.0.0/4',
		'255.255.255.255/32',
	)

	for network_cidr in defined_networks:
		if ip in ipcalc.Network(network_cidr):
			return get_next_ip(get_netrange_end(network_cidr))

	return ip

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
	print("EleasticSearch URL: {0}".format(elastic_search_url))
	connection = ElasticSearch(elastic_search_url)
	current_ip = starting_ip

	# debugging
	pp = pprint.PrettyPrinter(indent=4)

	print("DEBUG: Starting loop...")
	while True:
		#print("Current IP: {0}, Last IP: {1}".format(type(current_ip), \
		#	type(last_ip)))
		print("DEBUG: in loop")
		# See if we've finished the range of work
		if ipaddress.ip_network(str(current_ip).decode('utf-8')) > \
			ipaddress.ip_network(last_ip.decode('utf-8')):
			print("DEBUG: current ip bigger than last ip.  Batch done.")
			return

		current_ip = get_next_undefined_address(current_ip)

		print("{0}".format(current_ip))

		whois_resp = ipwhois.IPWhois(current_ip).lookup_rdap(asn_methods=['whois','http'])

		last_netrange_ip = ''
		if 'asn_cidr' in whois_resp and \
			whois_resp['asn_cidr'] is not None and \
			whois_resp['asn_cidr'].count('.') == 3:
			last_netrange_ip = get_netrange_end(whois_resp['asn_cidr'])
		else:
			if 'nets' in whois_resp:
				last_netrange_ip = \
					whois_resp['nets'][0]['range'].split('-')[-1].strip()
			elif 'network' in whois_resp:
				if "," in whois_resp['network']['cidr']:
					# we get a list of CIDRs ("many whelps!!!")
					# handle it!
					pp.pprint(whois_resp['network']['cidr'])
					# first, put the ranges in order, 
					nets = whois_resp['network']['cidr'].split(',')
					pp.pprint(nets)					
					# then get the last IP for the last net
					last_netrange_ip = \
						str(ipaddress.ip_network(
							nets[-1].replace(" ", "").decode('utf-8')
						).broadcast_address).decode('utf-8')
				else:
					last_netrange_ip = \
						str(ipaddress.ip_network(
							whois_resp['network']['cidr'].decode('utf-8')
						).broadcast_address).decode('utf-8')
			else:
				print("Whois response is missing the 'nets' and 'network' keys.")

		assert last_netrange_ip is not None and \
			str(last_netrange_ip).count('.') == 3, \
			'Unable to find last netrange ip for %s: %s' % (current_ip,
															whois_resp)

		# a bunch of elasticsearch stuff we'll get to
		block_size = 0
		if 'asn_cidr' in whois_resp:
			block_size = \
				netaddr.IPNetwork(whois_resp['asn_cidr']).size
		elif 'network' in whois_resp:
			block_size = \
				netaddr.IPNetwork(whois_resp['network']['cidr']).size
		else:
			pp.pprint(whois_resp)
			raise KeyError("No recognizable keys in whois response.")

		entry = {
			"netblock_start": current_ip, 
			"neblock_end": last_netrange_ip,
			"block_size": block_size,
			"whois": json.dumps(whois_resp),
		}

		# need to figure out a way to determin which data set we've got
		# I don't know if it's the same for http or whois asn_methods.
		keys = ('cidr', 'name', 'handle', 'range', 'description',
			'country', 'state', 'city', 'address', 'postal_code', 
			'abuse_emails', 'tech_emails', 'misc_emails', 'created',
			'updated')

		if 'net' in whois_resp:
			for _key in keys:
				entry[_key] = str(whois_resp['nets'][0][_key]) \
					if _key in whois_resp['net'][0] and \
						whois_resp['nets'][0][_key] else None

				if _key == 'city' and entry[_key] and ' ' in entry[_key]:
					entry[_key] = entry[_key].replace(' ', '_')
		elif 'network' in whois_resp:
			for _key in keys:
				entry[_key] = str(whois_resp['network'][_key]) \
					if _key in whois_resp['network'] and \
						whois_resp['network'][_key] else None

				if _key == 'city' and entry[_key] and ' ' in entry[_key]:
					entry[_key] = entry[_key].replace(' ', '_')

		try:
			connection.index(index_name, doc_name, entry)
		except ElasticHttpError as err:
			print('At %s.  Unable to save record: %s' % (current_ip, entry))
			raise error

		print("DEBUG: last_netrange_ip={0}".format(last_netrange_ip))
		current_ip = get_next_ip(last_netrange_ip)

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
			#print("addr is a type {0}".format(type(starting_ip.decode('utf-8'))))
			starting_ip = ipaddress.ip_address(starting_ip.decode('utf-8'))
			#print(str(dir(starting_ip)))
			#print("Starting IP: {0}, Next IP: {1}".format(starting_ip, \
			#	starting_ip + 1))

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
