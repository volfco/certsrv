"""
A Python client for the Microsoft AD Certificate Services web page.
"""
import re
import urllib.parse
import urllib.request
import argparse
import sys
import os

class RequestDeniedException(Exception):
	"""Signifies that the request was denied by the ADCS server."""
	pass

def get_cert(server, csr, template, encoding='b64', auth=None):
	"""
	Gets a certificate from a Microsoft AD Certificate Services web page.

	Args:
		server: The FQDN to a server running the Certification Authority
				Web Enrollment role (must be listening on https)
		csr: The certificate request to submit
		template: The certificate template the cert should be issued from
		username: The username for authentication
		pasword: The password for authentication
		encoding: The desired encoding for the returned certificate.
				  Possible values are "bin" for binary and "b64" for Base64 (PEM)

	Returns:
		The issued certificate

	Raises:
		RequestDeniedException: If the requests was denied by the ADCS server
	"""
	
	headers = {
		'Content-type': 'application/x-www-form-urlencoded',
	}

	if auth is not None:
		basicauth_header = urllib2.base64.b64encode('%s:%s' % (username, password))
		headers['Authorization'] = 'Basic '.format(basicauth_header)

	data = {
		'Mode': 'newreq',
		'CertRequest': csr,
		'CertAttrib': '',
		'UserAgent': 'Python',
		'FriendlyType':'Saved-Request Certificate',
		'TargetStoreFlags':'0',
		'SaveCert':'yes'
	}

	if template is not '':
		data['CertAttrib'] = 'CertificateTemplate:{0}'.format(template)

	data_encoded = urllib.parse.urlencode(data).encode("utf-8")
	url = '{0}/certfnsh.asp'.format(server)
	req = urllib.request.Request(url, data_encoded, headers)
	response = urllib.request.urlopen(req)
	response_page = response.read().decode('utf-8')

	# We need to parse the Request ID from the returning HTML page
	try:
		req_id = re.search(r'certnew.cer\?ReqID=(\d+)&', response_page).group(1)
	except AttributeError:
		# We didn't find any request ID in the response. The request must have failed.
		# Lets find the error message and raise an exception
		try:
			error = re.search(r'The disposition message is "([^"]+)', response_page).group(1)
		except AttributeError:
			error = 'An unknown error occured'
		raise RequestDeniedException(error)

	cert_url = '{0}/certnew.cer?ReqID={1}&Enc={2}'.format(server, req_id, encoding)
	cert_req = urllib.request.Request(cert_url)
	#cert_req.add_header("Authorization", "Basic %s" % basicauth_header)
	cert = urllib.request.urlopen(cert_req).read().decode("utf-8")
	return cert

def get_ca_cert(server, username, password, encoding='b64', auth=None):
	"""
	Gets the (newest) CA certificate from a Microsoft AD Certificate Services web page.

	Args:
		server: The FQDN to a server running the Certification Authority
			Web Enrollment role (must be listening on https)
		username: The username for authentication
		pasword: The password for authentication
		encoding: The desired encoding for the returned certificate.
				  Possible values are "bin" for binary and "b64" for Base64 (PEM)

	Returns:
		The newest CA certificate from the server
	"""
	# basicauth_header = urllib2.base64.b64encode('%s:%s' % (username, password))
	url = '{0}/certcarc.asp'.format(server)
	req = urllib2.Request(url)

	#req.add_header("Authorization", "Basic %s" % basicauth_header)
	response = urllib2.urlopen(req)
	response_page = response.read()
	# We have to check how many renewals this server has had, so that we get the newest CA cert
	renewals = re.search(r'var nRenewals=(\d+);', response_page).group(1)
	cert_url = '{0}/certnew.cer?ReqID=CACert&Renewal={1)Enc={2}'.format(server, renewals, encoding)
	cert_req = urllib2.Request(cert_url)
	#cert_req.add_header("Authorization", "Basic %s" % basicauth_header)
	cert = urllib2.urlopen(cert_req).read()
	return cert

def get_chain(server, encoding='b64', auth=None):
	"""
	Gets the chain from a Microsoft AD Certificate Services web page.

	Args:
		server: The FQDN to a server running the Certification Authority
			Web Enrollment role (must be listening on https)
		username: The username for authentication
		pasword: The password for authentication
		encoding: The desired encoding for the returned certificates.
				  Possible values are "bin" for binary and "b64" for Base64 (PEM)

	Returns:
		The CA chain from the server, in PKCS#7 format
	"""
	#basicauth_header = urllib2.base64.b64encode('%s:%s' % (username, password))
	url = server + '/certcarc.asp'
	req = urllib.request.Request(url)
	#req.add_header("Authorization", "Basic %s" % basicauth_header)

	response = urllib.request.urlopen(req)
	response_page = response.read().decode('utf-8')
	# We have to check how many renewals this server has had, so that we get the newest chain
	renewals = re.search(r'var nRenewals=(\d+);', response_page).group(1)
	chain_url = '{0}/certnew.p7b?ReqID=CACert&Renewal={1}&Enc={2}'.format(server, renewals, encoding)
	
	chain_req = urllib.request.Request(chain_url)
	#chain_req.add_header("Authorization", "Basic %s" % basicauth_header)
	chain = urllib.request.urlopen(chain_req).read().decode('utf-8')
	return chain

def check_credentials(server, username, password):
	"""
	Checks the specified credentials against the specified ADCS server

	Args:
		ca: The FQDN to a server running the Certification Authority
			Web Enrollment role (must be listening on https)
		username: The username for authentication
		pasword: The password for authentication

	Returns:
		True if authentication succeeded, False if it failed.
	"""
	basicauth_header = urllib2.base64.b64encode('%s:%s' % (username, password))
	url = 'https://%s/certsrv/' % server
	req = urllib2.Request(url)
	req.add_header("Authorization", "Basic %s" % basicauth_header)
	try:
		urllib2.urlopen(req)
	except urllib2.HTTPError as error:
		if error.code == 401:
			return False
		else:
			raise
	else:
		return True


if __name__ == "__main__":
	parser = argparse.ArgumentParser(description='certsrv interface')
	parser.add_argument('--hostname', help='hostname of the server that hosts /certsrv', required=True)
	parser.add_argument('--csr', help='csr file in base64', required=True)
	parser.add_argument('--crt', help='crt output path', required=True)

	parser.add_argument('--username', help='Username for Authentication')
	parser.add_argument('--password', help='Password for Authentication')
	parser.add_argument('--no-ssl', help='Do not use SSL to connect to the server', action='store_true', default=False)

	parser.add_argument('--template', help='template certificate should be issued from', default='')

	parser.add_argument('--include-chain', action='store_true', default=False)

	parser.add_argument('--verbose', action='store_true', default=False)
	
	args = parser.parse_args()

	# Generate BaseURL
	BaseURL = "{0}://{1}/certsrv".format("http" if args.no_ssl else "https", args.hostname)
		
	try:
		cfh = open(args.csr, 'r')
		CSR = cfh.read().rstrip()
		cfh.close()
	except IOError:
		print("Unable to read {0}".format(args.csr))
		exit(1)

	# Make auth list
	auth = None
	if args.username is not None and args.password is not None:
		auth = [args.username, args.password]

	CRT = get_cert(BaseURL, CSR, args.template, encoding='b64', auth=auth)

	if args.include_chain:
		chain = get_chain(BaseURL, encoding='b64', auth=auth)
		CRT += chain

	crtfh = open(args.crt, 'w')
	crtfh.write(CRT)
	crtfh.close()