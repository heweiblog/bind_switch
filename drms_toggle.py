#!/usr/bin/python3
# -*- coding: utf-8 -*-

from __future__ import print_function

import os, socket,  sys, re, time, datetime, logging, random, string, logging.handlers, gzip, paramiko
import multiprocessing, subprocess
from threading import Timer
from configparser import ConfigParser
from Crypto.Cipher import AES

from iscpy.iscpy_dns.named_importer_lib import *
import base64, hashlib, zlib, json, lxml.etree, pexpect, dns, dns.resolver, shutil

from time import sleep
import threading, binascii, xml.dom.minidom

from spyne import ServiceBase
from spyne.protocol.soap import Soap11
from spyne.decorator import rpc
from spyne.model.primitive import Integer, Int, Long, Unicode
from spyne.model.complex import Iterable
from spyne.application import Application
from spyne.util.wsgi_wrapper import WsgiMounter
from spyne.util.etreeconv import root_etree_to_dict
from wsgiref.simple_server import make_server

import osa, daemon

class AESCipher:
	def __init__(self, key, iv):
		self.key = key 
		self.iv = iv 
	def __pad(self, text):
		text_length = len(text)
		amount_to_pad = AES.block_size - (text_length % AES.block_size)
		if amount_to_pad == 0:
			amount_to_pad = AES.block_size
		pad = chr(amount_to_pad)
		return text + (pad * amount_to_pad).encode('utf-8')
	def __unpad(self, text):
		pad = text[-1] #ord(text[-1])
		return text[:-pad]
	def encrypt(self, raw):
		raw = self.__pad(raw)
		cipher = AES.new(self.key, AES.MODE_CBC, self.iv)
		return cipher.encrypt(raw)
	def decrypt(self, enc):
		cipher = AES.new(self.key, AES.MODE_CBC, self.iv )
		return self.__unpad(cipher.decrypt(enc))#.decode("utf-8"))

def getXmlValue(dom, root, xpath):
	ml = dom.getElementsByTagName(root)[0]
	node = ml.getElementsByTagName(xpath)[0]
	for n in node.childNodes:
		nodeValue = n.nodeValue
		return nodeValue
	return None


def gen_commandack_result(dnsId, cmdId, cmdType, resultCode):
	xml = u'''\
<?xml version="1.0" encoding="UTF-8"?>
<dnsCommandAck>
    <dnsId>%s</dnsId>
    <commandAck>
        <commandId>%s</commandId>
        <type>%d</type>
        <resultCode>%d</resultCode>
        <appealContent></appealContent>
        <msgInfo></msgInfo>
    </commandAck>
    <timeStamp>%s</timeStamp>
</dnsCommandAck>
''' % (dnsId, cmdId, cmdType, resultCode, time.strftime('%Y-%m-%d %H:%M:%S'))
    
	return xml


def dnsCommandAck(commandType, commandSequence, dnsId, hashAlgorithm, compressionFormat, encryptAlgorithm, resultCode):
	global gPwd, gAESKey, gAESIV, ackhost, ackport, logger

	sleep(1) 
	result = bytes(gen_commandack_result(dnsId, commandSequence, commandType, 0 if resultCode==0 else 2), encoding = 'utf-8')
	randVal = bytes(''.join(random.sample(string.ascii_letters, 20)), 'utf-8')
	lPwd = bytes(gPwd,'utf-8')

	if hashAlgorithm == 0: 
		_hashed_pwd = lPwd + randVal
		pwdHash = base64.b64encode(_hashed_pwd)
	elif hashAlgorithm == 1: 
		_hashed_pwd = hashlib.md5(lPwd + randVal).digest()
		pwdHash = base64.b64encode(binascii.b2a_hex(_hashed_pwd))
	elif hashAlgorithm == 2: 
		_hashed_pwd = hashlib.sha1(lPwd + randVal).digest()
		pwdHash = base64.b64encode(binascii.b2a_hex(_hashed_pwd))

	if compressionFormat == 0: _compressed_result = result
	elif compressionFormat == 1: _compressed_result = zlib.compress(result)

	e = AESCipher(gAESKey, gAESIV)
	if (gAESKey is not None) and (encryptAlgorithm == 1): 
		_encrypted_result = e.encrypt(_compressed_result)
	else: _encrypted_result = _compressed_result
    
	result = base64.b64encode(_encrypted_result)

	if hashAlgorithm == 0: 
		_hashed_result = _compressed_result + lPwd
		resultHash = base64.b64encode(_hashed_result)
	elif hashAlgorithm == 1: 
		_hashed_result = hashlib.md5(_compressed_result + lPwd).digest()
		resultHash = base64.b64encode(binascii.b2a_hex(_hashed_result))
	elif hashAlgorithm == 2: 
		_hashed_result = hashlib.sha1(_compressed_result + lPwd).digest()
		resultHash = base64.b64encode(binascii.b2a_hex(_hashed_result))

	commandVersion = 'v0.1'

	cl = osa.Client('http://%s:%d/DNSWebService/dnsCommandAck?wsdl' % (ackhost, ackport))
    
	try:
		r = cl.service.dns_commandack(dnsId, str(randVal, encoding='utf-8'), 
		str(pwdHash,encoding='utf-8'), str(result,encoding = 'utf-8'),
		str(resultHash,encoding='utf-8'), encryptAlgorithm, hashAlgorithm,compressionFormat, commandVersion)

		dom = xml.dom.minidom.parseString(r)
		if int(getXmlValue(dom, "return", "resultCode")) == 0:
			logger.info('return to drms dnsCommandAck success')
		else:
			logger.error('return to drms dnsCommandAck failed')

	except Exception as e:
		l = str(e).split('/')
		if 'tmp' in l:
			d = '/tmp/' + l[-2]
			if os.path.exists(d) == False:
				os.mkdir(d)
				logger.info('mkdir '+d+' and copy /var/drms_toggle_data/base_library.zip')
				shutil.copyfile('/var/drms_toggle_data/base_library.zip',d+'/base_library.zip')

			r = cl.service.dns_commandack(dnsId, str(randVal, encoding='utf-8'), 
			str(pwdHash,encoding='utf-8'), str(result,encoding = 'utf-8'),
			str(resultHash,encoding='utf-8'), encryptAlgorithm, hashAlgorithm,compressionFormat, commandVersion)

			dom = xml.dom.minidom.parseString(r)
			if int(getXmlValue(dom, "return", "resultCode")) == 0:
				logger.info('return to drms dnsCommandAck success')
			else:
				logger.error('return to drms dnsCommandAck failed')
		else:
			logger.warning('dnsCommandAck exception:'+str(e))
			return -1


def genResult(rcode, commandType, commandId, dnsId, hashAlgorithm, compressionFormat, encryptAlgorithm):
	lookaside = {
		0 : 'Done',
		1 : 'De-cryption error',
		2 : 'Certification error',
		3 : 'De-compression error',
		4 : 'Invalid type',
		5 : 'Malformed content',
		900 : 'Other error, try again'                                                        
	}
    
	xml = u'''<?xml version="1.0" encoding="UTF-8"?>
	<return>
		<resultCode>%d</resultCode>
		<msg>%s</msg>
	</return>''' % (rcode, lookaside[rcode])
    
	if commandId:    
		threading._start_new_thread(dnsCommandAck, (commandType, commandId, dnsId, hashAlgorithm, compressionFormat, encryptAlgorithm, rcode))

	return xml


def certificate(pwdHash, randVal, hashAlgorithm):                                             
	global gPwd
	if hashAlgorithm == 0: 
		raw = gPwd + randVal 
		return pwdHash == base64.b64encode(raw.encode('utf-8')).decode('utf-8')
	elif hashAlgorithm == 1: raw = hashlib.md5((gPwd + randVal).encode()).digest()
	elif hashAlgorithm == 2: raw = hashlib.sha1((gPwd + randVal).encode()).digest()
	else: return False
	return pwdHash == base64.b64encode(binascii.b2a_hex(raw)).decode()


def aesDecode(raw):
	aes = AESCipher(gAESKey, gAESIV)
	return aes.decrypt(raw)


def deCMDPre(command, compressionFormat, commandHash, hashAlgorithm, encryptAlgorithm):
	global gAESKey, gPwd
	raw = base64.b64decode(command.encode('utf-8'))
	if (gAESKey is not None) and (encryptAlgorithm == 1):
		data = aesDecode(raw)
	else: data = raw
	if hashAlgorithm == 0: hashed = data + gPwd.encode('utf-8')
	elif hashAlgorithm == 1: hashed = hashlib.md5((data + gPwd.encode('utf-8'))).digest()
	elif hashAlgorithm == 2: hashed = hashlib.sha1((data + gPwd.encode('utf-8'))).digest()
	else: return None
	if hashAlgorithm == 0:
		if base64.b64encode(hashed).decode('utf-8') != commandHash:
			return None
	else:
		if base64.b64encode(binascii.b2a_hex(hashed)).decode('utf-8') != commandHash:
			return None
	if compressionFormat == 0: cmd = data
	elif compressionFormat == 1: cmd = zlib.decompress(data)
	return cmd


def xmlget(root, xpath):
	lst = root.xpath(xpath)
	if lst and lst[0].text:
		return lst[0].text
	return None


def switch_named_file(target,source):
	global home, rndc, logger

	if os.path.exists(home+"/"+target) == False:
		logger.error('[%d] file[%s] not exist error!' % os.getpid(),target)
		return False

	try:
		subprocess.check_call(['ln', '-f', '-s', target, source], cwd = home)
	except subprocess.CalledProcessError:
		logger.error('[%d] create link path error!' % os.getpid())
		return False

	try:
		subprocess.check_call([rndc, 'reconfig'], cwd = home)
	except subprocess.CalledProcessError:
		logger.error('[%d] rndc reconfig error!' % os.getpid())
		return False

	try:
		subprocess.check_call([rndc, 'flush'], cwd = home)
	except subprocess.CalledProcessError:
		logger.error('[%d] rndc flush error!' % os.getpid())
		return False

	logger.warn('[%d] root switch to `%s`' % (os.getpid(), target))
	return True


def switch_rootca(stdon, delay, dnsId, commandType, commandId, hashAlgorithm, compressionFormat, encryptAlgorithm):
	global std, local, logger, switch

	def __do_command(target):
		if switch_named_file(target,switch):
			return genResult(0, commandType, commandId, dnsId, hashAlgorithm, compressionFormat, encryptAlgorithm)
		return genResult(900, commandType, commandId, dnsId, hashAlgorithm, compressionFormat, encryptAlgorithm)

	logger.warning('[%d] root direction will switch in %d seconds' % (os.getpid(), delay))
	Timer(delay, __do_command, ((std if stdon else local, ))).start()


def switch_root_source(is_exigency, delay, dnsId, commandType, commandId, hashAlgorithm, compressionFormat, encryptAlgorithm):
	global standard_source, exigency_source, logger, root_source

	def __do_command(target):
		if switch_named_file(target,root_source):
			return genResult(0, commandType, commandId, dnsId, hashAlgorithm, compressionFormat, encryptAlgorithm)
		return genResult(900, commandType, commandId, dnsId, hashAlgorithm, compressionFormat, encryptAlgorithm)

	logger.warning('[%d] root source will switch in %d seconds' % (os.getpid(), delay))
	Timer(delay, __do_command, ((exigency_source if is_exigency else standard_source, ))).start()


def respond18(cmd, commandType, dnsId, hashAlgorithm, compressionFormat, encryptAlgorithm):
	global logger

	ele = lxml.etree.fromstring(cmd)
	_commandId = xmlget(ele, 'commandId')
	_type = xmlget(ele, 'type')
	_urgency = xmlget(ele, 'urgency')
	_effectiveScope = xmlget(ele, 'range/effectiveScope')
	_check = xmlget(ele, 'privilege/check')
	_timestamp = xmlget(ele, 'timeStamp')
	_datasources = xmlget(ele, 'datasources')
	
	if _type != None:
		logger.info('switch root.ca type=%s' % _type)
		switch_rootca(True if _type != '1' else False, 
			(2 * 60 * 60) if _urgency == '1' else (10 * 60), 
			dnsId, 8, _commandId, hashAlgorithm, 
			compressionFormat, encryptAlgorithm)

	if _datasources != None:
		logger.info('switch root source datasources=%s' % _datasources)
		switch_root_source(True if _datasources != '1' else False, 
			(2 * 60 * 60) if _urgency == '1' else (10 * 60), 
			dnsId, 8, _commandId, hashAlgorithm, 
			compressionFormat, encryptAlgorithm)


class DRMSService(ServiceBase):
	@rpc(Unicode, Unicode, Unicode, Unicode, Unicode,Int, Long, Int, Int, 
		Int,Unicode, _out_variable_name = 'return', _returns = Unicode)

	def dns_command(ctx, dnsId, randVal, pwdHash, command, commandHash, commandType, 
	commandSequence, encryptAlgorithm, hashAlgorithm, compressionFormat, commandVersion):
		global logger
		try:
			if not certificate(pwdHash, randVal, hashAlgorithm):
				logger.error('certificate error')
				return genResult(2, commandType, None, dnsId, hashAlgorithm, compressionFormat, encryptAlgorithm) 
			cmd = deCMDPre(command, compressionFormat, commandHash,hashAlgorithm, encryptAlgorithm)
			if not cmd:
				logger.error("webService Malformed content do deCMDPre error")
				return genResult(5, commandType, None, dnsId, hashAlgorithm, compressionFormat, encryptAlgorithm)

			command_func = {18:respond18}
			if commandType in command_func:
				return command_func[commandType](cmd, commandType, dnsId, hashAlgorithm, compressionFormat, encryptAlgorithm)
		except Exception as e: 
			logger.error('command error:'+str(e))
			return genResult(900, commandType, None, dnsId, hashAlgorithm, compressionFormat, encryptAlgorithm)
        

def get_transfer_ip_and_delay(soa):
	global run_file,logger

	target = 'serial ' + str(soa)
	try:
		with open(run_file) as f:
			l = f.readlines()
			for i in range(len(l)):
				if l[i].find(target) > 0:
					for v in l[i:]:
						if v.find('Transfer completed') > 0:
							res = v
							return int(1000*float(_res.split(', ')[-1].split(' ')[0])) , res.split('#')[0].split(' ')[-1]

	except Exception as e:
		logger.warning('get transfer ip and delay error:'+str(e))
	return 0,'0.0.0.0'
		

def get_server_from_file():
	global root_source, home, logger
	root_source_file = home + '/' + root_source
	try:
		with open(root_source_file, 'r') as f:
			data = f.read()
			named_data = MakeNamedDict(data)
			servers = named_data['orphan_zones']['.']['options']['masters']
			server = ''
			for ip in servers:
				server += ip + ','
			return server[:-1]

	except Exception as e:
		logger.warning('get server from swotch_root.zone error:'+str(e))

	return ''


def get_transfer_ip_and_delay_from_file(soa):
	global root_source, home, logger
	root_source_file = home + '/' + root_source
	try:
		with open(root_source_file, 'r') as f:
			data = f.read()
			named_data = MakeNamedDict(data)
			servers = named_data['orphan_zones']['.']['options']['masters']
			dns_query = dns.message.make_query('.', 'SOA')
			for ip in servers:
				begin = datetime.datetime.now()
				res = dns.query.udp(dns_query, ip, port = 53,timeout = 2)
				end = datetime.datetime.now()
				for i in res.answer:
					for j in i.items:
						if j.serial == soa:
							return (end - begin).microseconds//1000,ip
	except Exception as e:
		logger.warning('get transfer ip and delay from swotch_root.zone error:'+str(e))
	return 0,'0.0.0.0'


def get_root_file_size():
	global root_source, home, logger
	root_source_file = home + '/' + root_source
	try:
		with open(root_source_file, 'r') as f:
			data = f.read()
			named_data = MakeNamedDict(data)
			return os.path.getsize('/var/named/'+named_data['orphan_zones']['.']['file'])
	except Exception as e:
		logger.warning('get root_copy file size error:'+str(e))
	return 0


def get_root_copy_soa():
	global logger
	try:
		dns_query = dns.message.make_query('.', 'SOA')
		res = dns.query.udp(dns_query, '127.0.0.1', port = 53,timeout = 2)
		for i in res.answer:
			for j in i.items:
				return j.serial
	except Exception as e:
		logger.warning('get root copy soa error:'+str(e))
	return 0


def get_root_copy_run_data():
	result = 'get source or size error'
	soa = get_root_copy_soa()
	if soa == 0:
		result = 'get soa serial error'
		
	delay,ip = get_transfer_ip_and_delay(soa)
	if delay == 0 and ip == '0.0.0.0': 
		delay,ip = get_transfer_ip_and_delay_from_file(soa)
	size = get_root_file_size()
	if delay != 0 and ip != '0.0.0.0' and size != 0:
		result = 'success'

	server = get_server_from_file()
	
	soa_data = {
		'ip' : server,
		'source': ip,
		'result': result,
		'size': size,
		'soa': soa,
		'delay': delay
	}

	return soa_data


def get_root_copy_list():
	global local, home, logger
	root_local_file = home + '/' + local
	try:
		with open(root_local_file, 'r') as f:
			data = f.read()
			named_data = MakeNamedDict(data)
			servers = named_data['orphan_zones']['.']['options']['server-addresses']
			root_copy_list = ''
			for k in servers:
				root_copy_list += k +','
			return root_copy_list[:-1]
				
	except Exception as e:
		logger.error('get root copy list error:'+str(e))
	return ''

def handle_connect(sock,addr):
	global dnstap_file,logger
	target_file = '/tmp/zone.txt'
	try:
		data = sock.recv(1024)
		if data:
			content = data.decode('utf-8')
			if content == 'root_copy_run_data' :
				logger.info('recv msg: get root copy run data!!!')
				run_data = get_root_copy_run_data()
				text = json.dumps(run_data)
				sock.send(text.encode())
				logger.info('send root copy run data: '+text)
			elif content == 'recursion_root_copy_list' :
				logger.info('recv get recursion root copy list')
				text = get_root_copy_list()
				sock.send(text.encode())
				logger.info('send recursion root copy list: '+text)
			else:
				logger.info('recv get dnstap info')
				try:
					with open(target_file,'w') as f:
						subprocess.check_call(['dnstap-read',dnstap_file],stdout=f, cwd = '.')
					with open(target_file,'r') as f:
						for l in f:
							sock.send(l.encode())
				except Exception as e:
					logger.warning('dnstap read info to file error:'+str(e))
		sock.close()
	except Exception as e:
		logger.warning('send dnstap info error:'+str(e))
		

def upload_dnstap_file():
	global logger,transport
	s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
	s.bind(('0.0.0.0',transport))
	s.listen(5)
	while True:
		sock,addr = s.accept()
		t = threading.Thread(target=handle_connect, args=(sock, addr))
		t.start()


def main_task():
	global listen_port

	application = Application([DRMSService],'http://webservice.ack.dns.act.com/', 
			in_protocol = Soap11(validator = 'lxml'), 
			out_protocol = Soap11())

	wsgi_app = WsgiMounter({'DNSWebService' : application})
	server = make_server('0.0.0.0', listen_port, wsgi_app)
	server.serve_forever()

try:
	config = ConfigParser()
	config.read('/etc/drms_toggle.ini')
	listen_port = config.getint('network', 'port')
	ackhost = config.get('network', 'ackhost')
	ackport = config.getint('network', 'ackport')
	transport = config.getint('network', 'transport')

	gPwd = config.get('security', 'secret')
	gAESKey = config.get('security', 'aes_key')
	gAESIV = config.get('security', 'aes_iv')

	home = config.get('named-conf', 'home')
	rndc = config.get('named-conf', 'rndc')
	switch = config.get('named-conf', 'switch')
	std = config.get('named-conf', 'std')
	local = config.get('named-conf', 'local')
	run_file = config.get('named-conf', 'run_file')
	dnstap_file = config.get('named-conf', 'dnstap_file')

	root_source = config.get('source', 'root_source')
	standard_source = config.get('source', 'standard_source')
	exigency_source = config.get('source', 'exigency_source')


except Exception as e:
	print('load conf or create log error:'+str(e))
	sys.exit(1)


with daemon.DaemonContext():
	logger = logging.getLogger('drms_toggle')
	logger.setLevel(level = logging.INFO)
	handler = logging.FileHandler("/var/log/drms_toggle.log")
	handler.setLevel(logging.INFO)
	formatter = logging.Formatter('%(asctime)s - %(lineno)s - %(levelname)s - %(message)s')
	handler.setFormatter(formatter)
	logger.addHandler(handler)

	logger.info('main process start at: %s' % time.ctime())

	while True:
		p = multiprocessing.Process(target = main_task, args = ())
		p1 = multiprocessing.Process(target = upload_dnstap_file, args = ())
		p.start()
		p1.start()
		p.join()
		p1.join()

	logger.info('main process end at: %s' % time.ctime())
 

