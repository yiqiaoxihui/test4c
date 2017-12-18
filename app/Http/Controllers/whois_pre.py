import re
import os
import socket
import struct
import hashlib
import sys  
from pymongo import MongoClient

'''
author:liuyang
date:2017/12/16 20:15
desrc:read the raw whois data,extract the beginip,endip and data,insert into mongodb
'''

def md5(str):
    import hashlib
    m = hashlib.md5()  
    m.update(str)
    return m.hexdigest()

def ip_n_to_ip(ip_num):
	#192.1.2.3/20
	#print ip_num
	i=ip_num[0].count('.')
	if i==1:
		ip=ip_num[0]+'.0.0'
	elif i==2:
		ip=ip_num[0]+'.0'
	elif i==0:
		ip=ip_num[0]+'.0.0.0'
	else:
		ip=ip_num[0]
	#print ip
	if int(ip_num[1])<32 and int(ip_num[1])>0:
		#print ip_num[1]
		ip_begin=""
		ip_end=""
		ip_int=int(ip_num[1])/8
		ip_rem=int(ip_num[1])%8
		elements=ip.split('.')
		for i in range(0,ip_int):
			ip_begin=ip_begin+elements[i]+'.'
			ip_end=ip_end+elements[i]+'.'
			#print ip_begin
			#print ip_end
		ip_begin=ip_begin+str(int(elements[ip_int])&(~((1<<(8-ip_rem))-1)))
		ip_end=ip_end+str(int(elements[ip_int])|((1<<(8-ip_rem))-1))
		if ip_int<3:
			for i in range(ip_int+1,4):
				ip_begin=ip_begin+'.'+'0'
				ip_end=ip_end+'.'+'255'
		return ip_begin,ip_end
	elif int(ip_num[1])==32:
		return ip,ip
	else:
		return '0.0.0.0','0.0.0.0'
#def is_real_ip_range(content,):

#deal the ip which like 1.01.02.03
def deal_abnormal_ip(ip_begin,ip_end):
	ip_begin_arr=ip_begin.split('.')
	ip_end_arr=ip_end.split('.')
	temp=[]
	for c in ip_begin_arr:
		c=str(int(c))
		temp.append(c)
	ip_begin='.'.join(temp)
	temp=[]
	for c in ip_end_arr:
		c=str(int(c))
		temp.append(c)
	ip_end='.'.join(temp)
	return ip_begin,ip_end

def ip_to_number(raw_ip_begin,raw_ip_end):
	#the ip may be not normal
	try:
		ip_begin_num=socket.ntohl(struct.unpack("I",socket.inet_aton(str(raw_ip_begin)))[0])
		ip_end_num=socket.ntohl(struct.unpack("I",socket.inet_aton(str(raw_ip_end)))[0])
	except Exception as e:
		ip_begin,ip_end=deal_abnormal_ip(raw_ip_begin,raw_ip_end)
		ip_begin_num=socket.ntohl(struct.unpack("I",socket.inet_aton(str(ip_begin)))[0])
		ip_end_num=socket.ntohl(struct.unpack("I",socket.inet_aton(str(ip_end)))[0])
	return ip_begin_num,ip_end_num
def whois_insert(ip_begin,ip_end,content,hash):
	global my_mongo
	content=content.decode("unicode_escape")
	my_mongo.insert({"ip_begin":ip_begin,"ip_end":ip_end,"content":content,"hash":hash})
#some raw whois data maybe include more accurate ip whois info,
#this function can find the most accurate ip whois info
def get_accurate_whois_info(raw_content):
	useful_object_list=[
		r'inetnum {0,1}: {0,1}\d{1,3}\.\d{1,3}',
		r'NetRange {0,1}: {0,1}\d{1,3}\.\d{1,3}',
		r'Network Number {0,}\] {0,1}\d{1,3}\.\d{1,3}',
		r'IPv4 Address {0,}: {0,1}\d{1,3}\.\d{1,3}'
	]
	use_content=""
	object_item_list=raw_content.split("\n\n")
	for object_item in object_item_list:
		for useful_object in useful_object_list:
			ip_range=re.findall(useful_object,object_item)
			if len(ip_range)>0:
				#print "count:"+str(len(ip_range))+":"+ip_range[0]
				use_content=raw_content[raw_content.find(object_item):]

	use_content=use_content.strip()
	return use_content
def whois_insert(ip_begin,ip_end,content,hash):
	global my_mongo
	content=content.decode("unicode_escape")
	my_mongo.insert({"ip_begin":ip_begin,"ip_end":ip_end,"content":content,"hash":hash})
	
def main():
	conn=MongoClient('127.0.0.1',27017)
	db=conn.ly
	global my_mongo
	my_mongo=db.whois3
	arg = 'whois '+sys.argv[1]
	query_result=os.popen(arg)
	data=""
	for line in query_result:
		if (line[0]=='%' or line[0]=='#'):    	#delete unnecessary info
			continue
		data=data+line
	data=re.sub("\n{3,}","\n\n",data)
	data=re.sub(" {2,}", " ", data)
	data=data.strip()							#delete whitespace in head or tail
	data=data.replace("\n","\\n")
	raw_content=data
	if raw_content=='':
		print "query nothing"
		return
	use_content=""
	use_content=get_accurate_whois_info(raw_content)
	print use_content
	#the netrange reg rule:
	#(\d+.\d+.\d+.\d+) - (\d+.\d+.\d+.\d+)
	#x.x.x.x/n
	#x.x.x/n
	#x.x/n
	ip_range_regs=[
	r'(?:inetnum {0,1}: {0,1}|Network Number {0,}\] {0,1}|NetRange {0,1}: {0,1}|IPv4 Address {0,1}: {0,1})((?:(?:1[0-9][0-9]\.)|(?:2[0-4][0-9]\.)|(?:25[0-5]\.)|(?:0{0,3}[1-9][0-9]\.)|(?:0{0,3}[0-9]\.)){3}(?:(?:1[0-9][0-9])|(?:2[0-4][0-9])|(?:25[0-5])|(?:0{0,3}[1-9][0-9])|(?:0{0,3}[0-9]))) {0,1}- {0,1}((?:(?:1[0-9][0-9]\.)|(?:2[0-4][0-9]\.)|(?:25[0-5]\.)|(?:0{0,3}[1-9][0-9]\.)|(?:0{0,3}[0-9]\.)){3}(?:(?:1[0-9][0-9])|(?:2[0-4][0-9])|(?:25[0-5])|(?:0{0,3}[1-9][0-9])|(?:0{0,3}[0-9])))',
	r'(?:inetnum {0,1}: {0,1}|Network Number {0,}\] {0,1}|NetRange {0,1}: {0,1}|IPv4 Address {0,1}: {0,1})((?:(?:1[0-9][0-9]\.)|(?:2[0-4][0-9]\.)|(?:25[0-5]\.)|(?:0{0,3}[1-9][0-9]\.)|(?:0{0,3}[0-9]\.)){3}(?:(?:1[0-9][0-9])|(?:2[0-4][0-9])|(?:25[0-5])|(?:0{0,3}[1-9][0-9])|(?:0{0,3}[0-9])))\/((?:[1-2][0-9])|(?:3[0-2])|[0-9])',
	r'(?:inetnum {0,1}: {0,1}|Network Number {0,}\] {0,1}|NetRange {0,1}: {0,1}|IPv4 Address {0,1}: {0,1})((?:(?:1[0-9][0-9]\.)|(?:2[0-4][0-9]\.)|(?:25[0-5]\.)|(?:0{0,3}[1-9][0-9]\.)|(?:0{0,3}[0-9]\.)){2}(?:(?:1[0-9][0-9])|(?:2[0-4][0-9])|(?:25[0-5])|(?:0{0,3}[1-9][0-9])|(?:0{0,3}[0-9])))\/((?:[1-2][0-9])|(?:3[0-2])|[0-9])',
	r'(?:inetnum {0,1}: {0,1}|Network Number {0,}\] {0,1}|NetRange {0,1}: {0,1}|IPv4 Address {0,1}: {0,1})((?:(?:1[0-9][0-9]\.)|(?:2[0-4][0-9]\.)|(?:25[0-5]\.)|(?:0{0,3}[1-9][0-9]\.)|(?:0{0,3}[0-9]\.)){1}(?:(?:1[0-9][0-9])|(?:2[0-4][0-9])|(?:25[0-5])|(?:0{0,3}[1-9][0-9])|(?:0{0,3}[0-9])))\/((?:[1-2][0-9])|(?:3[0-2])|[0-9])'
	]
	flag=0
	for ip_range_reg in ip_range_regs:
		ip_range=re.findall(ip_range_reg,use_content)
		if ip_range!=[]:
			flag=1
			if ip_range_regs.index(ip_range_reg)>0:
				ip_begin,ip_end=ip_n_to_ip(ip_range[0])
			else:
				ip_begin=ip_range[0][0]
				ip_end=ip_range[0][1]
			str_ip=str(ip_begin)+'~'+str(ip_end)
			#print str_ip
			ip_begin_num,ip_end_num=ip_to_number(ip_begin,ip_end)
			ip_range_str=str(ip_begin_num)+str(ip_end_num)
			hash=md5(ip_range_str)#skip the same ip range
			#whois_insert(ip_begin_num,ip_end_num,use_content,hash)
main()
