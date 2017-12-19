import re
import os
import socket
import struct
import hashlib
import json
import collections
import sys  
from pymongo import MongoClient

'''
author:liuyang
date:2017/12/16 20:15
desrc:read the raw whois data,extract the beginip,endip and data,insert into mongodb
'''
all_key=[
'NetRange','CIDR','NetName','NetHandle','Parent','NetType','OriginAS','Organization','RegDate','Updated','Comment','Ref',
'inetnum','aut-num','abuse-c','owner','ownerid','responsible','address',
'netname','descr','country','geoloc','language','org','sponsoring-org','admin-c',
'phone','owner-c','tech-c','status','remarks','notify','mnt-by','mnt-lower','mnt-routes','mnt-domains','mnt-irt',
'inetrev','dns',
'Network Number','Network Name','Administrative Contact','Technical Contact','Nameserver','Assigned Date','Return Date','Last Update',
'IPv4 Address','Organization Name','Network Type','Address','Zip Code','Registration Date'
'created','last-modified','changed','source','parent'
]

RIPE=['inetnum','netname','descr','country','geoloc','language','org','sponsoring-org','admin-c','tech-c','status',
'remarks','notify','mnt-by','mnt-lower','mnt-routes','mnt-domains','mnt-irt','created','last-modified','source']

APNIC=['inetnum','netname','descr','country','geoloc','language','admin-c','tech-c','status',
'remarks','notify','mnt-by','mnt-lower','mnt-routes','mnt-irt','changed','source']

ARIN=['NetRange','CIDR','NetName','NetHandle','Parent','NetType','OriginAS','Organization','RegDate','Updated','Comment','Ref']

LACNIC=['inetnum','aut-num','abuse-c','owner','ownerid','responsible','address','country',
'phone','owner-c','tech-c','status','inetrev','nserver','nsstat','nslastaa','created','changed']

AFRINIC=['inetnum','netname','descr','country','org','admin-c','tech-c','status','remarks','notify',
'mnt-by','mnt-lower','mnt-routes','mnt-domains','mnt-irt','source','parent']

JPNIC=['Network Number','Network Name','Administrative Contact','Technical Contact','Nameserver','Assigned Date','Return Date','Last Update']

KRNIC=['IPv4 Address','Organization Name','Network Type','Address','Zip Code','Registration Date']

dns_list=['nserver','nsstat','nslastaa']
array_key=['descr','remarks','Comment','mnt-by','mnt-lower','mnt-routes','mnt-domains','changed','dns']
org_list=['org','Organization','Organization Name']
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
#it will find the last string match useful_object_list reg
def get_accurate_whois_info(raw_content):
	useful_object_list=[
		r'inetnum {0,1}: {0,1}\d{1,3}\.\d{1,3}',
		r'NetRange {0,1}: {0,1}\d{1,3}\.\d{1,3}',
		r'Network Number {0,}\] {0,1}\d{1,3}\.\d{1,3}',
		r'IPv4 Address {0,}: {0,1}\d{1,3}\.\d{1,3}'
	]
	accurate_content=""
	object_item_list=raw_content.split("\n\n")
	for object_item in object_item_list:
		for useful_object in useful_object_list:
			ip_range=re.findall(useful_object,object_item)
			if len(ip_range)>0:
				#print "count:"+str(len(ip_range))+":"+ip_range[0]
				accurate_content=raw_content[raw_content.find(object_item):]

	accurate_content=accurate_content.strip()
	return accurate_content
def whois_insert(ip_begin,ip_end,content,hash):
	global my_mongo
	content=content.decode("unicode_escape")
	my_mongo.insert({"ip_begin":ip_begin,"ip_end":ip_end,"content":content,"hash":hash})
def whois_query(ip):
	arg = 'whois '+ip
	query_result=os.popen(arg)
	data=""
	for line in query_result:
		if (line[0]=='%' or line[0]=='#'):    	#delete unnecessary info
			continue
		data=data+line
	data=re.sub("\n{3,}","\n\n",data)
	data=re.sub(" {2,}", " ", data)
	data=data.strip()							#delete whitespace in head or tail
	#attention:deal straight,no write into file ,so dont need to substitiue \n to string \n
	#data=data.replace("\n","\\n")
	return data
def process_accurate_content(accurate_content):
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
		ip_range=re.findall(ip_range_reg,accurate_content)
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
			#if exist,update it
			item_count=my_mongo.find({'hash':hash}).count()
			#print item_result
			if item_count>0:
				my_mongo.delete_one({"hash":hash})
			whois_insert(ip_begin_num,ip_end_num,accurate_content,hash)
def get_ip_range_object(content):
	#print content
	object_item_list=content.split("\n\n")
	#print object_item_list
	#choose the main object
	ip_range_regs=[
	r'(?:inetnum {0,1}: {0,1}|Network Number {0,}\] {0,1}|NetRange {0,1}: {0,1}|IPv4 Address {0,1}: {0,1})((?:(?:1[0-9][0-9]\.)|(?:2[0-4][0-9]\.)|(?:25[0-5]\.)|(?:0{0,3}[1-9][0-9]\.)|(?:0{0,3}[0-9]\.)){3}(?:(?:1[0-9][0-9])|(?:2[0-4][0-9])|(?:25[0-5])|(?:0{0,3}[1-9][0-9])|(?:0{0,3}[0-9]))) {0,1}- {0,1}((?:(?:1[0-9][0-9]\.)|(?:2[0-4][0-9]\.)|(?:25[0-5]\.)|(?:0{0,3}[1-9][0-9]\.)|(?:0{0,3}[0-9]\.)){3}(?:(?:1[0-9][0-9])|(?:2[0-4][0-9])|(?:25[0-5])|(?:0{0,3}[1-9][0-9])|(?:0{0,3}[0-9])))',
	r'(?:inetnum {0,1}: {0,1}|Network Number {0,}\] {0,1}|NetRange {0,1}: {0,1}|IPv4 Address {0,1}: {0,1})((?:(?:1[0-9][0-9]\.)|(?:2[0-4][0-9]\.)|(?:25[0-5]\.)|(?:0{0,3}[1-9][0-9]\.)|(?:0{0,3}[0-9]\.)){3}(?:(?:1[0-9][0-9])|(?:2[0-4][0-9])|(?:25[0-5])|(?:0{0,3}[1-9][0-9])|(?:0{0,3}[0-9])))\/((?:[1-2][0-9])|(?:3[0-2])|[0-9])',
	r'(?:inetnum {0,1}: {0,1}|Network Number {0,}\] {0,1}|NetRange {0,1}: {0,1}|IPv4 Address {0,1}: {0,1})((?:(?:1[0-9][0-9]\.)|(?:2[0-4][0-9]\.)|(?:25[0-5]\.)|(?:0{0,3}[1-9][0-9]\.)|(?:0{0,3}[0-9]\.)){2}(?:(?:1[0-9][0-9])|(?:2[0-4][0-9])|(?:25[0-5])|(?:0{0,3}[1-9][0-9])|(?:0{0,3}[0-9])))\/((?:[1-2][0-9])|(?:3[0-2])|[0-9])',
	r'(?:inetnum {0,1}: {0,1}|Network Number {0,}\] {0,1}|NetRange {0,1}: {0,1}|IPv4 Address {0,1}: {0,1})((?:(?:1[0-9][0-9]\.)|(?:2[0-4][0-9]\.)|(?:25[0-5]\.)|(?:0{0,3}[1-9][0-9]\.)|(?:0{0,3}[0-9]\.)){1}(?:(?:1[0-9][0-9])|(?:2[0-4][0-9])|(?:25[0-5])|(?:0{0,3}[1-9][0-9])|(?:0{0,3}[0-9])))\/((?:[1-2][0-9])|(?:3[0-2])|[0-9])'
	]
	#useful_object_list=['inetnum','NetRange','Network Number','IPv4 Address']
	for object_item in object_item_list:
		for ip_range_reg in ip_range_regs:
			if re.findall(ip_range_reg,object_item)!=[]:
				return object_item
def get_useful_info_from_content(ip,content):
	main_content_array_k_v=collections.OrderedDict()
	main_content_array_k_v["IP_addr"]=ip
	main_content_array_k_v["whois"]=collections.OrderedDict()
	object_item_list=[]
	main_content=""
	main_content=get_ip_range_object(content)
	object_attrs=main_content.split("\n")
	#print object_attrs
	attr_item=[]
	i=0
	dns=collections.OrderedDict()


	#main_content_array_k_v["whois"]["remarks"]=[]
	#main_content_array_k_v["whois"]["dns"]=[]
	for object_attr in object_attrs:
		for key in all_key:
			position=object_attr.find(key)
			if position>=0 and position<=7:
				if object_attr[(position+len(key)):].strip()[0:1]!=":" and object_attr[(position+len(key)):].strip()[0:1]!="]":
					continue
				value=object_attr[position+len(key):].strip()
				#value_position=position+len(key)+1 #+1 for : or ]
				value=value[1:].strip()
				value=value.decode('utf-8', errors='ignore').encode('utf-8')
				if key in array_key:
					if main_content_array_k_v["whois"].has_key(key):
						main_content_array_k_v["whois"][key].append(value)
					else:
						main_content_array_k_v["whois"][key]=[]
						main_content_array_k_v["whois"][key].append(value)
				elif key in dns_list:
					if main_content_array_k_v["whois"].has_key('dns'):
						dns[key]=value
						if len(dns.keys())>=3:
							main_content_array_k_v["whois"]['dns'].append(dns)
							dns=collections.OrderedDict()
					else:
						main_content_array_k_v["whois"]['dns']=[]
						dns[key]=value
				else:
					main_content_array_k_v["whois"][key]=value
				break
	exist_key=set(main_content_array_k_v["whois"].keys()) & set(array_key)
	for key in exist_key:
		if len(main_content_array_k_v["whois"][key])==0:
			main_content_array_k_v["whois"].pop(key)

	date1="20170901-09:13:00"
	main_content_array_k_v["whois"]["timestamp"]=date1
	#print main_content_array_k_v
	jsonStr= json.dumps(main_content_array_k_v)
	#print jsonStr
	#print "\n"
	return jsonStr
def main():
	ip=sys.argv[1]
	conn=MongoClient('127.0.0.1',27017)
	db=conn.ly
	global my_mongo
	my_mongo=db.whois3
	#query by ip
	raw_content=whois_query(ip)
	#get accurate_whois info
	accurate_content=get_accurate_whois_info(raw_content)
	#print to php
	#print "accurate_content:\n"
	#print accurate_content
	#extract ip range,and insert into db
	process_accurate_content(accurate_content)
	#get the main object info,process into json
	json=get_useful_info_from_content(ip,accurate_content)
	print json
if __name__=="__main__":
	main()
