import re
import os
import socket
import struct
import hashlib
import json
import collections
import sys
from pymongo import MongoClient
import ConfigParser

useful=['inetnum','NetRange','descr','CIDR','NetName','Organization','Updated','NetType']
all_key=[
'NetRange','CIDR','NetName','NetHandle','Parent','NetType','OriginAS','Organization','RegDate','Updated','Comment','Ref',
'inetnum','aut-num','abuse-c','owner','ownerid','responsible','address',
'netname','descr','country','geoloc','language','org','sponsoring-org','admin-c',
'phone','owner-c','tech-c','status','remarks','notify','mnt-by','mnt-lower','mnt-routes','mnt-domains','mnt-irt',
'inetrev','dns',
'Network Number','Network Name','Administrative Contact','Technical Contact','Nameserver','Assigned Date','Return Date','Last Update',
'IPv4 Address','Organization Name','Network Type','Address','Zip Code','Registration Date',
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
def get_useful_info_from_content_old(ip,content):
	main_content_array_k_v={}
	main_content_array_k_v[ip]={}
	main_content_array_k_v[ip]["whois"]={}
	object_items=[]
	main_content=""
	object_items=content.split("\n\n")
	for object_item in object_items:
		if((object_item.find("NetRange")!=-1) or (object_item.find("inetnum")!=-1)):
			main_content=object_item

	object_attrs=main_content.split("\n")
	attr_item=[]
	i=0
	descr_list=[]
	useful=['inetnum','NetRange','descr','CIDR','NetName','Organization','Updated','NetType']
	for object_attr in object_attrs:
		attr_item=object_attr.split(":")
		if(len(attr_item)<2):
			continue
		if(attr_item[0]=="descr"):
			descr_list.append(attr_item[1])
		else:
			main_content_array_k_v[ip]["whois"][attr_item[0]]=attr_item[1]
	main_content_array_k_v[ip]["whois"]["descr"]=descr_list
	date1="20170901-23:13:00"
	main_content_array_k_v[ip]["whois"]["timestamp"]=date1
	jsonStr= json.dumps(main_content_array_k_v)
	return jsonStr

def get_ip_range_object(content):
	#print content
	object_item_list=content.split("\n\n")
	#choose the main object
	ip_range_regs=[
	r'(?:inetnum {0,1}: {0,1}|Network Number {0,}\] {0,1}|NetRange {0,1}: {0,1}|IPv4 Address {0,1}: {0,1})((?:(?:1[0-9][0-9]\.)|(?:2[0-4][0-9]\.)|(?:25[0-5]\.)|(?:0{0,3}[1-9][0-9]\.)|(?:0{0,3}[0-9]\.)){3}(?:(?:1[0-9][0-9])|(?:2[0-4][0-9])|(?:25[0-5])|(?:0{0,3}[1-9][0-9])|(?:0{0,3}[0-9]))) {0,1}- {0,1}((?:(?:1[0-9][0-9]\.)|(?:2[0-4][0-9]\.)|(?:25[0-5]\.)|(?:0{0,3}[1-9][0-9]\.)|(?:0{0,3}[0-9]\.)){3}(?:(?:1[0-9][0-9])|(?:2[0-4][0-9])|(?:25[0-5])|(?:0{0,3}[1-9][0-9])|(?:0{0,3}[0-9])))',
	r'(?:inetnum {0,1}: {0,1}|Network Number {0,}\] {0,1}|NetRange {0,1}: {0,1}|IPv4 Address {0,1}: {0,1})((?:(?:1[0-9][0-9]\.)|(?:2[0-4][0-9]\.)|(?:25[0-5]\.)|(?:0{0,3}[1-9][0-9]\.)|(?:0{0,3}[0-9]\.)){3}(?:(?:1[0-9][0-9])|(?:2[0-4][0-9])|(?:25[0-5])|(?:0{0,3}[1-9][0-9])|(?:0{0,3}[0-9])))\/((?:[1-2][0-9])|(?:3[0-2])|[0-9])',
	r'(?:inetnum {0,1}: {0,1}|Network Number {0,}\] {0,1}|NetRange {0,1}: {0,1}|IPv4 Address {0,1}: {0,1})((?:(?:1[0-9][0-9]\.)|(?:2[0-4][0-9]\.)|(?:25[0-5]\.)|(?:0{0,3}[1-9][0-9]\.)|(?:0{0,3}[0-9]\.)){2}(?:(?:1[0-9][0-9])|(?:2[0-4][0-9])|(?:25[0-5])|(?:0{0,3}[1-9][0-9])|(?:0{0,3}[0-9])))\/((?:[1-2][0-9])|(?:3[0-2])|[0-9])',
	r'(?:inetnum {0,1}: {0,1}|Network Number {0,}\] {0,1}|NetRange {0,1}: {0,1}|IPv4 Address {0,1}: {0,1})((?:(?:1[0-9][0-9]\.)|(?:2[0-4][0-9]\.)|(?:25[0-5]\.)|(?:0{0,3}[1-9][0-9]\.)|(?:0{0,3}[0-9]\.)){1}(?:(?:1[0-9][0-9])|(?:2[0-4][0-9])|(?:25[0-5])|(?:0{0,3}[1-9][0-9])|(?:0{0,3}[0-9])))\/((?:[1-2][0-9])|(?:3[0-2])|[0-9])'
	]
	# for reg in ip_range_regs:
	# 	print reg
	useful_object_list=['inetnum','NetRange','Network Number','IPv4 Address']
	for object_item in object_item_list:
		for ip_range_reg in ip_range_regs:
			if re.findall(ip_range_reg,object_item)!=[]:
				return object_item
	#attention!!!maybe no return above!!!!!
	return ""

def get_useful_info_from_content(ip,content):
	main_content_array_k_v=collections.OrderedDict()
	main_content_array_k_v["IP_addr"]=ip
	main_content_array_k_v["whois"]=collections.OrderedDict()
	object_item_list=[]
	main_content=""
	if content=="":
		#print "no find"
		return main_content_array_k_v
	main_content=get_ip_range_object(content)
	object_attrs=main_content.split("\n")
	attr_item=[]
	i=0
	dns=collections.OrderedDict()

	for object_attr in object_attrs:
		for key in all_key:
			position=object_attr.find(key)
			if position>=0 and position<=7:
				if object_attr[(position+len(key)):].strip()[0:1]!=":" and object_attr[(position+len(key)):].strip()[0:1]!="]":
					continue
				value=object_attr[position+len(key):].strip()
				#value_position=position+len(key)+1 #+1 for : or ]
				value=value[1:].strip()
				#value=value.decode('utf-8', errors='ignore').encode('utf-8')
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
	#jsonStr= json.dumps(main_content_array_k_v)
	return main_content_array_k_v


def main():
	###############################read configure#################################
	# cf = ConfigParser.ConfigParser()
	# cf.read("whois.config")
	# global ip_range_regs,all_key,dns_list,array_key,org_list
	# ip_range_regs=[]
	# regs=cf.items("ip_range_regs")
	# #print ip_range_regs
	# for reg in regs:
	# 	ip_range_regs.append(reg[1])
	# #print ip_range_regs[3]
	# str_key=cf.get("all_key","content")
	# all_key=eval(str_key)
	# #print all_key
	# # for k in all_key:
	# # 	print k
	# dns_list=eval(cf.get("information_struct","dns_list"))
	# array_key=eval(cf.get("information_struct","array_key"))
	# org_list=eval(cf.get("information_struct","org_list"))
	###############################read configure#################################
	conn=MongoClient('127.0.0.1',27017)
	db=conn.ly
	my_mongo=db.whois3
	json_list=[]
	#if func by php,must use abspath!!!!!!!!!
	fip=open(sys.argv[1],'r')
	ip_list=fip.readlines()
	fip.close()
	#ip_list=sys.argv[1].split('\n')
	for ip in ip_list:
		ip=ip.strip()
		m=re.match("^(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})$",ip)
		if not m:
			#print "error ip type:"+str(m)
			continue
		main_content_array_k_v={}
		main_content_array_k_v[ip]={}
		main_content_array_k_v[ip]["whois"]={}
		m=re.match("^(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})$",ip)
		if not m:
			continue
		#print "ip:"+ip
		ip_num=socket.ntohl(struct.unpack("I",socket.inet_aton(ip))[0])
		#print ip_num
		rows=my_mongo.find({'ip_begin':{'$lte':ip_num},'ip_end':{'$gte':ip_num}})
		#print my_mongo.find({'ip_begin':{'$lte':ip_num},'ip_end':{'$gte':ip_num}}).count()
		#count1=my_mongo.find({'ip_begin':{'$lte':0},'ip_end':{'$gte':ip_num}}).count()
		#break
		#print a
		result={}
		last_distance=4294967295
		result['ip_begin']=0
		result['ip_end']=4294967295
		result['content']=""
		for row in rows:
			if (row['ip_end']-row['ip_begin'])<last_distance:
				#choose the most accurate one
				last_distance=row['ip_end']-row['ip_begin']
				result['ip_begin']=row['ip_begin']
				result['ip_end']=row['ip_end']
				result['content']=row['content']
				#print "content:"+result['content']
		content=""
		content=result['content']
		#print content
		jsonStr=get_useful_info_from_content(ip,content)
	# 	try:
	# 		jsonStr=get_useful_info_from_content(ip,content)
	# 	except Exception as e:
	# 		#print result['content']
	# 		print ip
		json_list.append(jsonStr)
		#print jsonStr
	str1=json.dumps(json_list,indent=4)
	print str1

if __name__=="__main__":
	main()
