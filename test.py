import ConfigParser
import os

cf = ConfigParser.ConfigParser()
cf.read("whois.config")
ip_range_regs=[]
regs=cf.items("ip_range_regs")
#print ip_range_regs
for reg in regs:
	ip_range_regs.append(reg[1])
	#print reg[1]
str_key=cf.get("all_key","content")
all_key=eval(str_key)
#print all_key
# for k in all_key:
# 	print k
dns_list=eval(cf.get("information_struct","dns_list"))
array_key=eval(cf.get("information_struct","array_key"))
org_list=eval(cf.get("information_struct","org_list"))
# for l in org_list:
# 	print l
#print dns_list,array_key,org_list