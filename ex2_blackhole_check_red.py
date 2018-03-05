#place this script under ~/pyretic/pyretic/examples
from pyretic.lib.corelib import *
from pyretic.lib.std import *
from pyretic.examples.ex2_dumb_forwarding import dumb_forwarder

class BlackholeCheckerRedirector(DynamicPolicy):
    def __init__(self, threshold_rate, blackhole_port_dict, IPs_and_TCP_ports_to_protect):
        super(BlackholeCheckerRedirector, self).__init__()
        self.threshold_rate = threshold_rate
        self.port_dict = blackhole_port_dict
        self.ips_tcp_ports = IPs_and_TCP_ports_to_protect
        self.untrusted_incoming_traffic_to_check = union([match(inport=self.port_dict['untrusted'], dstip=i, protocol=6, dstport=p) for (i,p) in self.ips_tcp_ports])       
        self.forward = dumb_forwarder(self.port_dict['trusted'],self.port_dict['untrusted']) #initial forwarding scheme 
        #ATTENTION: other useful attributes???
        self.refresh()
        self.srcips=[]
        self.lastcount={}
        
    def update_policy(self):
        self.policy = self.forward+self.query #parallel
        #ATTENTION: update the policy based on current forward and query policies 
        pass

    def check_redirect(self,myquery): #ATTENTION: other attributes?

        #print myquery
        for my in myquery.keys():
            my=str(my)
            srcip=my.split('srcip\', ')[1]
            if srcip!='10.1.1.4':
                self.srcips.append(srcip)
                if srcip not in self.srcips:
                    print my
                    self.srcips.append(srcip)
                    self.lastcount[srcip]=0

        #ATTENTION: implement check and redirection
        pass
         
    def refresh_query(self):
        #ATTENTION: reset the query checking for suspicious traffic and register the callback function
        self.query = count_packets(1,['srcip','dstip','dstport'])
        self.query.register_callback(self.check_redirect)        
        

    def refresh(self):
        #refresh query and policy
        self.refresh_query()
        self.update_policy()