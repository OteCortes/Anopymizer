# -*- coding: utf-8 -*-"
'''
@author Angel -Ote- Cortes
@version 0.1

Anonymizer is a class based on the requests package to simplify the use of proxies and Tor.
The class automatically select a proxy from a list, change headers randomly and keep control of not working proxies.
'''
import requests
from random import choice
from time import sleep
import socket
import datetime

TOR_CONF = {"MaxCircuitDirtiness":"60","NewCircuitPeriod":"10","CircuitBuildTimeout":"20"}

class AnonymizerException(Exception):
	'''
		Simple exception for the class
	'''
	def __init__(self,errorCode,content):
		self.errorCode = errorCode
		self.content = content

	def __str__(self):
		Lista = [self.errorCode,self.content]
		return repr(Lista)


class Anonymizer(object):
    '''
        Anonymize any http GET petition throught a proxy list or a TOR.
        If the proxy is a TOR you can manage how many connections want to do per minute and if you
        configure a TOR Control Port automatically change the circuit.
        Params:
        -proxy: Required. Dict with the http proxies list. Accept standar HTTP proxies:
          {'http':["127.0.0.1:3128","127.0.0.1:3129"]}
          Or TOR format with/without TORCTL port:
          {'tor':"127.0.0.1:8118",'torctl':"127.0.0.1:9051"}
        -petitions: (default 15) Number of petitions per minute with TOR
        -user: (default None) Reserved for future uses
        -passwd: (default None) Passphrase of the TOR control AUTHENTICATE
        -timeout: (default 15) Timeout for HTTP petitions
    '''
    def __init__(self,proxy,petitions=15,user=None,passwd=None, timeout=15):
        self.MAX_PETITIONS=petitions
        self.CURR_PETITIONS=0
        self.LAST_TIMESTAMP = datetime.datetime.now()
        self.timeout = timeout
        self.proxy_to_use = {'http':None}
        self.isTor = False
        self.torCTL = None

    	##TorCtl user/pass
        self.proxy_user = user
        self.proxy_passwd = passwd
        ##Set the Headers
        self.request_headers = {}
        ##Temporal objects
        self.url = None
        ##Result object
        self.http_response = None

        #Validate the proxy list provided
        self.__check_proxy_list(proxy)
      

    def __check_proxy_list(self,proxyDict):
        if not (proxyDict or (not (isinstance(proxyDict,dict)))):
            raise AnonymizerException(501,"No good proxy dict/list provided for Anonymizer")

        if "tor" in proxyDict.keys():
            self.isTor = True
            self.proxy = {'http':[proxyDict['tor']]}
            if "torctl" in proxyDict.keys():
                self.torCTL = proxyDict['torctl']
                self.__prepare_tor()
                
            return True

        if "http" in proxyDict.keys():
            if isinstance(proxyDict['http'],list):
                self.proxy = proxyDict
                return True
            else:
                raise AnonymizerException(502,"No good HTTP proxy list provided for Anonymizer")
            
    def __check_timestamps(self):
        now=datetime.datetime.now()
        delta=now-self.LAST_TIMESTAMP
        #print("Delta Seconds:%s"%str(delta.seconds))
        if delta.seconds > int(TOR_CONF['MaxCircuitDirtiness']):
            self.LAST_TIMESTAMP = now
            return True
        return False


    def __set_RandomHeaders(self):
        '''
            Select a random headers from a list and asings it to the the connection
        '''
        ##User Agent
        user_agents_list = []
        user_agents_list.append('Mozilla/5.0 (iPhone; U; CPU iOS 2_0 like Mac OS X; en-us)')
        user_agents_list.append('Mozilla/5.0 (Linux; U; Android 0.5; en-us)')
        user_agents_list.append('Mozilla/5.0 (iPad; U; CPU OS 3_2_1 like Mac OS X; en-us) AppleWebKit/531.21.10 (KHTML, like Gecko)')
        user_agents_list.append('Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 6.0)')
        user_agents_list.append('Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1)')
        user_agents_list.append('Mozilla/5.0 (Windows; U; Windows NT 5.1; en-US) AppleWebKit/525.13 (KHTML, like Gecko) Chrome/0.2.149.29 Safari/525.13')
        user_agents_list.append('Opera/9.25 (Windows NT 6.0; U; en)')
        user_agents_list.append('Opera/9.80 (X11; Linux x86_64; U; pl) Presto/2.7.62 Version/11.00')
        user_agents_list.append('Opera/9.80 (Windows NT 6.0; U; en) Presto/2.7.39 Version/11.00')
        user_agents_list.append('Mozilla/5.0 (Windows NT 6.0; U; ja; rv:1.9.1.6) Gecko/20091201 Firefox/3.5.6 Opera 11.00')
        user_agents_list.append('Mozilla/4.0 (compatible; MSIE 8.0; X11; Linux x86_64; pl) Opera 11.00')
        user_agents_list.append('Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.1; fr) Opera 11.00')
        user_agents_list.append('Opera/9.80 (Windows NT 6.1 x64; U; en) Presto/2.7.62 Version/11.00')
        user_agents_list.append('Mozilla/5.0 (Windows NT 5.1; U; de; rv:1.9.1.6) Gecko/20091201 Firefox/3.5.6 Opera 11.00')
        user_agents_list.append('Mozilla/4.0 (compatible; MSIE 8.0; X11; Linux x86_64; pl) Opera 11.00')

        user_agent = choice(user_agents_list).strip() 

        ##Language
        accept_languaje_list = []
        accept_languaje_list.append('de-de,es-es;q=0.8,en-us;q=0.5,en;q=0.3')
        accept_languaje_list.append('en-us;q=0.8,en;q=0.3')
        accept_languaje_list.append('es;q=0.8,en-us;q=0.5,en;q=0.3')
        accept_languaje_list.append('es-es;q=0.8,en;q=0.3')
        accept_languaje_list.append('de-de;q=0.8,en;q=0.3')
        accept_languaje_list.append('de-de;q=0.8,en-us;q=0.5)')

        languaje = choice(accept_languaje_list).strip() 

        self.request_headers = {'User-Agent': user_agent, 'Accept-Languaje':languaje, 'Referer': ''}
    
    def __prepare_request(self,url):
        """ 
            Prepare the random objects for the request.
        """
        self.url = url
        self.__set_RandomHeaders()
        requests.defaults.defaults['keep_alive']=False
        if self.isTor:
            if self.torCTL != None:
                if not self.__check_timestamps():
                    if (self.CURR_PETITIONS == self.MAX_PETITIONS):
                        self.CURR_PETITIONS = 0
                        raise AnonymizerException(111,"Max number of petitions(%s) in %sseconds reached"%(self.MAX_PETITIONS,TOR_CONF['MaxCircuitDirtiness']))
                        
                    self.CURR_PETITIONS = self.CURR_PETITIONS + 1
                else:
                    self.CURR_PETITIONS = 1
                    self.__reroute_tor()

        self.proxy_to_use['http'] = choice(self.proxy['http'])

    def __prepare_tor(self):
        host, port = self.torCTL.split(':')
        #print("Servidor de control TOR: %s"%host)
        #print("Puerto de control TOR: %s"%port)
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
 
        s.connect((host,int(port)))
        if self.proxy_passwd:
            s.send(str.encode('AUTHENTICATE "%s"\r\n'%self.proxy_passwd))
            data = s.recv(100)
            if not str(data.decode()).startswith("250"):
                raise Anonymizer(211, "Error in the AUTHENTICATE command to the TOR control port.")
        #Short circuit time
        s.send(str.encode('SETCONF NewCircuitPeriod=%s\r\n'%TOR_CONF['NewCircuitPeriod']))
        data = s.recv(100)
        #Short circuit build time
        s.send(str.encode('SETCONF CircuitBuildTimeout=%s\r\n'%TOR_CONF['CircuitBuildTimeout']))
        data = s.recv(100)
        #Short circuit Valid time
        s.send(str.encode('SETCONF MaxCircuitDirtiness="%s"\r\n'%TOR_CONF['MaxCircuitDirtiness']))
        data = s.recv(100)
        sleep(5)
        s.close()
 
        #print("Tor ReConfigured")


    def __reroute_tor(self):
        host, port = self.torCTL.split(':')
        #print("Servidor de control TOR: %s"%host)
        #print("Puerto de control TOR: %s"%port)
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        data = None
 
        s.connect((host,int(port)))
        #print("Conectado al servidor de control")
        if self.proxy_passwd:
            s.send(str.encode("AUTHENTICATE \"%s\"\r\n"%self.proxy_passwd))
            data = s.recv(100)
            if not str(data.decode()).startswith("250"):
                raise Anonymizer(211, "Error in the AUTHENTICATE command to the TOR control port.")
        s.send(str.encode('SIGNAL NEWNYM\r\n'))
        s.recv(100)
        sleep(5)
        s.close()
 
        #print("Tor rerouted")



    def get(self,url,pureAnon=False,DEBUG=False):
        '''
            get will return the url requested using a randomized proxy from the list as a request.response item.
            PARAMS:
            -url: The url to retrieve
            -pureAnon: (default False) If set to True no cookies are accepted in this petition and will not be returned.
            -DEBUG: (default False) If True, return a dict like:
                    {'response':http_response,'proxy':"proxy used",'headers':"Fake headers used"}
        '''
        self.__prepare_request(url)
        if pureAnon:
            requests.defaults.defaults['store_cookies'] = False
        try:
            self.http_response = requests.get(self.url,proxies=self.proxy_to_use,headers=self.request_headers, timeout=self.timeout)
        except Exception as e:
            raise AnonymizerException(101,"Requests unable to get %s using the proxy %s"%(url,self.proxy_to_use))

        if not DEBUG:
            return self.http_response
        else:
            output = {'response':self.http_response,'proxy':self.proxy_to_use,'headers':self.request_headers}
            return output
    
    