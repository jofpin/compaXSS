#!/usr/bin/env python
# -*- coding: utf-8 -*-
# wafw00f - Web Application Firewall Detection Tool
# by Sandro Gauci - enablesecurity.com (c) 2009
#  and Wendel G. Henrique - Trustwave 2009

__license__ = """
Copyright (c) 2009, {Sandro Gauci|Wendel G. Henrique}
All rights reserved.

Redistribution and use in source and binary forms, with or without modification,
are permitted provided that the following conditions are met:

    * Redistributions of source code must retain the above copyright notice,
      this list of conditions and the following disclaimer.
    * Redistributions in binary form must reproduce the above copyright notice,
      this list of conditions and the following disclaimer in the documentation
      and/or other materials provided with the distribution.
    * Neither the name of EnableSecurity or Trustwave nor the names of its contributors
      may be used to endorse or promote products derived from this software
      without specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT,
INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE
OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED
OF THE POSSIBILITY OF SUCH DAMAGE.
"""
import os
import httplib
from urllib import quote, unquote
import urllib2
from optparse import OptionParser
import logging
import socket
import sys
import random

currentDir = os.getcwd()
scriptDir = os.path.dirname(sys.argv[0]) or '.'
os.chdir( scriptDir )

from libs.evillib import *




class WafW00F(waftoolsengine):
    """
    WAF detection tool
    """
    
    AdminFolder = '/Admin_Files/'
    xssstring = '<script>alert(1)</script>'
    dirtravstring = '../../../../etc/passwd'
    cleanhtmlstring = '<invalid>hello'
    isaservermatch = 'Forbidden ( The server denied the specified Uniform Resource Locator (URL). Contact the server administrator.  )'
    
    def __init__(self,target='www.microsoft.com',port=80,ssl=False,
                 debuglevel=0,path='/',followredirect=True):
        """
        target: the hostname or ip of the target server
        port: defaults to 80
        ssl: defaults to false
        """
        waftoolsengine.__init__(self,target,port,ssl,debuglevel,path,followredirect)
        self.log = logging.getLogger('wafw00f')
        self.knowledge = dict(generic=dict(found=False,reason=''),wafname=list())
        
    def normalrequest(self,usecache=True,cacheresponse=True,headers=None):
        return self.request(usecache=usecache,cacheresponse=cacheresponse,headers=headers)
    
    def normalnonexistentfile(self,usecache=True,cacheresponse=True):
        path = self.path + str(random.randrange(1000,9999)) + '.html'
        return self.request(path=path,usecache=usecache,cacheresponse=cacheresponse)
    
    def unknownmethod(self,usecache=True,cacheresponse=True):
        return self.request(method='OHYEA',usecache=usecache,cacheresponse=cacheresponse)
    
    def directorytraversal(self,usecache=True,cacheresponse=True):
        return self.request(path=self.path+self.dirtravstring,usecache=usecache,cacheresponse=cacheresponse)
        
    def invalidhost(self,usecache=True,cacheresponse=True):
        randomnumber = random.randrange(100000,999999)
        return self.request(headers={'Host':str(randomnumber)})
        
    def cleanhtmlencoded(self,usecache=True,cacheresponse=True):
        string = self.path + quote(self.cleanhtmlstring) + '.html'
        return self.request(path=string,usecache=usecache,cacheresponse=cacheresponse)

    def cleanhtml(self,usecache=True,cacheresponse=True):
        string = self.path + self.cleanhtmlstring + '.html'
        return self.request(path=string,usecache=usecache,cacheresponse=cacheresponse)
        
    def xssstandard(self,usecache=True,cacheresponse=True):
        xssstringa = self.path + self.xssstring + '.html'
        return self.request(path=xssstringa,usecache=usecache,cacheresponse=cacheresponse)
    
    def protectedfolder(self,usecache=True,cacheresponse=True):
        pfstring = self.path + self.AdminFolder
        return self.request(path=pfstring,usecache=usecache,cacheresponse=cacheresponse)

    def xssstandardencoded(self,usecache=True,cacheresponse=True):
        xssstringa = self.path + quote(self.xssstring) + '.html'
        return self.request(path=xssstringa,usecache=usecache,cacheresponse=cacheresponse)
    
    def cmddotexe(self,usecache=True,cacheresponse=True):
        # thanks j0e
        string = self.path + 'cmd.exe'
        return self.request(path=string,usecache=usecache,cacheresponse=cacheresponse)
    
    attacks = [cmddotexe,directorytraversal,xssstandard,protectedfolder,xssstandardencoded]
    
    def genericdetect(self,usecache=True,cacheresponse=True):        
        reason = ''
        reasons = ['Blocking is being done at connection/packet level.',
                   'La cabecera del servidor es diferente cuando un ataque es detectado',
                   'El servidor devuelve un código de respuesta diferentes provocadopor  una cadena de lista negra',
                   'Se cerro la conexion para una solicitud normal',
                   'La cabecera de conexion fue mezclada.'
                   ]
        # test if response for a path containing html tags with known evil strings
        # gives a different response from another containing invalid html tags
        r = self.cleanhtml()
        if r is None:
            self.knowledge['generic']['reason'] = reasons[0]
            self.knowledge['generic']['found'] = True
            return True
        cleanresponse,_tmp =r
        r = self.xssstandard()
        if r is None:            
            self.knowledge['generic']['reason'] = reasons[0]
            self.knowledge['generic']['found'] = True
            return True
        xssresponse,_tmp = r
        if xssresponse.status != cleanresponse.status:
            self.log.info('Servidor ha devuelto una respuesta diferente cuando una etiqueta script fue juzgada')            
            reason = reasons[2]
            reason += '\r\n'
            reason += 'El codigo de respuesta normal es "%s",' % cleanresponse.status
            reason += ' mientras que el codigo de respuesta para un ataque es "%s"' % xssresponse.status
            self.knowledge['generic']['reason'] = reason
            self.knowledge['generic']['found'] = True
            return True
        r = self.cleanhtmlencoded()
        cleanresponse,_tmp = r
        r = self.xssstandardencoded()
        if r is None:            
            self.knowledge['generic']['reason'] = reasons[0]
            self.knowledge['generic']['found'] = True
            return True
        xssresponse,_tmp = r
        if xssresponse.status != cleanresponse.status:
            self.log.info('Server returned a different response when a script tag was tried')
            reason = reasons[2]
            reason += '\r\n'
            reason += 'El codigo de respuesta normal es "%s",' % cleanresponse.status
            reason += ' mientras que el codigo de respuesta para un ataque es "%s"' % xssresponse.status
            self.knowledge['generic']['reason'] = reason
            self.knowledge['generic']['found'] = True
            return True
        response, responsebody = self.normalrequest()
        normalserver = response.getheader('Server')
        for attack in self.attacks:        
            r = attack(self)              
            if r is None:                
                self.knowledge['generic']['reason'] = reasons[0]
                self.knowledge['generic']['found'] = True
                return True
            response, responsebody = r
            attackresponse_server = response.getheader('Server')
            if attackresponse_server:
                if attackresponse_server != normalserver:
                    self.log.info('La cabecera del servidor cambio, WAF posiblemente detectado')
                    self.log.debug('Respuesta a ataque: %s' % attackresponse_server)
                    self.log.debug('Respuesta normal: %s' % normalserver)
                    reason = reasons[1]
                    reason += '\r\nLa cabecera del servidor para una respuesta normal es "%s",' % normalserver
                    reason += ' mientras que la cabecera del servidor de respuesta a un ataque es "%s.",' % attackresponse_server
                    self.knowledge['generic']['reason'] = reason
                    self.knowledge['generic']['found'] = True
                    return True
        for attack in self.wafdetectionsprio:
            if self.wafdetections[attack](self) is None:
                self.knowledge['generic']['reason'] = reasons[0]
                self.knowledge['generic']['found'] = True
                return True
        for attack in self.attacks:
            r = attack(self)
            if r is None:                
                self.knowledge['generic']['reason'] = reasons[0]
                self.knowledge['generic']['found'] = True
                return True
            response, responsebody = r
            for h,v in response.getheaders():
                if scrambledheader(h):
                    self.knowledge['generic']['reason'] = reasons[4]
                    self.knowledge['generic']['found'] = True
                    return True
        return False

    def matchheader(self,headermatch,attack=False,ignorecase=True):
        import re
        detected = False
        header,match = headermatch
        if attack:
            requests = self.attacks
        else:
            requests = [self.normalrequest]
        for request in requests:            
            r = request(self)
            if r is None:                
                return
            response,responsebody = r
            headerval = response.getheader(header)
            if headerval:
                # set-cookie can have multiple headers, python gives it to us
                # concatinated with a comma
                if header == 'set-cookie':
                    headervals = headerval.split(', ')
                else:
                    headervals = [headerval]
                for headerval in headervals:
                    if ignorecase:
                        if re.match(match,headerval,re.IGNORECASE):
                            detected = True
                            break
                    else:
                        if re.match(match,headerval):
                            detected = True
                            break
                if detected:
                    break
        return detected

    def isbigip(self):
        return self.matchheader(('X-Cnection','^close$'), attack=True)
    
    def iswebknight(self):
        detected = False
        for attack in self.attacks:
            r = attack(self)
            if r is None:                
                return
            response, responsebody = r
            if response.status == 999:
                detected = True
                break
        return detected
        
    def ismodsecurity(self):
        detected = False
        for attack in self.attacks:
            r = attack(self)
            if r is None:                
                return
            response, responsebody = r
            if response.status == 501:
                detected = True
                break
        return detected
    
    def isisaserver(self):
        detected = False
        r = self.invalidhost()
        if r is None:
            return
        response,responsebody = r
        if response.reason == self.isaservermatch:
            detected = True
        return detected
    
    def issecureiis(self):
        # credit goes to W3AF
        detected = False
        headers = dict()
        headers['Transfer-Encoding'] = 'z' * 1025
        r = self.normalrequest(headers=headers)
        if r is None:
            return 
        response,responsebody = r 
        if response.status == 404:
            detected = True
        return detected
    
    def matchcookie(self,match):
        """
        a convenience function which calls matchheader
        """
        return self.matchheader(('set-cookie',match))
    
    def isairlock(self):
        # credit goes to W3AF
        return self.matchcookie('^AL[_-]?(SESS|LB)=')
    
    def isbarracuda(self):
        # credit goes to W3AF
        return self.matchcookie('^barra_counter_session=')
    
    def isdenyall(self):
        # credit goes to W3AF
        if self.matchcookie('^sessioncookie='):
            return True
        # credit goes to Sebastien Gioria
        #   Tested against a Rweb 3.8
        # and modified by sandro gauci and someone else
        for attack in self.attacks:
            r = attack(self)
            if r is None:
                return
            response, responsebody = r
            if response.status == 200:
                if response.reason == 'Condition Intercepted':
                    return True
        return False
    
    def isbeeware(self):
        # disabled cause it was giving way too many false positives
        # credit goes to Sebastien Gioria
        detected = False
        r = self.xssstandard()
        if r is None:
            return
        response, responsebody = r
        if (response.status != 200) or (response.reason == 'Forbidden'):
            r = self.directorytraversal()
            if r is None:
                return
            response, responsebody = r
            if response.status == 403:
                if response.reason == "Forbidden":
                    detected = True
        return detected
        
    def isf5asm(self):
        # credit goes to W3AF
        return self.matchcookie('^TS[a-zA-Z0-9]{3,6}=')
    
    def isf5trafficshield(self):
        for hv in [['cookie','^ASINFO='],['server','F5-TrafficShield']]:            
            r = self.matchheader(hv)
            if r is None:
                return
            elif r:
                return r
        return False

    def isteros(self):
        # credit goes to W3AF
        return self.matchcookie('^st8id=')
    
    def isnetcontinuum(self):
        # credit goes to W3AF
        return self.matchcookie('^NCI__SessionId=')
    
    def isbinarysec(self):
        # credit goes to W3AF
        return self.matchheader(('server','BinarySec'))
    
    def ishyperguard(self):
        # credit goes to W3AF
        return self.matchcookie('^WODSESSION=')
    
    def isprofense(self):
        """
        Checks for server headers containing "profense"
        """
        return self.matchheader(('server','profense'))
        
    def isnetscaler(self):
        """
        First checks if a cookie associated with Netscaler is present,
        if not it will try to find if a "Cneonction" or "nnCoection" is returned
        for any of the attacks sent
        """
        # NSC_ and citrix_ns_id come from David S. Langlands <dsl 'at' surfstar.com>
        if self.matchcookie('^(ns_af=|citrix_ns_id|NSC_)'):
            return True    
        if self.matchheader(('Cneonction','close'),attack=True):
            return True
        if self.matchheader(('nnCoection','close'),attack=True):
            return True
        return False
    
    def isurlscan(self):
        detected = False
        testheaders = dict()
        testheaders['Translate'] = 'z'*10
        testheaders['If'] = 'z'*10
        testheaders['Lock-Token'] = 'z'*10
        testheaders['Transfer-Encoding'] = 'z'*10
        r = self.normalrequest()
        if r is None:
            return
        response,_tmp = r
        r = self.normalrequest(headers=testheaders)
        if r is None:
            return 
        response2,_tmp = r
        if response.status != response2.status:
            if response2.status == 404:
                detected = True
        return detected
    
    def iswebscurity(self):
        detected = False
        r = self.normalrequest()
        if r is None:
            return
        response,responsebody=r
        if response.status == 403:
            return detected
        newpath = self.path + '?nx=@@'
        r = self.request(path=newpath)
        if r is None:
            return 
        response,responsebody = r
        if response.status == 403:
            detected = True
        return detected
    
    def isdotdefender(self):
        # thanks to j0e
        return self.matchheader(['X-dotDefender-denied', '^1$'],attack=True)

    def isimperva(self):
        # thanks to Mathieu Dessus <mathieu.dessus(a)verizonbusiness.com> for this
        # might lead to false positives so please report back to sandro@enablesecurity.com
        for attack in self.attacks:
            r = attack(self)
            if r is None:
                return
            response, responsebody = r
            if response.version == 10:
                return True
        return False
    
    def ismodsecuritypositive(self):
        import random
        detected = False
        self.normalrequest(usecache=False,cacheresponse=False)
        randomfn = self.path + str(random.randrange(1000,9999)) + '.html'
        r = self.request(path=randomfn)
        if r is None:
            return
        response,responsebody = r
        if response.status != 302:
            return False
        randomfnnull = randomfn+'%00'
        r = self.request(path=randomfnnull)
        if r is None:
            return
        response,responsebody = r
        if response.status == 404:
            detected = True
        return detected
    
    def isibmdatapower(self):
	# Added by Mathieu Dessus <mathieu.dessus(a)verizonbusiness.com> 
	detected = False
	if self.matchheader(('X-Backside-Transport', '^(OK|FAIL)')):
		detected = True
	return detected


    def isibm(self):
        detected = False
        r = self.protectedfolder()
        if r is None:
            detected = True
        return detected


    wafdetections = dict()
    # easy ones
    wafdetections['IBM Web Application Security'] = isibm
    wafdetections['IBM DataPower'] = isibmdatapower
    wafdetections['Profense'] = isprofense
    wafdetections['ModSecurity'] = ismodsecurity
    wafdetections['ISA Server'] = isisaserver
    wafdetections['NetContinuum'] = isnetcontinuum
    wafdetections['HyperGuard'] = ishyperguard
    wafdetections['Barracuda'] = isbarracuda
    wafdetections['Airlock'] = isairlock
    wafdetections['BinarySec'] = isbinarysec
    wafdetections['F5 Trafficshield'] = isf5trafficshield
    wafdetections['F5 ASM'] = isf5asm
    wafdetections['Teros'] = isteros
    wafdetections['DenyALL'] = isdenyall
    wafdetections['BIG-IP'] = isbigip
    wafdetections['Citrix NetScaler'] = isnetscaler
    # lil bit more complex
    wafdetections['webApp.secure'] = iswebscurity
    wafdetections['WebKnight'] = iswebknight    
    wafdetections['URLScan'] = isurlscan
    wafdetections['SecureIIS'] = issecureiis
    wafdetections['dotDefender'] = isdotdefender
    #wafdetections['BeeWare'] = isbeeware
    # wafdetections['ModSecurity (positive model)'] = ismodsecuritypositive removed for now
    wafdetections['Imperva'] = isimperva
    wafdetectionsprio = ['Profense','NetContinuum',                         
                         'Barracuda','HyperGuard','BinarySec','Teros',
                         'F5 Trafficshield','F5 ASM','Airlock','Citrix NetScaler',
                         'ModSecurity', 'IBM Web Application Security', 'IBM DataPower', 'DenyALL',
                         'dotDefender','webApp.secure', # removed for now 'ModSecurity (positive model)',                         
                         'BIG-IP','URLScan','WebKnight',
                         'SecureIIS','Imperva','ISA Server']
    
    def identwaf(self,findall=False):
        detected = list()
        for wafvendor in self.wafdetectionsprio:
            self.log.info('Analizando a %s' % wafvendor)
            if self.wafdetections[wafvendor](self):
                detected.append(wafvendor)
                if not findall:
                    break
        self.knowledge['wafname'] = detected
        return detected

def calclogginglevel(verbosity):
    default = 40 # errors are printed out
    level = default - (verbosity*10)
    if level < 0:
        level = 0
    return level

class wafwoof_api:
    def __init__(self):
        self.cache = dict()
        
    def vendordetect(self,url,findall=False):            
        if self.cache.has_key(url):
            wafw00f = self.cache[url]
        else:
            r = oururlparse(url)
            if r is None:
                return ['']
            (hostname,port,path,query,ssl) = r
            wafw00f = WafW00F(target=hostname,port=port,path=path,ssl=ssl)
            self.cache[url] = wafw00f
        return wafw00f.identwaf(findall=findall)
    
    def genericdetect(self,url):            
        if self.cache.has_key(url):
            wafw00f = self.cache[url]
        else:
            r = oururlparse(url)
            if r is None:
                return {}
            (hostname,port,path,query,ssl) = r
            wafw00f = WafW00F(target=hostname,port=port,path=path,ssl=ssl)
            self.cache[url] = wafw00f
        wafw00f.genericdetect()
        return wafw00f.knowledge['generic']
        
    def alltests(self,url,findall=False):
        if self.cache.has_key(url):
            wafw00f = self.cache[url]
        else:
            r = oururlparse(url)
            if r is None:
                return {}
            (hostname,port,path,query,ssl)  = r
            wafw00f = WafW00F(target=hostname,port=port,path=path,ssl=ssl)
            self.cache[url] = wafw00f
        wafw00f.identwaf(findall=findall)
        if (len(wafw00f.knowledge['wafname']) == 0) or (findall):
            wafw00f.genericdetect()
        return wafw00f.knowledge

def detector(url):
    findall = False
    verbose = True
    followredirect = False
    logging.basicConfig(level=calclogginglevel(verbose))
    log = logging.getLogger()
    target = url
    print "Analizando %s" % target
    pret = oururlparse(target)
    if pret is None:
        log.critical('The url %s is not well formed' % target)
        sys.exit(1)
    (hostname,port,path,query,ssl) = pret
    log.info('Iniciando wafw00f en %s' % target)
    attacker = WafW00F(hostname,port=port,ssl=ssl,
                        debuglevel=verbose,path=path,
                        followredirect=followredirect)
    if attacker.normalrequest() is None:
        log.error('El sitio %s parece estar caido' % target)
        sys.exit(1)
    waf = attacker.identwaf(findall)
    log.info('Ident WAF: %s' % waf)
    if len(waf) > 0:
        print 'El sitio %s esta detras de8 %s' % (target, ' and/or '.join( waf))
    if (findall) or len(waf) == 0:
        print '\033[92mResultados de la detección genérica:\033[0m'          
        if attacker.genericdetect():                
            log.info('Deteccion generica: %s' % attacker.knowledge['generic']['reason'])                    
            print 'El sitio %s parece estar detras de un WAF ' % target
            print 'Reason: %s' % attacker.knowledge['generic']['reason']
        else:
            print '\033[91mNo se detecto WAF\033[0m'
    print '\033[94mNumero de soliitudes:\033[1;33m %s \033[0m' % attacker.requestnumber
