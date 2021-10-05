"""
Code for Self-Signing certificate
"""

from datetime import date, datetime,timedelta #set expiration date
from cryptography import x509 #digital cert standard
from cryptography.x509.oid import NameOID #assign names to certs in form of Object ids
from cryptography.hazmat.primitives import hashes #to sign didital certs
from cryptography.hazmat.backends import default_backend #choosing any default backend
from cryptography.hazmat.primitives import serialization #to save private keys and certs to a file 
from cryptography.hazmat.primitives.asymmetric import rsa #RSA itself

def ip_address_checker(ip):
    p = ip.split(".")
    if len(p) != 4:
        print(f"IP address {ip} is not valid")
        return False
    for part in p:
        if not isinstance(int(part), int):
            print(f"IP address {ip} is not valid")
            return False

        if int(part) < 0 or int(part) > 255:
            print(f"IP address {ip} is not valid")
            return False
 
    print(f"IP address {ip} is valid")
    return True
print("""
***********************************
* Generate Self-Signed Certificate*
***********************************
""")


server_IP = input("Enter the IP address = ")
while(ip_address_checker(server_IP)!=True):
    server_IP = input()

print("""
*********************************
* Please provide Valid Hostname *
*********************************
""")

h_name = input("hostname= ")

print("""

Generating keys...

""")

key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048,
    backend=default_backend(),
)

name = x509.Name([
    x509.NameAttribute(NameOID.COMMON_NAME,h_name)
])

alt_name = [x509.DNSName(h_name)]
alt_name.append(x509.DNSName(server_IP))


basic_constraints = x509.BasicConstraints(ca=True,path_length=0)
now =  datetime.utcnow()

cert = (
    x509.CertificateBuilder()
    .subject_name(name)
    .issuer_name(name)
    .public_key(key.public_key())
    .serial_number(1000)
    .not_valid_before(now)
    .not_valid_after(now+timedelta(days=365))
    .add_extension(basic_constraints,True)
    .add_extension(x509.SubjectAlternativeName(alt_name),False)
    .sign(key,hashes.SHA256(),default_backend())
)

my_cert_pem = cert.public_bytes(encoding=serialization.Encoding.PEM)
my_key_pem = key.private_bytes(
    encoding=serialization.Encoding.PEM,
    format = serialization.PrivateFormat.TraditionalOpenSSL,
    encryption_algorithm=serialization.NoEncryption(),
)

with open('cert_for_homeserver.crt','wb') as c:
    c.write(my_cert_pem)
with open('key_for_hs.key','wb') as c:
    c.write(my_key_pem)
