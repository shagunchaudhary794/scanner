import os
from gvm.protocols.gmp import Gmp
from gvm.transforms import EtreeTransform
from lxml import etree

socket_path = "/run/gvmd/gvmd.sock"
try:
    gvm_host = os.environ.get('GVM_HOST')
    if gvm_host:
        from gvm.connections import TLSConnection
        connection = TLSConnection(hostname=gvm_host, port=int(os.environ.get('GVM_PORT', 9390)))
    else:
        from gvm.connections import UnixSocketConnection
        connection = UnixSocketConnection(path=socket_path)
    transform = EtreeTransform()
    
    with Gmp(connection=connection, transform=transform) as gmp:
        gmp.authenticate('admin', 'admin')
        
        target = "127.0.0.1"
        target_name = f"Target-{target}-test"
        print(f"Creating target {target_name}...")
        
        from gvm.protocols.gmp.requests.v224 import AliveTest
        res = gmp.create_target(name=target_name, hosts=[target], alive_test=AliveTest.CONSIDER_ALIVE)
        
        # Print raw response
        print("Response received:")
        xml_str = etree.tostring(res, pretty_print=True).decode('utf-8')
        print(xml_str)
        
        # Check id
        target_id = res.xpath('//@id')
        print(f"Extracted IDs: {target_id}")

except Exception as e:
    print(f"Error: {e}")
