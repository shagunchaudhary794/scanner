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
        
        # Get port lists
        res = gmp.get_port_lists()
        
        print("Port Lists:")
        xml_str = etree.tostring(res, pretty_print=True).decode('utf-8')
        print(xml_str)
        
except Exception as e:
    print(f"Error: {e}")
