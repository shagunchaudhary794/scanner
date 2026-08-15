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
        
        print("Configs:")
        res = gmp.get_scan_configs()
        print(etree.tostring(res, pretty_print=True).decode('utf-8')[:500])
        
        print("Scanners:")
        res = gmp.get_scanners()
        print(etree.tostring(res, pretty_print=True).decode('utf-8')[:500])
        
except Exception as e:
    print(f"Error: {e}")
