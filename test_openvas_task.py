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
        
        # 1. Get Port List
        res = gmp.get_port_lists(filter_string="name=All IANA assigned TCP")
        port_lists = res.xpath('port_list/@id')
        if not port_lists:
            print("Could not find port list")
            exit(1)
        port_list_id = port_lists[0]
        
        # 2. Get Config
        res = gmp.get_scan_configs(filter_string="name=Base")
        configs = res.xpath('config/@id')
        if not configs:
            print("Could not find Base config")
            res_all = gmp.get_scan_configs()
            print("Available configs:", [c.xpath('name/text()')[0] for c in res_all.xpath('config')])
            exit(1)
        config_id = configs[0]
        
        # 3. Get Scanner
        res = gmp.get_scanners(filter_string="name=CVE")
        scanners = res.xpath('scanner/@id')
        if not scanners:
            print("Could not find CVE scanner")
            res_all = gmp.get_scanners()
            print("Available scanners:", [c.xpath('name/text()')[0] for c in res_all.xpath('scanner')])
            exit(1)
        scanner_id = scanners[0]
        
        target = "127.0.0.1"
        target_name = f"Target-{target}-test-2"
        
        # 4. Create Target
        from gvm.protocols.gmp.requests.v224 import AliveTest
        res = gmp.create_target(name=target_name, hosts=[target], port_list_id=port_list_id, alive_test=AliveTest.CONSIDER_ALIVE)
        status = res.get('status')
        if status != '201':
            print(f"Error creating target: {res.get('status_text')}")
            exit(1)
            
        target_id = res.xpath('//@id')[0]
        print(f"Target ID: {target_id}")
        
        # 5. Create Task
        task_name = f"Task-{target}-test"
        res = gmp.create_task(name=task_name, config_id=config_id, target_id=target_id, scanner_id=scanner_id)
        status = res.get('status')
        if status != '201':
            print(f"Error creating task: {res.get('status_text')}")
            exit(1)
            
        task_id = res.xpath('//@id')[0]
        print(f"Task ID: {task_id}")
        
except Exception as e:
    print(f"Exception: {e}")
