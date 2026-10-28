"""Publisher fixed profile contract; no service creation in unit tests."""
from pathlib import Path
import sys
import unittest
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'scripts'))
from inventory_refresh_publisher_profile import publisher_properties

class PublisherProfileTests(unittest.TestCase):
    def test_minimal_caps_private_network_and_fixed_write_roots(self):
        props=publisher_properties()
        for value in ('User=0','Group=0','CapabilityBoundingSet=CAP_CHOWN CAP_DAC_OVERRIDE',
                      'AmbientCapabilities=','NoNewPrivileges=yes','ProtectSystem=strict','PrivateNetwork=yes',
                      'KillMode=control-group','KillSignal=SIGKILL','OOMPolicy=kill','TasksMax=8'):
            self.assertIn(value,props)
        self.assertIn('TemporaryFileSystem=/etc:ro /var/lib:ro /run:ro /run/systemd/system:ro,nodev,nosuid,noexec,size=4k,nr_inodes=16',props)
        write=set(next(value for value in props if value.startswith('ReadWritePaths=')).split('=',1)[1].split())
        self.assertEqual(write,{'/var/cache/command-center-inventory-refresh','/var/lib/command-center-inventory-refresh',
                               '/run/command-center-inventory-refresh','/etc/command-center-inventory-refresh/apt'})
        read=next(value for value in props if value.startswith('BindReadOnlyPaths=')).split('=',1)[1].split()
        self.assertIn('/run/systemd/private',read)
        self.assertNotIn('/run/systemd/system',read)
        self.assertNotIn('/run',read);self.assertNotIn('/var/lib',read)
        self.assertNotIn('/etc',read)
        with self.assertRaises(TypeError):publisher_properties('caller command')

if __name__=='__main__':unittest.main()
