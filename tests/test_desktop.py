"""Run directory and tool attribution checks (no external scanning)."""
import os
from pathlib import Path
import sys
import tempfile
import types
import unittest
from unittest.mock import patch

sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
import wizard


class DesktopTests(unittest.TestCase):
    def test_desktop_user_gets_private_report_directory(self):
        with tempfile.TemporaryDirectory() as temp:
            (Path(temp)/"Desktop").mkdir()
            fake=types.SimpleNamespace(pw_dir=temp,pw_gid=1000)
            with patch.dict(os.environ,{"SUDO_UID":"1000"}),patch.object(wizard.pwd,"getpwuid",return_value=fake),patch.object(wizard.os,"chown"):
                directory,owner=wizard.choose_run_base()
            self.assertEqual(directory,Path(temp)/"Desktop"/"UBDEN-Cyber-Reports")
            self.assertEqual(directory.stat().st_mode & 0o777,0o700)
            self.assertEqual(owner,(1000,1000) if os.geteuid()==0 else None)

    def test_symlink_reports_directory_is_rejected(self):
        with tempfile.TemporaryDirectory() as temp:
            desktop=Path(temp)/"Desktop";desktop.mkdir()
            (desktop/"UBDEN-Cyber-Reports").symlink_to(Path(temp))
            fake=types.SimpleNamespace(pw_dir=temp,pw_gid=1000)
            with patch.dict(os.environ,{"SUDO_UID":"1000"}),patch.object(wizard.pwd,"getpwuid",return_value=fake):
                with self.assertRaises(SystemExit): wizard.choose_run_base()


if __name__ == '__main__': unittest.main()
