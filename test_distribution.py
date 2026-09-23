import tempfile
import unittest
from pathlib import Path
import zipfile
from tools import check_distribution as check


class DistributionTests(unittest.TestCase):
    def test_secret_patterns_are_rejected_without_disclosing_values(self):
        token = b'gh' + b'p_' + b'a' * 36
        self.assertIn('github_token', check.content_findings(token))
        private_key = b'-----BEGIN ' + b'OPENSSH PRIVATE KEY-----'
        self.assertIn('private_key', check.content_findings(private_key))
        self.assertEqual([], check.content_findings(b"accessToken: '_', nickname: 'LocalGuest'"))

    def test_current_home_is_rejected_even_inside_original_binary(self):
        home = Path('/example-home')
        self.assertIn('current_user_home_path', check.content_findings(b'/example-home/file', binary=True, home=home))

    def test_archive_cannot_contain_profile_or_signing_material(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / 'test.ipa'
            with zipfile.ZipFile(path, 'w') as archive:
                archive.writestr('Payload/ArcherCat.app/embedded.mobileprovision', b'not a real profile')
            with self.assertRaises(ValueError): check.scan_ipa(path)

    def test_archive_cannot_escape_payload(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / 'test.ipa'
            with zipfile.ZipFile(path, 'w') as archive:
                archive.writestr('../outside', b'x')
            with self.assertRaises(ValueError): check.scan_ipa(path)


if __name__ == '__main__': unittest.main()
