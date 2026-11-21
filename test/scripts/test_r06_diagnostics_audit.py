#!/usr/bin/env python3
"""Synthetic ZIP negative controls; not actual APK acceptance."""
from pathlib import Path
import tempfile
import unittest
import warnings
import zipfile

import r06_diagnostics_audit as audit


class R06DiagnosticsAuditTest(unittest.TestCase):
    def apk(self, path, diagnostic, *, missing=None, omit=None, duplicate=False):
        with zipfile.ZipFile(path, 'x') as output:
            for abi in audit.ABIS:
                if abi == missing:
                    continue
                markers = b' '.join(marker for marker in audit.MARKERS if marker != omit) if diagnostic else b''
                output.writestr('lib/' + abi + '/libmullvad_jni.so', b'synthetic-not-ELF ' + markers)
            if duplicate:
                with warnings.catch_warnings():
                    warnings.simplefilter('ignore', UserWarning)
                    output.writestr('lib/x86/libmullvad_jni.so', b'duplicate')
        return path

    def test_all_four_normal_and_diagnostic_images_are_inspected(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            result = audit.compare(self.apk(root / 'normal', False), self.apk(root / 'diagnostic', True))
            for kind in ('normal', 'diagnostic'):
                self.assertEqual(list(audit.ABIS), [row['abi'] for row in result[kind]['jni']])
            self.assertTrue(all(not row['markers'] for row in result['normal']['jni']))
            self.assertTrue(all(len(row['markers']) == len(audit.MARKERS) for row in result['diagnostic']['jni']))

    def test_swapped_or_identical_artifacts_are_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            normal = self.apk(root / 'normal', False)
            diagnostic = self.apk(root / 'diagnostic', True)
            with self.assertRaisesRegex(ValueError, 'Normal JNI contains'):
                audit.compare(diagnostic, normal)
            with self.assertRaisesRegex(ValueError, 'identical'):
                audit.compare(normal, normal)

    def test_each_intended_boundary_must_be_present(self):
        for index, marker in enumerate(audit.MARKERS):
            with self.subTest(marker=marker), tempfile.TemporaryDirectory() as directory:
                apk = self.apk(Path(directory) / str(index), True, omit=marker)
                with self.assertRaisesRegex(ValueError, 'observations missing'):
                    audit.inspect(apk, True)

    def test_missing_abi_is_not_silently_skipped(self):
        for abi in audit.ABIS:
            with self.subTest(abi=abi), tempfile.TemporaryDirectory() as directory:
                apk = self.apk(Path(directory) / 'missing', True, missing=abi)
                with self.assertRaises(KeyError):
                    audit.inspect(apk, True)

    def test_duplicate_members_are_not_hidden_by_zip_lookup(self):
        with tempfile.TemporaryDirectory() as directory:
            apk = self.apk(Path(directory) / 'duplicate', True, duplicate=True)
            with self.assertRaisesRegex(ValueError, 'Duplicate APK members'):
                audit.inspect(apk, True)


if __name__ == '__main__':
    unittest.main()
