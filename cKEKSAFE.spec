# -*- mode: python ; coding: utf-8 -*-

from PyInstaller.utils.hooks import collect_data_files

customtkinter_datas = collect_data_files('customtkinter')
asset_datas = [
    ('assets/logo-red-black.png', 'assets'),
    ('assets/logo-red-black.ico', 'assets'),
    ('assets/logo-red-black-sidebar.png', 'assets'),
]

a = Analysis(
    ['cKEKSAFE.py'],
    pathex=[],
    binaries=[],
    datas=customtkinter_datas + asset_datas,
    hiddenimports=[],
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[],
    noarchive=False,
    optimize=0,
)
pyz = PYZ(a.pure)

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.datas,
    [],
    name='cKEKSAFE',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    upx_exclude=[],
    runtime_tmpdir=None,
    console=False,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
    icon='assets/logo-red-black.ico',
)
