# -*- mode: python ; coding: utf-8 -*-
# 打包：pip install -r requirements.txt
#       pyinstaller dumptrace.spec
# 产物：dist/dumptrace.exe（单文件控制台）

block_cipher = None

a = Analysis(
    ['dumptrace.py'],
    pathex=[],
    binaries=[],
    datas=[],
    hiddenimports=[
        'dumptrace',
        'dumptrace.cli',
        'dumptrace.pipeline',
        'dumptrace.ingest',
        'dumptrace.ass_parser',
        'dumptrace.symbolizer',
        'dumptrace.rules',
        'dumptrace.credibility',
        'dumptrace.config',
        'dumptrace.export_scene',
        'dumptrace.batch',
        'dumptrace.timeline',
        'dumptrace.mem_stack',
        'dumptrace.callstack',
        'dumptrace.diff',
    ],
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[],
    win_no_prefer_redirects=False,
    win_private_assemblies=False,
    cipher=block_cipher,
    noarchive=False,
)

pyz = PYZ(a.pure, a.zipped_data, cipher=block_cipher)

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.zipfiles,
    a.datas,
    [],
    name='dumptrace',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    upx_exclude=[],
    runtime_tmpdir=None,
    console=True,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
)
