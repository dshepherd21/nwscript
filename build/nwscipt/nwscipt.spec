# -*- mode: python -*-
a = Analysis(['nwscipt.py'],
             pathex=['C:\\nwscript\\build\\nwscipt'],
             hiddenimports=['pyad', 'IPy'],
             hookspath=None,
             runtime_hooks=None)
pyz = PYZ(a.pure)
exe = EXE(pyz,
          a.scripts,
          a.binaries,
          a.zipfiles,
          a.datas,
          name='nwscipt.exe',
          debug=False,
          strip=None,
          upx=True,
          console=True )
