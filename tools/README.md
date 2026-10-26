# tools

`build_bundle.py` expects `tools/winsw.exe` — WinSW v2.12.0 `WinSW.NET461.exe`
from <https://github.com/winsw/winsw/releases>.

SHA-256:

```text
b5066b7bbdfba1293e5d15cda3caaea88fbeab35bd5b38c41c913d492aadfc4f
```

The binary is not committed here. WinSW is distributed under the MIT license;
see the upstream repository for its license text. Download it, verify the hash,
and place it at `tools/winsw.exe` before running `python build_bundle.py`.
