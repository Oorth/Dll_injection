cls
del main.pdb main.map main.ilk injection.obj main.obj main.exe injection.asm main.lib main.exp vc140.pdb 2>nul
cls
cl /EHsc /GS- /Oy /Zi .\main.cpp .\injection.cpp /link /OUT:main.exe /DEBUG /MAP
@REM cl /EHsc /GS- /Oy /Zi .\main.cpp .\injection.cpp /link /OUT:main.exe /DEBUG /MAP /DEF:main.def
@REM cl /EHsc /GS- /Oy /Zi .\main.cpp .\injection.cpp /link /OUT:main.exe /VERBOSE /DEBUG /MAP
@REM cl /c /EHsc /GS- /Oy /Zi /FAs .\injection.cpp