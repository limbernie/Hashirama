@echo off
cl -nologo -EHa- -GR- -GS- -Od  -Oi Hashirama.cpp -link -nodefaultlib -subsystem:windows kernel32.lib