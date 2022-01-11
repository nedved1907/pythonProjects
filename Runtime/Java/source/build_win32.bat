@rem --------------------------------------------------------------------------
@rem 
@rem build the native JNI layer
@rem --------------------------------------------------------------------------

@if "%JDK%"=="" goto variable_undef

@if exist HASPJava.obj del HASPJava.obj
@if exist HASPJava.dll del HASPJava.dll

cl.exe -I"%JDK%\include" -I"%JDK%\include\win32" -I..\..\C\win32 -DSUN_JNI -c -Ox -Zl -Ob1 -Gy -DWIN32 -D_CRT_SECURE_NO_WARNINGS -D_X86_ -W3 -FoHASPJava.obj HASPJava.c
link.exe /DLL -out:HASPJava.dll HASPJava.obj ..\..\C\win32\libhasp_windows_demo.lib libcmt.lib kernel32.lib
@goto exit

:variable_undef
@echo.
@echo Error: please set the variable JDK first

:exit
