Set shell = CreateObject("WScript.Shell")
Set fso = CreateObject("Scripting.FileSystemObject")

appDir = "C:\Users\anoth\Stuben"
agentPath = appDir & "\agent.py"
pythonwPath = "C:\Python314\pythonw.exe"

If Not fso.FolderExists(appDir) Or Not fso.FileExists(agentPath) Then
  MsgBox "Stuben app files were not found at:" & vbCrLf & appDir & vbCrLf & vbCrLf & _
         "Please restore the Stuben folder and then run this launcher again.", _
         vbExclamation, "Stuben startup error"
  WScript.Quit 1
End If

shell.CurrentDirectory = appDir
If fso.FileExists(pythonwPath) Then
  shell.Run """" & pythonwPath & """ """" & agentPath & """ desktop", 0, False
Else
  shell.Run "pyw -3 """" & agentPath & """ desktop", 0, False
End If
