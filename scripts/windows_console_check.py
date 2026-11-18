"""Exercise the proxy in a private Windows pseudoconsole; no parent console is changed."""
import ctypes as c
from ctypes import wintypes as w
import json
import msvcrt
import os
import queue
import subprocess
import sys
import threading
import time

if "--grandchild" in sys.argv:
    time.sleep(120)
    raise SystemExit(0)
if "--fixture" in sys.argv:
    grandchild = subprocess.Popen([sys.executable, __file__, "--grandchild"], creationflags=0x200, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    for line in sys.stdin:
        req = json.loads(line)
        print(json.dumps({"jsonrpc":"2.0", "id":req.get("id"), "result":{"grandchild_pid":grandchild.pid, "server_pid":os.getpid()}}), flush=True)
    raise SystemExit(0)

if sys.platform != "win32":
    raise SystemExit("Windows required")
K = c.WinDLL("kernel32", use_last_error=True)
H = w.HANDLE
class COORD(c.Structure):
    _fields_ = [("X", c.c_short), ("Y", c.c_short)]
class STARTUPINFO(c.Structure):
    _fields_ = [("cb",w.DWORD),("lpReserved",w.LPWSTR),("lpDesktop",w.LPWSTR),("lpTitle",w.LPWSTR),("dwX",w.DWORD),("dwY",w.DWORD),("dwXSize",w.DWORD),("dwYSize",w.DWORD),("dwXCountChars",w.DWORD),("dwYCountChars",w.DWORD),("dwFillAttribute",w.DWORD),("dwFlags",w.DWORD),("wShowWindow",w.WORD),("cbReserved2",w.WORD),("lpReserved2",c.c_void_p),("hStdInput",H),("hStdOutput",H),("hStdError",H)]
class STARTUPINFOEX(c.Structure):
    _fields_ = [("StartupInfo", STARTUPINFO), ("lpAttributeList", c.c_void_p)]
class PROCESS_INFORMATION(c.Structure):
    _fields_ = [("hProcess",H),("hThread",H),("dwProcessId",w.DWORD),("dwThreadId",w.DWORD)]
K.CreatePseudoConsole.argtypes = [COORD,H,H,w.DWORD,c.POINTER(H)]
K.CreatePseudoConsole.restype = c.c_long
K.ClosePseudoConsole.argtypes = [H]
K.InitializeProcThreadAttributeList.argtypes = [c.c_void_p,w.DWORD,w.DWORD,c.POINTER(c.c_size_t)]
K.UpdateProcThreadAttribute.argtypes = [c.c_void_p,w.DWORD,c.c_size_t,c.c_void_p,c.c_size_t,c.c_void_p,c.c_void_p]
K.DeleteProcThreadAttributeList.argtypes = [c.c_void_p]
K.CreateProcessW.argtypes = [w.LPCWSTR,w.LPWSTR,c.c_void_p,c.c_void_p,w.BOOL,w.DWORD,c.c_void_p,w.LPCWSTR,c.POINTER(STARTUPINFO),c.POINTER(PROCESS_INFORMATION)]
K.CreateProcessW.restype = w.BOOL
K.OpenProcess.argtypes = [w.DWORD,w.BOOL,w.DWORD]
K.OpenProcess.restype = H
K.WaitForSingleObject.argtypes = [H,w.DWORD]
K.GetExitCodeProcess.argtypes = [H,c.POINTER(w.DWORD)]
K.CloseHandle.argtypes = [H]
K.TerminateProcess.argtypes = [H,w.UINT]

def pipe():
    a,b = os.pipe()
    os.set_handle_inheritable(msvcrt.get_osfhandle(a), True)
    os.set_handle_inheritable(msvcrt.get_osfhandle(b), True)
    return a,b

def pump(fd, out):
    try:
        while True:
            part = os.read(fd, 4096)
            if not part: break
            out.put(part)
    except OSError:
        pass

def wait_contains(q, token, seconds=12):
    end=time.monotonic()+seconds
    data=b""
    while time.monotonic()<end:
        try: data += q.get(timeout=0.2)
        except queue.Empty: continue
        if token in data: return data
    raise RuntimeError("expected output was not observed")

def run():
    moat = os.path.abspath(sys.argv[1] if len(sys.argv)>1 else "target/debug/moat.exe")
    if not os.path.isfile(moat): raise RuntimeError("build moat first")
    ci,ciw=pipe(); co, cow=pipe(); ri,riw=pipe(); ro,row=pipe()
    os.set_handle_inheritable(msvcrt.get_osfhandle(ciw), False)
    os.set_handle_inheritable(msvcrt.get_osfhandle(co), False)
    os.set_handle_inheritable(msvcrt.get_osfhandle(riw), False)
    os.set_handle_inheritable(msvcrt.get_osfhandle(ro), False)
    hp=H()
    if K.CreatePseudoConsole(COORD(120,40), H(msvcrt.get_osfhandle(ci)), H(msvcrt.get_osfhandle(cow)), 0, c.byref(hp)) != 0: raise RuntimeError("CreatePseudoConsole failed")
    os.close(ci); os.close(cow)
    size=c.c_size_t()
    K.InitializeProcThreadAttributeList(None,1,0,c.byref(size))
    buf=c.create_string_buffer(size.value)
    if not K.InitializeProcThreadAttributeList(buf,1,0,c.byref(size)): raise c.WinError(c.get_last_error())
    if not K.UpdateProcThreadAttribute(buf,0,0x00020016,hp,c.sizeof(hp),None,None): raise c.WinError(c.get_last_error())
    si=STARTUPINFOEX(); si.StartupInfo.cb=c.sizeof(si); si.lpAttributeList=c.cast(buf,c.c_void_p)
    si.StartupInfo.dwFlags=0x100
    si.StartupInfo.hStdInput=H(msvcrt.get_osfhandle(ri))
    si.StartupInfo.hStdOutput=H(msvcrt.get_osfhandle(row))
    si.StartupInfo.hStdError=H(msvcrt.get_osfhandle(row))
    pi=PROCESS_INFORMATION()
    cmd=[moat,"wrap","--allow",os.environ.get("MOAT_TEST_TEMP",os.getcwd()),"--require-approval","--",sys.executable,os.path.abspath(__file__),"--fixture"]
    line=c.create_unicode_buffer(subprocess.list2cmdline(cmd))
    if not K.CreateProcessW(moat,line,None,None,True,0x00080000,None,None,c.byref(si.StartupInfo),c.byref(pi)): raise c.WinError(c.get_last_error())
    K.DeleteProcThreadAttributeList(buf); K.CloseHandle(pi.hThread); os.close(ri); os.close(row)
    con=queue.Queue(); rpc=queue.Queue()
    threading.Thread(target=pump,args=(co,con),daemon=True).start()
    threading.Thread(target=pump,args=(ro,rpc),daemon=True).start()
    grandchild_handle=None
    server_handle=None
    try:
        ping={"jsonrpc":"2.0","id":1,"method":"ping"}
        os.write(riw,(json.dumps(ping)+"\n").encode())
        reply=wait_contains(rpc,b'grandchild_pid')
        response=json.loads(next(line for line in reply.splitlines() if b'grandchild_pid' in line))
        grandchild_handle=K.OpenProcess(0x00100001,False,response["result"]["grandchild_pid"])
        if not grandchild_handle: raise c.WinError(c.get_last_error())
        server_handle=K.OpenProcess(0x00100001,False,response["result"]["server_pid"])
        if not server_handle: raise c.WinError(c.get_last_error())
        target=os.path.join(os.environ.get("MOAT_TEST_TEMP",os.getcwd()),"conpty-target.txt")
        req={"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"write_file","arguments":{"path":target,"content":"test"}}}
        os.write(riw,(json.dumps(req)+"\n").encode())
        wait_contains(con,b"Allow this operation?")
        os.write(ciw,b"y\r")
        wait_contains(rpc,b'grandchild_pid')
        print("PASS: CONIN$/CONOUT$ approval")
        os.write(ciw,b"\x03")
        if K.WaitForSingleObject(pi.hProcess,10000) != 0: raise RuntimeError("proxy did not exit after Ctrl+C")
        code=w.DWORD(); K.GetExitCodeProcess(pi.hProcess,c.byref(code))
        if code.value != 130: raise RuntimeError("unexpected Ctrl+C exit status")
        if K.WaitForSingleObject(grandchild_handle,5000) != 0: raise RuntimeError("grandchild survived")
        if K.WaitForSingleObject(server_handle,5000) != 0: raise RuntimeError("child survived")
        print("PASS: Ctrl+C exit 130 and child and grandchild terminated")
    finally:
        if K.WaitForSingleObject(pi.hProcess,0) != 0: K.TerminateProcess(pi.hProcess,1)
        if grandchild_handle:
            if K.WaitForSingleObject(grandchild_handle,0) != 0: K.TerminateProcess(grandchild_handle,1)
            K.CloseHandle(grandchild_handle)
        if server_handle:
            if K.WaitForSingleObject(server_handle,0) != 0: K.TerminateProcess(server_handle,1)
            K.CloseHandle(server_handle)
        K.CloseHandle(pi.hProcess)
        os.close(riw); os.close(ciw)
        K.ClosePseudoConsole(hp)

if __name__ == "__main__": run()
