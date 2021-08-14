from functools import partialmethod
import os
import ctypes
import frida
import queue
import time
import threading
import zlib
import sys
import report

kernel32 = ctypes.windll.kernel32
chkdll = ctypes.CDLL("./check.dll")
mypath = os.path.split(os.path.realpath(__file__))[0]
process_handle = 0
utils = None
dump_queue = queue.Queue()

def OpenProcess(pid:int):
    return kernel32.OpenProcess(0x1fffff,False,pid)

def CheckMem(hProc,mem_addr):
    region_size = ctypes.c_size_t(0)
    region_base = ctypes.c_void_p(0)

    ret = chkdll.checkmem(ctypes.c_uint64(hProc),ctypes.c_uint64(mem_addr),ctypes.byref(region_size),ctypes.byref(region_base))
    #print("Region Size:  %d " % region_size.value)
    #print("Region Base:  0x%x " % region_base.value)
    return (ret,region_base.value,region_size.value)

def dumpMemLoop():
    while True:
        result = dump_queue.get()
        if result == -1:
            break
        data = utils.readmemory(result[1],result[2])
        crc_val = zlib.crc32(data)
        file_name = str(hex(result[1])) + '_' + str(crc_val)
        print(" [Dump Memory] Address: 0x%x ,  length: %d , crc32: %d , Save to => ./dump/%s" % (result[1],result[2],crc_val,file_name))
        f = open(mypath + "/dump/" + file_name,"wb")
        f.write(data)
        f.close()

def on_message(message, data):
    if message['type'] == 'send':
        payload = message['payload']
        stack = payload
        for addr in stack[:8]:
            result = CheckMem(process_handle,int(addr,16))
            if result[0]:
                print("   [!WARNING!] Detected on address => %s , Base: 0x%x , Size: %d " % (addr,result[1],result[2]))
                ###dump memory
                dump_queue.put(result)
                 
def ExecuteProgram(path,arg=''):
    pid = frida.spawn(path)
    session = frida.attach(pid)
    print("PID: {}".format(pid))
    return (session,pid)

def read_script(path):
    try:
        f = open(path,"r")
        content = f.read()
    except BaseException as e:
        print("read script failed,path: %s" % path)
        return ""
    finally:
        f.close()
    
    return content

def load_js(session):
    global utils
    script = session.create_script(read_script(mypath + "/trace.js"))
    script.on('message', on_message)
    script.load() 

    script_d = session.create_script(read_script(mypath + "/dump.js"))
    script_d.load()
    utils = script_d.exports

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("usage: check.py exe_path ")
        os._exit(0)
        
    exe_path = sys.argv[1]
    print("Target: %s " % exe_path)
    
    session,pid = ExecuteProgram(exe_path)
    load_js(session)

    process_handle = OpenProcess(pid)

    if process_handle:
        print("[+]Open process , handle: %d " % process_handle)
    else:
        print("[!]Open process failed! ")
        frida.kill(pid)
        os._exit(0)
    
    threading.Thread(target=dumpMemLoop).start()
    os.system("powershell -c rm .\\dump\\*")
    print("[*]Resume process")
    frida.resume(pid)

    print("[*]Wait 6 seconds...." )
    time.sleep(6)
    print("[!]Stop process...")
    dump_queue.put(-1)
    time.sleep(2)
    frida.kill(pid)
    print("[!]Trace finished")
    frida.shutdown()
    #################gen report######
    report.scan_dump_report()