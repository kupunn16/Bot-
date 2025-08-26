from flask import Flask, render_template, request, jsonify
import requests
import subprocess
import os

app = Flask(__name__)

CS2_PROCESS_NAME = "cs2.exe"
TARGET_URL = "https://github.com/yourusername/cs2-cheat/releases/latest/download/cheat.dll"

INJECTOR_SCRIPT = """
using System;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Net;

namespace WebInjector
{
    class Program
    {
        [DllImport("kernel32.dll")]
        static extern IntPtr OpenProcess(int dwDesiredAccess, bool bInheritHandle, int dwProcessId);

        [DllImport("kernel32.dll", CharSet = CharSet.Auto)]
        static extern IntPtr GetModuleHandle(string lpModuleName);

        [DllImport("kernel32", CharSet = CharSet.Ansi, ExactSpelling = true, SetLastError = true)]
        static extern IntPtr GetProcAddress(IntPtr hModule, string procName);

        [DllImport("kernel32.dll", SetLastError = true, ExactSpelling = true)]
        static extern IntPtr VirtualAllocEx(IntPtr hProcess, IntPtr lpAddress, uint dwSize, uint flAllocationType, uint flProtect);

        [DllImport("kernel32.dll", SetLastError = true)]
        static extern bool WriteProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, byte[] lpBuffer, uint nSize, out UIntPtr lpNumberOfBytesWritten);

        [DllImport("kernel32.dll")]
        static extern IntPtr CreateRemoteThread(IntPtr hProcess, IntPtr lpThreadAttributes, uint dwStackSize, IntPtr lpStartAddress, IntPtr lpParameter, uint dwCreationFlags, IntPtr lpThreadId);

        const int PROCESS_ALL_ACCESS = 0x1F0FFF;
        const uint MEM_COMMIT = 0x00001000;
        const uint MEM_RESERVE = 0x00002000;
        const uint PAGE_READWRITE = 4;

        static void Main(string[] args)
        {
            try
            {
                WebClient client = new WebClient();
                string dllPath = "cheat.dll";
                client.DownloadFile("{{dll_url}}", dllPath);

                Process[] processes = Process.GetProcessesByName("{{process_name}}");
                if (processes.Length == 0) return;

                Process targetProcess = processes[0];
                IntPtr processHandle = OpenProcess(PROCESS_ALL_ACCESS, false, targetProcess.Id);

                IntPtr allocMem = VirtualAllocEx(processHandle, IntPtr.Zero, (uint)dllPath.Length, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

                UIntPtr bytesWritten;
                WriteProcessMemory(processHandle, allocMem, System.Text.Encoding.ASCII.GetBytes(dllPath), (uint)dllPath.Length, out bytesWritten);

                IntPtr loadLibraryAddr = GetProcAddress(GetModuleHandle("kernel32.dll"), "LoadLibraryA");
                CreateRemoteThread(processHandle, IntPtr.Zero, 0, loadLibraryAddr, allocMem, 0, IntPtr.Zero);
            }
            catch { }
        }
    }
}
"""

def download_dll():
    try:
        response = requests.get(TARGET_URL)
        with open('cheat.dll', 'wb') as f:
            f.write(response.content)
        return True
    except:
        return False

def compile_injector():
    with open('WebInjector.cs', 'w') as f:
        f.write(INJECTOR_SCRIPT.replace('{{dll_url}}', TARGET_URL)
                             .replace('{{process_name}}', CS2_PROCESS_NAME))
    
    result = subprocess.run(['csc', 'WebInjector.cs'], capture_output=True)
    return result.returncode == 0

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/api/inject', methods=['POST'])
def api_inject():
    try:
        if not download_dll():
            return jsonify({'status': 'error', 'message': 'DLL download failed'})

        if not compile_injector():
            return jsonify({'status': 'error', 'message': 'Compilation failed'})

        subprocess.Popen(['WebInjector.exe'], shell=True)
        return jsonify({'status': 'success', 'message': 'Injection started'})
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)})

@app.route('/api/status')
def api_status():
    return jsonify({'status': 'online', 'version': '1.0'})

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)
