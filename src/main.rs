use std::env;
use std::mem;
use windows::Win32::Foundation::{CloseHandle, GetLastError};
use windows::Win32::System::Threading::{OpenProcess, PROCESS_QUERY_INFORMATION, PROCESS_VM_READ};
use windows::Win32::System::Memory::{
    VirtualQueryEx, MEMORY_BASIC_INFORMATION, MEM_PRIVATE, MEM_COMMIT, 
    PAGE_EXECUTE_READWRITE, PAGE_EXECUTE_READ, PAGE_EXECUTE, PAGE_READWRITE, MEM_IMAGE
};
use windows::Win32::System::Diagnostics::Debug::ReadProcessMemory;

fn main() {
    let args: Vec<String> = env::args().collect();
    if args.len() < 2 {
        println!("Usage: {} <PID>", args[0]);
        return;
    }

    let pid: u32 = args[1].parse().expect("Invalid PID");
    println!("[*] HijackHunter PoC started. Target PID: {}", pid);

    unsafe {
        // Open target process with read permissions
        let handle = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, false, pid);
        if handle.is_err() {
            println!("[-] Failed to open process. Try running as administrator. Error: {:?}", GetLastError());
            return;
        }
        let handle = handle.unwrap();

        // PHASE 1: Find unbacked (not file-backed) and executable memory regions (Shellcode detection)
        let mut suspicious_regions = Vec::new();
        let mut address: usize = 0;
        let mut mem_info = MEMORY_BASIC_INFORMATION::default();

        println!("[*] Scanning for suspicious memory regions (Shellcode)...");
        while VirtualQueryEx(
            handle,
            Some(address as *const _),
            &mut mem_info,
            mem::size_of::<MEMORY_BASIC_INFORMATION>(),
        ) != 0
        {
            if mem_info.State == MEM_COMMIT {
                let is_executable = mem_info.Protect == PAGE_EXECUTE_READWRITE || 
                                    mem_info.Protect == PAGE_EXECUTE_READ || 
                                    mem_info.Protect == PAGE_EXECUTE;
                
                // MEM_PRIVATE: Memory not mapped from a file (e.g., allocated via VirtualAlloc)
                if is_executable && mem_info.Type == MEM_PRIVATE {
                    println!("[!] Suspicious (Unbacked + Executable) region found! Address: 0x{:X} (Size: {})", 
                        mem_info.BaseAddress as usize, mem_info.RegionSize);
                    suspicious_regions.push(mem_info);
                }
            }
            address = mem_info.BaseAddress as usize + mem_info.RegionSize;
        }

        if suspicious_regions.is_empty() {
            println!("[+] No injected shellcode region found in memory. Process looks clean.");
            let _ = CloseHandle(handle);
            return;
        }

        // PHASE 2: Scan Data and Text sections of loaded modules for Hijack/Hook situations
        println!("[*] Scanning loaded modules for 'Data Pointer Hijack' and 'Threadless Hook'...");

        address = 0;
        while VirtualQueryEx(
            handle,
            Some(address as *const _),
            &mut mem_info,
            mem::size_of::<MEMORY_BASIC_INFORMATION>(),
        ) != 0
        {
            // Scan only memory regions belonging to loaded modules (MEM_IMAGE)
            if mem_info.State == MEM_COMMIT && mem_info.Type == MEM_IMAGE {
                let mut buffer = vec![0u8; mem_info.RegionSize];
                let mut bytes_read = 0;

                // A) DATA POINTER HIJACKING DETECTION (Legacyy Method)
                // Scans readable/writable (RW) sections like .data or .rdata
                if mem_info.Protect == PAGE_READWRITE {
                    if ReadProcessMemory(handle, mem_info.BaseAddress, buffer.as_mut_ptr() as *mut _, buffer.len(), Some(&mut bytes_read)).is_ok() {
                        // Read and check as 8-byte pointers
                        for i in (0..bytes_read).step_by(8) {
                            if i + 8 <= bytes_read {
                                let mut ptr_bytes = [0u8; 8];
                                ptr_bytes.copy_from_slice(&buffer[i..i+8]);
                                let ptr_val = u64::from_le_bytes(ptr_bytes) as usize;

                                // Does this pointer point to one of our suspicious shellcode regions?
                                for sus_reg in &suspicious_regions {
                                    let sus_start = sus_reg.BaseAddress as usize;
                                    let sus_end = sus_start + sus_reg.RegionSize;

                                    if ptr_val >= sus_start && ptr_val < sus_end {
                                        println!("--------------------------------------------------");
                                        println!("[!!!] DATA POINTER HIJACK DETECTED [!!!]");
                                        println!("      Detection Site : Module RW (Data) Section (0x{:X})", mem_info.BaseAddress as usize);
                                        println!("      Overwritten Ptr: 0x{:X}", mem_info.BaseAddress as usize + i);
                                        println!("      Target Dest    : Suspicious Shellcode (0x{:X})", ptr_val);
                                        println!("--------------------------------------------------");
                                    }
                                }
                            }
                        }
                    }
                }

                // B) THREADLESS INJECT / INLINE HOOK DETECTION
                // Scans executable (RX) sections like .text
                if mem_info.Protect == PAGE_EXECUTE_READ {
                    if ReadProcessMemory(handle, mem_info.BaseAddress, buffer.as_mut_ptr() as *mut _, buffer.len(), Some(&mut bytes_read)).is_ok() {
                        for i in 0..bytes_read {
                            // 0xE9 = JMP rel32, 0xE8 = CALL rel32
                            if buffer[i] == 0xE9 || buffer[i] == 0xE8 {
                                if i + 5 <= bytes_read {
                                    let mut rel_bytes = [0u8; 4];
                                    rel_bytes.copy_from_slice(&buffer[i+1..i+5]);
                                    let rel_offset = i32::from_le_bytes(rel_bytes);
                                    
                                    let instr_addr = mem_info.BaseAddress as usize + i;
                                    // Target Address = Instruction Address + 5 (instruction length) + Relative Offset
                                    let target_addr = instr_addr.wrapping_add(5).wrapping_add(rel_offset as usize);

                                    // Does the jump (JMP/CALL) target one of our suspicious shellcode regions?
                                    for sus_reg in &suspicious_regions {
                                        let sus_start = sus_reg.BaseAddress as usize;
                                        let sus_end = sus_start + sus_reg.RegionSize;

                                        if target_addr >= sus_start && target_addr < sus_end {
                                            let hook_type = if buffer[i] == 0xE9 { "JMP" } else { "CALL" };
                                            println!("--------------------------------------------------");
                                            println!("[!!!] THREADLESS / INLINE HOOK DETECTED [!!!]");
                                            println!("      Detection Site : Module RX (Code) Section (0x{:X})", mem_info.BaseAddress as usize);
                                            println!("      Hook Type      : {} instruction (at 0x{:X})", hook_type, instr_addr);
                                            println!("      Target Dest    : Suspicious Shellcode (0x{:X})", target_addr);
                                            println!("--------------------------------------------------");
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
            address = mem_info.BaseAddress as usize + mem_info.RegionSize;
        }

        let _ = CloseHandle(handle);
        println!("[*] Scan completed.");
    }
}
