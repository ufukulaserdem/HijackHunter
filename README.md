# HijackHunter - Control Flow Hijacking Detection PoC

Bu proje, **ThreadlessInject** ve **Data Pointer Hijacking (Control Flow Hijacking via Data Pointers)** gibi ileri seviye (stealth) process injection yöntemlerini analiz etmek ve tespit etmek amacıyla hazırlanmış teknik bir **Proof of Concept (PoC)** çalışmasıdır.

## 1. Analiz Edilen Yöntemler

### A. ThreadlessInject (Inline Hooking)
Geleneksel injection yöntemleri hedef process üzerinde yeni bir thread başlatırken (`CreateRemoteThread`), bu işlem güvenlik çözümleri (EDR, Sysmon Event ID 8 vb.) tarafından kolayca yakalanır. **ThreadlessInject** yöntemi ise hedef bellekte halihazırda sık çalışan bir fonksiyonu bulur, o bellek alanını `VirtualProtect` ile `RX`'ten `RWX`'e çeker ve fonksiyonun başlangıcına bir `JMP` (Atlama) komutu yazar (Inline Hook). Mevcut çalışan thread'ler bu fonksiyonu çağırdığında zararlı kod (shellcode) çalıştırılmış olur. Yeni thread açılmadığı için geleneksel tespit mekanizmalarından kaçar.

### B. Control Flow Hijacking via Data Pointers (Legacyy)
ThreadlessInject'in zayıf noktası, kod bölümünde (`.text`) yaptığı bellek koruma değişikliğidir (`VirtualProtect`). EDR'lar bu API çağrısını yakalayabilir. **Data Pointers** yöntemi bu durumu aşmak için halihazırda okunabilir/yazılabilir (`RW`) olan `.data` veya `.rdata` bölümlerini hedefler. Örneğin `combase.dll!__guard_check_icall_fptr` gibi sistem tarafından bilinen bir fonksiyon pointer'ı doğrudan shellcode alanını gösterecek şekilde ezilir (`WriteProcessMemory`). Herhangi bir bellek koruma izni değişikliğine gerek kalmadığı için çok daha gizli bir yöntemdir.

## 2. Tespit Yöntemleri (PoC)

Bu projede tespit mekanizmaları statik ve dinamik (runtime) olarak ikiye ayrılmıştır.

### Statik Tespit (YARA)
`static_rules/detections.yar` dizini altında bulunan kurallar:
- ThreadlessInject araçlarının bıraktığı string ve IAT (Import Address Table) paternlerini tarar.
- Data Pointer hijacking yapan BOF (Beacon Object File) yapılarını ve spesifik API serilerini (örn: `WriteProcessMemory` ile `__guard_check_icall_fptr` ilişkisi) statik olarak tespit eder.

### Runtime / Memory Tespit (Rust Scanner)
`src/main.rs` içerisinde yazılmış olan bellek tarayıcısı, hedef sürece ait bellek alanlarını Windows API'leri aracılığıyla (`VirtualQueryEx`, `ReadProcessMemory`) tarar.

**Nasıl Çalışır?**
1. **Unbacked Memory Tespiti:** Sistemdeki dosyalara bağlı olmayan (Private) ve çalıştırılabilir (`RX` / `RWX`) bellek alanlarını bularak potansiyel Shellcode adreslerini işaretler.
2. **Data Pointer Hijack Tespiti:** Hedef process'in yüklü modüllerine ait yazılabilir (`RW`) veri bölümlerini (`.data`) tarar. Buradaki pointer'ların yukarıda işaretlenen **unbacked shellcode alanlarına bakıp bakmadığını** tespit eder. Eğer bir pointer DLL sınırları dışına (shellcode'a) bakıyorsa alarm verir.
3. **Threadless Hook Tespiti:** Hedef process'in çalıştırılabilir (`RX`) bölümlerini tarar. `JMP` (`0xE9`) veya `CALL` (`0xE8`) komutlarının hedef adresini hesaplar. Eğer atlama yapılan yer bir **unbacked shellcode alanına düşüyorsa**, ThreadlessInject kullanıldığı tespit edilir.

## 3. Kurulum ve Kullanım

### Derleme
Bu araç Windows API'leri kullandığı için Windows üzerinde veya Linux'ta cross-compilation ile derlenmelidir.
```bash
# Linux üzerinden Windows için derleme
rustup target add x86_64-pc-windows-gnu
cargo build --release --target x86_64-pc-windows-gnu
```

### Kullanım
```bash
# Windows ortamında CMD veya PowerShell üzerinden çalıştırın
.\hijackhunter.exe <Hedef_PID>
```
Araç belleği tarayıp anormallikleri anında ekrana basacaktır.
