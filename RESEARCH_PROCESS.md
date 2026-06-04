# Research and Analysis Methodology

Bu döküman, görev kapsamında iletilen kaynaklar (Legacyy makalesi ve CCob reposu) üzerinden "ThreadlessInject" ve "Data Pointer Hijacking" tekniklerini nasıl araştırıp öğrendiğimi ve bu yeni bilgilerle HijackHunter PoC'sini nasıl tasarladığımı açıklamaktadır. Ana geliştirme ortamımın Linux olması (Kernel-Eye projem) sebebiyle, süreci ağırlıklı olarak **"Statik Kaynak Kod Analizi (Source-Code Reversing)"** ve **"Bellek İzi Modelleme (Memory Footprint Modeling)"** metodolojisiyle yürüttüm.

## 1. ThreadlessInject Analiz Süreci

ThreadlessInject'in (CCob) GitHub reposundaki C# kaynak kodları incelendiğinde, geleneksel Process Injection yöntemlerinden (`CreateRemoteThread`) farklı bir yol izlediği tespit edilmiştir. 

### A. Davranışsal Analiz (Source-Code Review)
*   **Program.cs İncelemesi:** Repodaki ana saldırı mantığını barındıran `Program.cs` dosyası satır satır analiz edilmiş; bellek izlerini (memory footprints) modellediğim kritik satırlara (`VirtualAlloc`, `VirtualProtect` ve `0xE8` Assembly komutlarının çağrıldığı yerlere) çalışma/analiz notlarım eklenmiştir. Eklenen `Program.cs` dosyasındaki notlarımı inceleyebilirsiniz.
*   Saldırgan araç, hedef sürecin (örn. `notepad.exe`) bellek alanında `VirtualAllocEx` ile shellcode için yer açmakta ve `WriteProcessMemory` ile kodu yazmaktadır. (Bu adım klasik yöntemlerle aynıdır).
*   **Fark Yaratan Adım:** Araç, yeni bir thread açmak yerine, hedef sürecin hafızasında sık çağrılan bir sistem fonksiyonunu (örneğin `ntdll.dll` içindeki export edilmiş bir fonksiyonu) bulmaktadır.
*   `VirtualProtectEx` kullanılarak bu fonksiyonun bulunduğu `.text` bölümünün (RX) bellek koruması geçici olarak yazılabilir (`RWX`) hale getirilmektedir.
*   Fonksiyonun başlangıç (prologue) byte'ları, shellcode'a atlayan bir `JMP` (`0xE9`) veya `CALL` (`0xE8`) komutuyla ezilmektedir.

### B. Bellek İzi Hipotezi (Memory Footprint Modeling)
Bu statik analiz sonucunda, ThreadlessInject başarılı olduğunda hedef sürecin belleğinde şu **iki fiziksel izin** kalacağı teorik olarak modellenmiştir:
1.  **Av (Shellcode):** Hiçbir dosyaya bağlı olmayan (`MEM_PRIVATE`) ve çalıştırılabilir (`RX` veya `RWX`) bir bellek bloğu.
2.  **Kanca (Hook):** `MEM_IMAGE` (yüklü bir modül) olan bir bellek alanının `.text` bölümünde hedefe yönlendiren mantıksız bir atlama (`0xE9`) komutu.

**HijackHunter Mimarisi:** Bu teorik modelleme doğrultusunda, `VirtualQueryEx` ile tüm süreci tarayan ve hedef JMP adreslerinin "Unbacked" alanlara gidip gitmediğini doğrulayan bir tarayıcı geliştirilmiştir.

## 2. Data Pointer Hijacking Analiz Süreci

Legacyy'nin blog yazısı ve DataInject BOF (Beacon Object File) kodları incelendiğinde, ThreadlessInject'in zayıf noktası olan `VirtualProtect` çağrısından kaçınmak için farklı bir bellek bölgesinin hedeflendiği görülmüştür.

### Analiz Bulguları
*   EDR'ların kod bölümlerindeki (`.text`) modifikasyonları (Inline Hooks) sıkı takip etmesi sebebiyle, saldırı vektörü veri bölümüne (`.data` / `.rdata`) kaydırılmıştır.
*   `.data` bölümleri zaten okunabilir ve yazılabilir (`RW`) olduğu için `VirtualProtect` API'sine ihtiyaç duyulmamaktadır.
*   Özellikle `combase.dll` gibi `KnownDlls` yapılarındaki Control Flow Guard (CFG) pointer'ları (`__guard_check_icall_fptr`) hedeflenmektedir. Kaynak kod analizinde, doğrudan `WriteProcessMemory` ile bu pointer'ın shellcode alanına yönlendirildiği saptanmıştır.

**Tespit Geliştirmesi:** Bu analiz sonucunda, HijackHunter'ın ikinci modülü olarak; `MEM_IMAGE` alanlarının `PAGE_READWRITE` bölümlerindeki verilerin 8-byte'lık (64-bit) pointer'lar halinde okunması ve bu pointer'ların `MEM_PRIVATE` (Shellcode) alanlarını gösterip göstermediğinin kontrol edilmesi mantığı oluşturulmuştur.

