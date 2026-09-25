# İsteğe bağlı çevrimdışı IEEE MAC üretici dizini

Kali'de Nmap'in `/usr/share/nmap/nmap-mac-prefixes` dosyası ve resmî Kali APT deposundaki `ieee-data` paketinin MA-L/MA-M/MA-S CSV kayıtları kullanılır. Kurulum ayrıca `ieee_registry.py` ile IEEE'nin resmî `oui.csv`, `mam.csv` ve `mas.csv` kayıtlarını yenilemeyi dener; başarılı dosyaların kaynağı ve SHA-256 özeti `SOURCE_MANIFEST.json` içinde tutulur. İndirme başarısızsa APT ve önceki kayıtlar korunur. Tarama sırasında OUI verisi indirilmez.

Üretici ve servis ipuçları cihaz adayı çıkarır; MAC rastgele/yerel atanmış, başka adrese ortak veya hedef yönlendirici arkasındaysa model ve üretici kesinleşmez.
