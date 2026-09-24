# İsteğe bağlı çevrimdışı IEEE MAC üretici dizini

Kali'de Nmap'in `/usr/share/nmap/nmap-mac-prefixes` dosyası varsayılan OUI kütüphanesidir. Güncel ve daha uzun önekli kayıtlar için IEEE'nin resmi kayıtlarından alınan `oui.csv`, `mam.csv` ve `mas.csv` dosyalarını bu klasöre yerleştirip `bash install.sh` komutunu çalıştırın. Uygulama hiçbir OUI dosyasını tarama sırasında indirmez.

Üretici ve servis ipuçları cihaz adayı çıkarır; MAC rastgele/yerel atanmış, başka adrese ortak veya hedef yönlendirici arkasındaysa model ve üretici kesinleşmez.
