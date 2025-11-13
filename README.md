## Network Topology Visualizer

FastAPI tabanlı bir backend ve React + Tailwind arayüzü ile yerel ağınızdaki cihazları otomatik olarak keşfedip, Tron esintili neon-kırmızı bir topoğrafya üzerinde görselleştirmenizi sağlayan bir projedir.

---

## Özellikler

- **Düğüm Tabanlı Topoloji**: IP, MAC, hostname ve cihaz tipine göre düğümler
- **ARP Keşfi**: Scapy tabanlı ARP taraması ve pasif dinleme, nmap ve ARP tablosu geri dönüşleri
- **Nmap Port/Servis Taraması**: XML çıktı ile sağlam ayrıştırma, batch + paralel tarama
- **Etkileşimli Frontend**:
  - Düğümlere hover ile özet bilgi (IP, hostname, açık port sayısı)
  - Düğüme tıklayınca port / servis detaylarını gösteren bilgi kartı
  - Neon-kırmızı Tron teması, koyu arka plan
- **Ayrıntılı Loglama**: `/api/scan` isteğinde adım adım tarama log’ları (interface, ARP, Nmap batch bilgileri)

---

## Kurulum

### Sistem Bağımlılıkları (Debian/Ubuntu)

```bash
sudo apt update
sudo apt install nmap arp-scan python3-pip python3-venv
```

### Python Kurulumu

```bash
python3 -m venv venv
source venv/bin/activate  # Windows: venv\Scripts\activate

pip install -r requirements.txt
```

### Frontend Kurulumu

```bash
cd frontend
npm install
```

---

## Çalıştırma

### Geliştirme Ortamı

1. **Backend’i başlatın**

   > Tam ağ keşfi için root veya gerekli yetkiler gereklidir.

   ```bash
   source venv/bin/activate
   sudo venv/bin/python -m uvicorn backend.main:app --reload
   ```

   Backend varsayılan olarak `http://127.0.0.1:8000` adresinde çalışır.

2. **Frontend’i başlatın** (ayrı terminalde):

   ```bash
   cd frontend
   npm run dev
   ```

   Geliştirme arayüzü genellikle `http://localhost:5173` üzerinde çalışır.

### Production (Ön Yüz Derlenmiş)

```bash
cd frontend
npm run build

cd ..
source venv/bin/activate
sudo venv/bin/python -m uvicorn backend.main:app --reload
```

Derlenmiş frontend, FastAPI uygulaması tarafından `http://127.0.0.1:8000` üzerinden servis edilir.

---

## API Uç Noktaları

- `GET /api/health`
  - Servisin ayakta olup olmadığını döner.

- `GET /api/scan?timeout=60&ports=1-1024&debug=0`
  - Ağ taramasını başlatır.
  - Parametreler:
    - `timeout`: Tüm tarama için üst zaman sınırı (saniye, varsayılan `60`)
    - `ports`: Port aralığı (varsayılan `"1-1024"`, tüm portlar için `"-"`)
    - `debug`: Ayrıntılı verilerin dönülüp dönülmeyeceği (0 = kapalı, 1 = açık)
  - `debug=1` olduğunda JSON içinde `debug.steps`, `arp_discovery`, `nmap_results`, `nmap_steps` gibi alanlar da döner.

---

## Kullanım (Özet Akış)

1. `/api/scan` çağrısı yapılır (frontend üzerinden veya doğrudan HTTP ile).
2. Backend aşağıdaki adımları uygular:
   1. Varsayılan ağ arayüzünü ve gateway adresini tespit eder.
   2. ARP keşfi ile aktif cihazları bulur.
   3. Gerekirse nmap ile host discovery (ping sweep) yapar.
   4. Hedef IP listesini batch’lere bölerek nmap ile port/servis taraması yapar.
   5. Sonuçları tek bir topoloji JSON’unda birleştirir (`nodes` + `edges`).
3. Frontend bu JSON’u kullanarak düğüm-link grafiğini ve alt kısımdaki cihaz kartlarını oluşturur.

Tüm bu adımlar, log dosyalarına ve `debug.steps` alanına bilgi olarak yazılır.

---

## Ekran Görüntüleri

> Buraya proje ekran görüntüleri eklenecek.

- `docs/screenshots/` klasöründe PNG/JPEG dosyaları tutulabilir.

---

## Katkıda Bulunma

1. Bu repoyu fork’layın.
2. Yeni bir feature/bugfix branch’i açın.
3. Değişikliklerinizi yapın ve test edin.
4. Açık ve kısa bir açıklama ile Pull Request açın.

Kod stilinde:

- Python için `black` / `ruff` benzeri araçlarla biçimlendirme önerilir.
- Frontend tarafında React + Tailwind kullanılmakta; gereksiz inline stil yerine Tailwind sınıfları tercih edin.

---

## Lisans

Bu proje için lisans metni henüz eklenmemiştir.

- Örnek: MIT, Apache-2.0 veya GPL-3.0 kullanılabilir.
- Kurumsal gereksinimlerinize uygun lisansı seçip `LICENSE` dosyası ekleyin.

