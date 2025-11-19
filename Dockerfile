# 1. Gunakan image dasar Python yang ringan
FROM python:3.14-slim

# 2. Tentukan folder kerja di dalam "komputer virtual" (container)
WORKDIR /app

# 3. Salin file requirements.txt dulu (untuk caching yang efisien)
COPY requirements.txt .

# 4. Install library yang dibutuhkan
RUN pip install --no-cache-dir -r requirements.txt

# 5. Salin sisa kode proyek Anda ke dalam container
COPY . .

# 6. Beritahu Docker port mana yang akan dibuka
EXPOSE 5000

# 7. Perintah untuk menjalankan aplikasi saat container hidup
CMD ["python", "app.py"]