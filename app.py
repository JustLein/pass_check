from flask import Flask, request, jsonify, render_template
from analyze import PasswordAnalyzer, DictionaryLoader
from flask_cors import CORS

# Inisialisasi Server dan Memuat Dataset
print("--- Server Flask Mulai Berjalan ---")

# 1. Tentukan lokasi dataset Anda
# (Pastikan file ini ada di folder yang sama dengan app.py)
DATASET_FILE = "common_password_data.csv" 

# 2. (DictionaryLoader)
my_loader = DictionaryLoader(DATASET_FILE)

# 3. (PasswordAnalyzer)
my_analyzer = PasswordAnalyzer(my_loader)

print("--- Server Siap Menerima Permintaan ---")

# Buat aplikasi Flask
app = Flask(__name__)
# MENJADI SEPERTI INI:
# Tambahkan CORS untuk mengizinkan 'fetch' dari file HTML
CORS(app) 

# --- ENDPOINT / ALAMAT URL ---

@app.route("/", methods=["GET"])
def index():
    """
    Rute ini bertugas menyajikan file 'index.html' 
    yang ada di dalam folder 'templates'.
    (Ini adalah metode Jinja/Server-Side, jika Anda mau)
    """
    return render_template("index.html")

@app.route("/analyze", methods=["POST"])
def handle_analysis():
    """
    Rute API ini adalah yang akan dipanggil oleh JavaScript.
    Tugasnya menerima JSON, memanggil 'Koki', dan mengembalikan JSON.
    """
    # 1. Ambil kata sandi dari data JSON yang dikirim HTML
    data = request.json
    password_input = data.get("password")

    # 2. Panggil PasswordAnalyzer untuk menganalisis
    hasil_objek = my_analyzer.analyze(password_input)

    # 3. Ubah objek hasil menjadi format dictionary agar bisa dikirim sebagai JSON
    hasil_dict = {
        "isWeak": hasil_objek.isWeak,
        "weaknesses": hasil_objek.weaknesses,
        "suggestions": hasil_objek.suggestions
    }
    
    # 4. Kembalikan hasilnya ke HTML
    return jsonify(hasil_dict)


# --- Perintah untuk Menjalankan Server ---
if __name__ == "__main__":
    # app.run(debug=True) akan otomatis me-restart server jika Anda mengubah kode
    app.run(host="0.0.0.0", port=5000, debug=True)