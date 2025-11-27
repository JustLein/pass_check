import re
import pandas as pd
import os

# --- Kelas AnalysisResult
class AnalysisResult:
    def __init__(self):
        self.isWeak = False
        self.weaknesses = []
        self.suggestions = []

# --- Kelas DictionaryLoader
class DictionaryLoader:
    def __init__(self, datasetPath):
        print(f"Mencoba memuat kamus dari: {datasetPath}...")
        self.kamus_set = set()
        try:
            df = pd.read_csv(datasetPath)
            if not df.empty:
                password_column_name = df.columns[0]
                print(f"Membaca dari kolom: '{password_column_name}'")
                for pw in df[password_column_name]:
                    if isinstance(pw, str):
                        self.kamus_set.add(pw.lower())
                print(f"Berhasil! {len(self.kamus_set)} kata sandi dimuat ke kamus.")
            else:
                print("--- ERROR: File csv kosong ---")
        except FileNotFoundError:
            print(f"--- ERROR FATAL: File dataset tidak ditemukan di '{datasetPath}' ---")
        except Exception as e:
            print(f"--- ERROR FATAL: Terjadi kesalahan saat memuat file csv: {e} ---")

    def isInDictionary(self, word):
        return word.lower() in self.kamus_set

# --- Kelas PasswordAnalyzer
class PasswordAnalyzer:
    
    def __init__(self, loader: DictionaryLoader):
        self.loader = loader

    def _checkBruteForce(self, password):
        weaknesses = []
        suggestions = []

        if len(password) < 8:
            weaknesses.append("BRUTEFORCE_LENGTH")
            suggestions.append("Gunakan minimal 8 karakter. Lebih baik 12+ karakter.")
        
        if not re.search(r"[a-z]", password):
            weaknesses.append("BRUTEFORCE_NO_LOWER")
            suggestions.append("Tambahkan huruf kecil (a-z).")
            
        if not re.search(r"[A-Z]", password):
            weaknesses.append("BRUTEFORCE_NO_UPPER")
            suggestions.append("Tambahkan huruf besar (A-Z).")
            
        if not re.search(r"[0-9]", password):
            weaknesses.append("BRUTEFORCE_NO_NUMBER")
            suggestions.append("Tambahkan angka (0-9).")
            
        if not re.search(r"[!@#$%^&*(),.?:{}|<>]", password):
            weaknesses.append("BRUTEFORCE_NO_SYMBOL")
            suggestions.append("Tambahkan simbol (contoh: !@#$).")
            
        return weaknesses, suggestions

    def _checkDictionary(self, password):
        weaknesses = []
        suggestions = []
        
        if self.loader.isInDictionary(password):
            weaknesses.append("DICTIONARY_MATCH")
            suggestions.append("Ganti total. Password yang Anda gunakan sudah terisi di kamus bocor.")
            
        return weaknesses, suggestions

    def _checkHybrid(self, password):
        """Aturan #3: Cek Hybrid (Pola Kata+Angka ATAU Angka+Kata)."""
        weaknesses = []
        suggestions = []
        
        # --- METODE 1: Strip & Check (Paling Ampuh) ---

        kata_bersih = "".join(filter(str.isalpha, password)).lower()
        
        # Syarat: Panjang kata > 2 (agar tidak mendeteksi singkatan pendek)
        if len(kata_bersih) > 2:
            if self.loader.isInDictionary(kata_bersih):
                weaknesses.append("HYBRID_MATCH")
                suggestions.append(f"Kata sandi ini mengandung kata umum '{kata_bersih}'. Pola angka+kata atau kata+angka sangat mudah ditebak.")
                return weaknesses, suggestions # Langsung lapor

        # --- METODE 2: Regex Pola Spesifik (Cadangan) ---
        

        match1 = re.fullmatch(r"([a-zA-Z]+)([0-9]+)", password)
        
        match2 = re.fullmatch(r"([0-9]+)([a-zA-Z]+)", password)
        
        kata_ditemukan = None
        
        if match1:
            kata_ditemukan = match1.group(1) 
        elif match2:
            kata_ditemukan = match2.group(2) 
            
        if kata_ditemukan:
            if self.loader.isInDictionary(kata_ditemukan):
                weaknesses.append("HYBRID_MATCH")
                suggestions.append(f"Pola umum: Angka digabung dengan kata umum '{kata_ditemukan}'. Hindari pola ini.")

        return weaknesses, suggestions

    # --- METODE (CheckSequence) ---
    
    def _checkSequenceAndKeyboard(self, password):
        weaknesses = []
        suggestions = []
        password_lower = password.lower()

        # 1. Cek Pengulangan (Repetition)
        for i in range(len(password) - 2):
            if password[i] == password[i+1] == password[i+2]:
                weaknesses.append("BRUTEFORCE_REPEAT")
                suggestions.append("Jangan mengulang karakter yang sama lebih dari 2 kali berturut-turut.")
                break 

        # 2. Cek Urutan (Sequence - abc/123)
        for i in range(len(password) - 2):
            # Maju
            if ord(password[i]) + 1 == ord(password[i+1]) and ord(password[i+1]) + 1 == ord(password[i+2]):
                weaknesses.append("BRUTEFORCE_SEQUENCE")
                suggestions.append("Hindari urutan alfabet/angka (misal: abc, 123).")
                break
            # Mundur
            if ord(password[i]) - 1 == ord(password[i+1]) and ord(password[i+1]) - 1 == ord(password[i+2]):
                weaknesses.append("BRUTEFORCE_SEQUENCE")
                suggestions.append("Hindari urutan mundur (misal: cba, 321).")
                break

        # 3. Cek Pola Keyboard (qwerty/asdf)
        keyboard_rows = ["qwertyuiop", "asdfghjkl", "zxcvbnm", "1234567890"]
        found_keyboard_pattern = False
        for i in range(len(password_lower) - 2):
            chunk = password_lower[i:i+3]
            for row in keyboard_rows:
                if chunk in row or chunk in row[::-1]:
                    found_keyboard_pattern = True
                    break
            if found_keyboard_pattern: break
        
        if found_keyboard_pattern:
            weaknesses.append("BRUTEFORCE_KEYBOARD") 
            suggestions.append("Hindari pola keyboard berurutan (misal: qwerty).")

        return weaknesses, suggestions
    
    # --- METODE UTAMA
    def analyze(self, password):
        result = AnalysisResult()
        
        if not password or not password.strip():
            result.isWeak = True
            result.weaknesses.append("INVALID_INPUT")
            result.suggestions.append("Kata sandi tidak boleh kosong atau hanya berisi spasi.")
            return result 

        bf_w, bf_s = self._checkBruteForce(password)
        result.weaknesses.extend(bf_w)
        result.suggestions.extend(bf_s)
        
        dict_w, dict_s = self._checkDictionary(password)
        result.weaknesses.extend(dict_w)
        result.suggestions.extend(dict_s)
        
        hyb_w, hyb_s = self._checkHybrid(password)
        result.weaknesses.extend(hyb_w)
        result.suggestions.extend(hyb_s)
        
        seq_w, seq_s = self._checkSequenceAndKeyboard(password)
        result.weaknesses.extend(seq_w)
        result.suggestions.extend(seq_s)

        if result.weaknesses:
            result.isWeak = True
        else:
            result.isWeak = False
            result.suggestions.append("Selamat! Kata sandi Anda kuat menurut aturan yang ada.")

        return result