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

    # --- METODE ATURAN
    
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
            suggestions.append("Kata sandi ini ada di daftar kata sandi bocor. Ganti total.")
            
        return weaknesses, suggestions

    def _checkHybrid(self, password):
        weaknesses = []
        suggestions = []
        
        match = re.fullmatch(r"([a-zA-Z]+)([0-9]+)", password)
        if match:
            kata_bagian = match.group(1)
            if self.loader.isInDictionary(kata_bagian):
                weaknesses.append("HYBRID_MATCH")
                suggestions.append(f"Ini adalah pola 'kata' umum ('{kata_bagian}') diikuti angka. Hindari pola ini.")
                
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

        if result.weaknesses:
            result.isWeak = True
        else:
            result.isWeak = False
            result.suggestions.append("Selamat! Kata sandi Anda kuat menurut aturan yang ada.")

        return result