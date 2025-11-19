#!/bin/bash

# --- KONFIGURASI ---
warn_percentage_volume=5
warn_percentage_multi_ip=5
basepath=/opt/scripts/saslnotif
# ---------------------

domain=$(hostname -d)
date=$(date +%Y%m%d)

# --- Variabel File ---
mktemp_file="$basepath/mktemp"
mktemp2_file="$basepath/mktemp2"
whitelist_file="$basepath/whitelist"
account_tmp_file="$basepath/account_sasl_tmp"
geo_report_file="$basepath/geo_report.log"
success_log_temp="$basepath/success_log_temp"
processed_success_log="$basepath/processed_success.log"

# Hapus file temp dari eksekusi sebelumnya
> "$account_tmp_file"
> "$geo_report_file"
> "$success_log_temp"

# Buat file log 'processed_success' jika belum ada
touch "$processed_success_log"

# ======================================================================
# LANGKAH 1: Kumpulkan Log GAGAL (Top 40)
# ======================================================================
cat /var/log/zimbra.log | sed -n "s/.* warning: \([^[]\+\)\[\([0-9.]\+\)\].*sasl_username=\([^, ]\+\).*/\1 \2 \3/p" | sort -n | uniq -c | sort -nr | head -40 > "$mktemp_file"

# ======================================================================
# MODUL 1: Cek Serangan Volume & Buat Laporan GeoIP
# ======================================================================
echo "Menjalankan Modul 1: Pengecekan Volume & Pembuatan Laporan Geo..."
cat "$mktemp_file" | while read value host ip account_sasl; do
    
    geo_full=$(geoiplookup $ip)
    
    geo_ip=$(echo "$geo_full" | sed -n 's/GeoIP Country Edition: \([A-Z]\{2\}\).*/\1/p')
    geo_desc=$(echo "$geo_full" | sed 's/GeoIP Country Edition: //')

    # --- Integrasi Logika cek-geo.sh ---
    echo "$ip / $account_sasl / $geo_full" >> "$geo_report_file"
    echo "----------------------------------------------------------------------" >> "$geo_report_file"
    # ----------------------------------------

    if [ $value ]; then
        if [ $value -gt $warn_percentage_volume ]; then
            if ! grep -Fxq "$account_sasl" "$whitelist_file" && [ "$geo_ip" != 'ID' ]; then
                echo "MODUL 1 DETEKSI (TIDAK MENGUNCI): $account_sasl (Percobaan: $value, IP: $ip, Lokasi: $geo_desc)"
            fi
        fi
    fi
done

# ======================================================================
# MODUL 2: Cek Serangan Terdistribusi (Multi-IP)
# ======================================================================
echo "Menjalankan Modul 2: Pengecekan Multi-IP..."

cat "$mktemp_file" | awk '{print $4}' | sort -n | uniq -c > "$mktemp2_file"

cat "$mktemp2_file" | while read value account_sasl; do
    if [ $value ]; then
        if [ $value -gt $warn_percentage_multi_ip ]; then
            if ! grep -Fxq "$account_sasl" "$whitelist_file"; then
                echo "MODUL 2 DETEKSI (TIDAK MENGUNCI): $account_sasl (Diserang dari $value IP berbeda)"
            fi
        fi
    fi
done

# ======================================================================
# MODUL 3: Cek Sukses Login Pasca-Gagal (Kunci-Akun)
# ======================================================================
echo "Menjalankan Modul 3: Pengecekan Sukses Login dari IP Asing..."

# 1. Cari log SUKSES
cat /var/log/zimbra.log | grep 'sasl_username=' | grep -v 'warning:' | \
    sed -n "s/.* \([^[]\+\)\[\([0-9.]\+\)\].*sasl_username=\([^, ]\+\).*/\1 \2 \3/p" | sort -n | uniq > "$success_log_temp"

# 2. Coba format "client=" jika gagal
if [ ! -s "$success_log_temp" ]; then
    echo "Modul 3: Tidak menemukan log sukses dengan format pertama. Mencoba format 'client='..."
    cat /var/log/zimbra.log | grep 'sasl_username=' | grep -v 'warning:' | \
        sed -n "s/.* client=\([^[]\+\)\[\([0-9.]\+\)\].*sasl_username=\([^, ]\+\).*/\1 \2 \3/p" | sort -n | uniq > "$success_log_temp"
fi

cat "$success_log_temp" | while read host ip account_sasl; do
    
    geo_full=$(geoiplookup $ip)
    geo_ip=$(echo "$geo_full" | sed -n 's/GeoIP Country Edition: \([A-Z]\{2\}\).*/\1/p')
    geo_desc=$(echo "$geo_full" | sed 's/GeoIP Country Edition: //')

    if [ "$geo_ip" != 'ID' ]; then
        
        # === LOGIKA BARU DITAMBAHKAN DI SINI ===
        # Buat ID unik untuk kejadian ini (IP + Akun)
        event_id="$ip-$account_sasl"

        # Cek: Apakah akun ini ADA di daftar GAGAL (geo_report_file)?
        # Cek: Apakah akun ini BELUM dikunci oleh modul ini?
        # Cek: Apakah kejadian (event) ini BELUM PERNAH diproses?
        if grep -q "/ $account_sasl /" "$geo_report_file" && ! grep -Fxq "$account_sasl" "$account_tmp_file" && ! grep -Fxq "$event_id" "$processed_success_log"; then
            
            echo "MODUL 3 MENGUNCI (MENGIRIM EMAIL): $account_sasl (Sukses login dari IP asing [$ip, $geo_desc] setelah sebelumnya gagal)"

            # 1. Kunci Akun
            su - zimbra -c "zmprov ma $account_sasl zimbraAccountStatus locked"
            
            # 2. Catat
            echo "$account_sasl" >> "$account_tmp_file"
            
            # 3. CATAT KEJADIAN INI agar tidak diulang
            echo "$event_id" >> "$processed_success_log"

            # 4. Kirim notifikasi Tipe 3 (AKTIF)
            echo "Subject: [$HOSTNAME] AKUN DIKUNCI - LOGIN ASING BERHASIL $date
From: Admin <admin@$domain>
To: Admin <it-notif@example.com>

Akun $account_sasl telah dikunci otomatis.

Terdeteksi login SUKSES dari IP $ip (Lokasi: $geo_desc).

Akun ini dikunci karena IP tersebut berasal dari luar Indonesia(ID) dan akun ini sebelumnya
berada di daftar 40 teratas akun yang sedang diserang (brute-force).

Mohon segera reset password akun tersebut.
" | /opt/zimbra/common/sbin/sendmail -f admin@$domain it-notif@example.com
        
        fi
    fi
done

# ======================================================================
# LANGKAH 4: Pembersihan File Temporary
# ======================================================================
rm "$mktemp_file"
rm "$mktemp2_file"
rm "$success_log_temp"

echo "Skrip gabungan saslnotif selesai. Laporan Geo disimpan di $geo_report_file"
