# SafeSimpleOSINT

SafeSimpleOSINT adalah tool OSINT sederhana berbasis Python
yang dibuat untuk tujuan **edukasi dan pembelajaran**.

⚠️ Tool ini hanya boleh digunakan pada:
- Target milik sendiri
- Target yang kamu punya izin resmi

## Fitur
1. IP Geolocation
2. IP RDAP lookup
3. Domain RDAP lookup
4. DNS Resolve
5. GitHub User Lookup

## Cara Install
```bash
Installation (Linux)
git clone https://github.com/san154-af/SafeSimpleOSINT.git
cd SafeSimpleOSINT
pip3 install -r requirements.txt
python3 safe_simple_osint.py --yes

Update
cd SafeSimpleOSINT
git pull
pip3 install -r requirements.txt --upgrade
python3 safe_simple_osint.py --yes

Optional (Virtual Environment – Recommended)
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
python3 safe_simple_osint.py --yes

