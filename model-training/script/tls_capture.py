import subprocess
import json
import time
import requests 
import threading
import os 
# Thư viện cho việc thay đổi User-Agent
import random

USER_AGENTS = [
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36', # Chrome Win
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Safari/605.1.15', # Safari Mac
    'Mozilla/5.0 (Windows NT 10.0; WOW64; rv:126.0) Gecko/20100101 Firefox/126.0', # Firefox Win
    'Mozilla/5.0 (Linux; Android 14) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.6367.126 Mobile Safari/537.36', # Chrome Android
    'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36', # Chrome Linux
]

SURICATA_LOG = "logs/eve.json"
PCAP_FILE = "logs/traffic.pcap"

URLS = [
    # ----------------------------------
    # TECH & DEVELOPER
    # ----------------------------------
    "https://google.com",
    "https://youtube.com",
    "https://gmail.com",
    "https://github.com",
    "https://gitlab.com",
    "https://bitbucket.org",
    "https://stackoverflow.com",
    "https://serverfault.com",
    "https://superuser.com",
    "https://microsoft.com",
    "https://bing.com",
    "https://apple.com",
    "https://cloudflare.com",
    "https://mozilla.org",
    "https://facebook.com",
    "https://instagram.com",
    "https://twitter.com",
    "https://x.com",
    "https://linkedin.com",
    "https://slack.com",
    "https://dropbox.com",
    "https://zoom.us",
    "https://tiktok.com",
    "https://pinterest.com",
    "https://reddit.com",
    "https://tumblr.com",
    "https://quora.com",
    "https://netflix.com",
    "https://spotify.com", # Giữ nguyên như file
    "https://hulu.com",
    
    # ----------------------------------
    # VIETNAM NEWS
    # ----------------------------------
    "https://vnexpress.net",
    "https://tuoitre.vn",
    "https://zingnews.vn",
    "https://thanhnien.vn",
    "https://dantri.com.vn",
    "https://vtc.vn",
    "https://vov.vn",
    "https://laodong.vn",
    "https://vietnamnet.vn",
    "https://cafef.vn",
    "https://vietnambiz.vn",
    "https://baotintuc.vn",
    "https://nld.com.vn",
    "https://tienphong.vn",
    "https://plo.vn",
    
    # ----------------------------------
    # INTERNATIONAL NEWS
    # ----------------------------------
    "https://bbc.com",
    "https://cnn.com",
    "https://nytimes.com",
    "https://theguardian.com",
    "https://reuters.com",
    "https://bloomberg.com",
    "https://foxnews.com",
    "https://aljazeera.com",
    "https://wsj.com",
    "https://usatoday.com",
    "https://cnbc.com",
    "https://forbes.com",
    "https://ft.com",
    "https://time.com",
    "https://economist.com",
    "https://newsweek.com",
    "https://abcnews.go.com",
    "https://nbcnews.com",
    "https://sky.com",
    "https://apnews.com",
    
    # ----------------------------------
    # E-COMMERCE
    # ----------------------------------
    "https://shopee.vn",
    "https://tiki.vn",
    "https://lazada.vn",
    "https://sendo.vn",
    "https://dienmayxanh.com",
    "https://thegioididong.com",
    "https://fptshop.com.vn",
    "https://cellphones.com.vn",
    "https://meta.vn",
    "https://aeoneshop.com",
    "https://amazon.com",
    "https://ebay.com",
    "https://aliexpress.com",
    "https://rakuten.com",
    "https://etsy.com",
    "https://walmart.com",
    "https://bestbuy.com",
    "https://target.com",
    "https://alibaba.com",
    "https://newegg.com",
    
    # ----------------------------------
    # DEVOPS & CLOUD
    # ----------------------------------
    "https://aws.amazon.com",
    "https://cloud.google.com",
    "https://azure.microsoft.com",
    "https://digitalocean.com",
    "https://vercel.com",
    "https://netlify.com",
    "https://heroku.com",
    "https://oracle.com",
    "https://akamai.com",
    "https://cloudfront.net",
    "https://fastly.com",
    "https://linode.com",
    "https://openai.com",
    "https://anthropic.com",
    "https://datadoghq.com",
    "https://grafana.com",
    "https://kaggle.com",
    "https://hackerone.com",
    "https://bugcrowd.com",
    "https://terraform.i",
    
    # ----------------------------------
    # EDUCATION & RESEARCH
    # ----------------------------------
    "https://coursera.org",
    "https://edx.org",
    "https://udemy.com",
    "https://khanacademy.org",
    "https://codecademy.com",
    "https://geeksforgeeks.org",
    "https://w3schools.com",
    "https://freecodecamp.org",
    "https://springer.com",
    "https://ieee.org",
    "https://acm.org",
    "https://sciencedirect.com",
    "https://arxiv.org",
      "https://mit.edu",
    "https://stanford.edu",
    
    # ----------------------------------
    # BANKING (VIETNAM)
    # ----------------------------------
    "https://techcombank.com.vn",
    "https://mbbank.com.vn",
    "https://vietcombank.com.vn",
    "https://vib.com.vn",
    "https://bidv.com.vn",
    "https://tpb.vn",
    "https://acb.com.vn",
    "https://vpbank.com.vn",
    "https://hdbank.com.vn",
    "https://ocb.com.vn",
    
    # ----------------------------------
    # OTHER SERVICES
    # ----------------------------------
    "https://notion.so",
    "https://figma.com",
    "https://discord.com",
    "https://trello.com",
    "https://telegram.org",
    "https://whatsapp.com",
    "https://booking.com",
    "https://agoda.com",
    "https://airbnb.com",
    "https://expedia.com",
    "https://uber.com",
    "https://grab.com",
    "https://baemin.vn",
    "https://be.com.vn",
    "https://medium.com",
    "https://wordpress.com",
    "https://wikipedia.org",
    "https://imdb.com",
    "https://rottentomatoes.com",
    "https://soundcloud.com","https://researchgate.net",
    "https://nature.com",
    "https://sciencemag.org",
    "https://oxfordlearnersdictionaries.com",
    "https://cambridge.org",
  
]

print(f"Total Website: {len(URLS)}")

# def run_web_traffic():
#     # THAY ĐỔI: Lặp lại quá trình 10 lần (10 cycles) để tăng số lượng log
#     NUM_REPETITIONS = 10
    
#     for rep in range(NUM_REPETITIONS):
#         # THAY ĐỔI: Chọn User-Agent ngẫu nhiên cho mỗi chu kỳ lặp
#         current_ua = random.choice(USER_AGENTS) 
#         HEADERS = {'User-Agent': current_ua}
        
#         print(f"\n[CYCLE {rep+1}/{NUM_REPETITIONS}] Using UA: {current_ua[:60]}...")
        
#         for i, url in enumerate(URLS):
#             print(f"[{i+1}/{len(URLS)}] Fetching: {url}")
#             try:
#                 # Tăng timeout để xử lý các request bị chậm
#                 response = requests.get(url, headers=HEADERS, timeout=15, verify=False) 
                
#                 if response.status_code == 200:
#                     print(f"   -> Success: Status {response.status_code}")
#                 else:
#                     print(f"   -> Failed: Status {response.status_code}")
                    
#             except requests.exceptions.RequestException as e:
#                 print(f"   -> Connection Error: {e}")
            
#             # Giữ thời gian chờ để Suricata có thể xử lý và flush log
#             time.sleep(1) 
    
#     print("\n[+] All traffic generation cycles complete.")

def run_web_traffic():
    NUM_REPETITIONS = 10
    
    for rep in range(NUM_REPETITIONS):
        # THAY ĐỔI: Sử dụng Session để quản lý kết nối
        s = requests.Session() 
        
        current_ua = random.choice(USER_AGENTS) 
        HEADERS = {'User-Agent': current_ua}
        
        print(f"\n[CYCLE {rep+1}/{NUM_REPETITIONS}] Using UA: {current_ua[:60]}...")
        
        for i, url in enumerate(URLS):
            print(f"[{i+1}/{len(URLS)}] Fetching: {url}")
            try:
                # Dùng session.get() thay vì requests.get()
                # Gửi request bằng Session
                response = s.get(url, headers=HEADERS, timeout=15, verify=False) 
                
                if response.status_code == 200:
                    print(f"   -> Success: Status {response.status_code}")
                else:
                    print(f"   -> Failed: Status {response.status_code}")
                    
            except requests.exceptions.RequestException as e:
                print(f"   -> Connection Error: {e}")
            
            # Giữ thời gian chờ
            time.sleep(1) 
            
        # QUAN TRỌNG: Đóng Session sau mỗi Cycle để xóa cache TLS Session ID.
        # Điều này buộc request ở Cycle tiếp theo phải dùng Handshake đầy đủ.
        s.close()

if __name__ == "__main__":
    
    # Thiết lập thư mục làm việc 
    ROOT_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    os.chdir(ROOT_DIR)

    subprocess.run(["mkdir", "-p", "logs"])
    subprocess.run(["sudo", "rm", "-f", "/usr/var/run/suricata.pid"], check=False) 
    subprocess.run(["sudo", "rm", "-f", PCAP_FILE], check=False) # Xóa file pcap cũ

    # 1. KHỞI ĐỘNG TSHARK ĐỂ GHI GÓI TIN THÔ
    print("[+] Starting TShark live capture...")
    
    # DURATION phải đủ dài để quá trình requests hoàn thành
    # CAPTURE_DURATION = 60 
    # tshark_proc = subprocess.Popen([
    #     "sudo", "tshark", 
    #     "-i", "eth0", # Sử dụng eth0 đã xác định
    #     "-a", f"duration:{CAPTURE_DURATION}", 
    #     "-w", PCAP_FILE
    # ], stderr=subprocess.PIPE)
    
    tshark_proc = subprocess.Popen([
    "sudo", "tcpdump", 
    "-i", "eth0",
    "-w", PCAP_FILE
    # Không cần duration vì chúng ta sẽ dùng terminate()
], stderr=subprocess.PIPE)
    
    time.sleep(3) # Chờ TShark khởi động

    # 2. CHẠY LƯU LƯỢNG MẠNG
    run_web_traffic()
    
    # 3. DỪNG TSHARK & CHỜ FILE PCAP HOÀN THÀNH
    print(f"\n[+] Stopping TShark and waiting for {PCAP_FILE}...")
    tshark_proc.terminate()
    tshark_proc.wait(timeout=5)
    
    # 4. CHẠY SURICATA Ở CHẾ ĐỘ XỬ LÝ FILE PCAP
    print("[+] Starting Suricata processing PCAP file...")
    
    # Xóa file log cũ của Suricata trước khi ghi lại
    subprocess.run(["sudo", "rm", "-f", SURICATA_LOG], check=False) 

    suri_proc = subprocess.Popen([
        "sudo", "suricata", 
        "-r", PCAP_FILE, # <-- ĐỌC TỪ FILE PCAP
        "-c", "suricata.yaml",
        "-l", "logs"
    ])
    
    # Chờ Suricata xử lý file và thoát
    try:
        suri_proc.wait(timeout=15)
    except subprocess.TimeoutExpired:
        print("[-] Suricata timed out during file processing. Forcing terminate.")
        suri_proc.terminate()
        
    # Kiểm tra log cuối cùng
    time.sleep(1) 
    try:
        with open(SURICATA_LOG, "r") as f:
            tls_count = 0
            print(f"\n[+] SUCCESS: Printing ALL TLS logs found in {SURICATA_LOG}...")
            
            for line in f:
                if '\"event_type\":\"tls\"' in line:
                    event = json.loads(line)
                    # Lấy các trường bạn cần
                    sni = event["tls"].get("sni", "-")
                    ja3_hash = event["tls"].get("ja3", {}).get("hash", "-")
                    
                    # In ra log (in đầy đủ nếu có)
                    if ja3_hash != "-":
                         print(f"    [TLS {tls_count+1}] SNI={sni} | JA3={ja3_hash}")
                    else:
                         print(f"    [TLS {tls_count+1}] SNI={sni} | JA3=MISSING (Raw Log: {line.strip()[:100]}...)")
                         
                    tls_count += 1
                    
            print(f"\n[+] Total TLS events found: {tls_count}") # In ra tổng số
            
    except FileNotFoundError:
        print(f"[-] ERROR: {SURICATA_LOG} not found, Suricata processing may have failed.")
        
    print("\n[+] Finished. Check logs/eve.json for full data.")