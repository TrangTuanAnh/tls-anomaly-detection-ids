# Report
## Module 1
### Suricata
- cấu hình SPAN port ở chế độ Both (Bidirectional). Điều này đảm bảo Suricata bắt được cả gói tin Client Hello và Server Hello để trích xuất đầy đủ bộ vân tay JA3/JA3S của Firewall để copy toàn bộ lưu lượng đẩy vào dây cáp và dẫn qua một card mạng cụ thể của máy sensor.
- Card mạng Sensor (mode: Promiscuous): Chế độ Hỗn tạp (Promiscuous Mode) là lệnh bắt buộc để bảo card mạng nhận tất cả gói tin kể cả gói tin không gửi cho nó.
  - `ip link set <tên_card> promisc on`. Nếu không có chế độ này, card mạng sẽ tự động loại bỏ (drop) các gói tin không có MAC đích là chính nó, khiến Suricata bị "mù" dù dây cáp đã cắm đúng.
- Suricata(host mode): dùng chung mạng với host, đưa các gói tin bắt được vào container để sử lí 
- Lưu ý là máy sensor nên có 2 card mạng vật lí:
  - Card 1 (Management): Có IP để bạn SSH và Backend/Frontend hoạt động
  - Card 2 (Monitoring): Không cần IP, chỉ để cắm dây SPAN và chạy chế độ Promiscuous như bạn đã mô tả.