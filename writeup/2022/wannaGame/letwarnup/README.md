# cnsc.uit.edu.vn - letwarnup

Link challenge gốc (closed, inactive): [https://cnsc.uit.edu.vn/ctf/challenges](https://cnsc.uit.edu.vn/ctf/challenges)

Các bạn có thể tải challenge ở ngay repo của mình: [letwarnup.zip](letwarnup.zip)

Challenge sẽ bao gồm 2 file: 
- letwarnup
- libc-2.31.so

Các bạn tải về và patch file libc-2.31.so vào file letwarnup bằng [patchelf](https://github.com/NixOS/patchelf) hoặc [pwninit](https://github.com/io12/pwninit) nhé. Và bây giờ chúng ta bắt đầu nào!

# 1. Tìm lỗi
Đầu tiên, dùng lệnh `file` để xem file thực thi có những gì:
```
letwarnup: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, BuildID[sha1]=7544e1f18055de6fd54ff658d5e979b125964440, for GNU/Linux 3.2.0, not stripped
```
Đây là file 64-bit không bị mã hóa code nên ta có thể dễ dàng tìm kiếm function trong ghidra cũng như gdb.

Tiếp theo, ta sẽ mở file bằng ghidra, ở đây ta có 2 function chính là main() và vuln()

![main](https://raw.githubusercontent.com/nhtri2003gmail/writeup-cnsc.uit.edu.vn-letwarnup/master/images/main.png)

![vuln](https://raw.githubusercontent.com/nhtri2003gmail/writeup-cnsc.uit.edu.vn-letwarnup/master/images/vuln.png)

Nhận thấy ở vuln(), câu lệnh printf có lỗi khi bị thiếu "%s" --> Lỗi format string.

Kế đến, ta sẽ kiểm tra file bằng checksec:
```
Arch:     amd64-64-little
RELRO:    Partial RELRO
Stack:    No canary found
NX:       NX enabled
PIE:      No PIE (0x400000)
```
Ta thấy chỉ có NX được bật

# 2. Ý tưởng
Thông thường, khi NX được bật và có lỗi format string thì ta sẽ xài kỹ thuật ret2libc bằng cách overwrite các GOT.

- Ý tưởng đầu tiên:

Ban đầu ta nghĩ là sẽ overwrite cái exit(0) trong vuln() thành system@got trong libc nhưng khi kiểm tra trong gdb thì exit@got nó không có địa chỉ của libc nên việc ghi địa chỉ thế vào sẽ phức tạp.

Tuy nhiên, vì exit(0) có địa chỉ giống với địa chỉ chương trình --> overwrite exit(0) với địa chỉ đầu của hàm vuln() để chương trình lặp lại và ta có thể đưa payload vào.

- Ý tưởng thứ hai:

Khi chương trình lặp lại hàm vuln(), ta sẽ overwrite hàm nào đó thành system và truyền địa chỉ "/bin/sh" trong libc vào để tạo shell. Tuy nhiên khi thực hiện thì ta gặp khó khăn (thực thi chương trình rồi nhưng không tạo được shell) nên ta chuyển sang ý tưởng thứ ba.

- Ý tưởng thứ ba:

Ta nhận thấy có hàm fgets để nhập dữ liệu vào và kế tiếp là printf cái biến ta mới nhập vào --> Overwrite printf thành system và ta nhập chuỗi "/bin/sh" tại fgets để tạo shell

- Tổng kết ý tưởng:
  - Overwrite exit(0) với địa chỉ đầu hàm vuln()
  - Leak địa chỉ của libc
  - Overwrite printf@got với system@got
  - Ở fgets kế tiếp, nhập "/bin/sh" và tạo được shell

# 3. Thực hiện

**Lưu ý:** Ở dưới đây là mình thực hiện trên gdb, địa chỉ được đặt tĩnh với câu lệnh `set disable-randomization on` nên khi thực hiện chương trình thực tế, ta cần phải tính toán khi overwrite các function.

- Bước 1: Overwrite exit(0) với địa chỉ đầu hàm vuln()

Đầu tiên ta chạy chương trình trong gdb. Nhận thấy khi nhập dữ liệu vào, dữ liệu đó không được lưu trên stack mà được lưu trong heap (có thể dùng vmmap để check)

![stack](https://raw.githubusercontent.com/nhtri2003gmail/writeup-cnsc.uit.edu.vn-letwarnup/master/images/stack.png)

Do dữ liệu được nhập vào không ở trên stack nên ta không thể trực tiếp thay đổi giá trị của các hàm @got như bình thường. Thay vào đó, ta sẽ kiểm tra stack để kiếm những địa chỉ được trỏ tới một vị trí khác trên stack và ghi dữ liệu lên đó.

Dừng trước lệnh printf trong vuln() và kiểm tra stack:

![stack](https://raw.githubusercontent.com/nhtri2003gmail/writeup-cnsc.uit.edu.vn-letwarnup/master/images/stack_before_printf.png)

Ta thấy ở địa chỉ `0x7fffffffde50` (dòng 2) có địa chỉ `0x00007fffffffde60` trỏ tới vị trí khác trên stack, ta sẽ ghi 4 byte địa chỉ của exit(0) lên stack với offset = 8. 

Sau khi ghi được địa chỉ của exit(0) lên stack, ta sẽ overwrite 2 byte cuối địa chỉ exit(0) thành địa chỉ đầu hàm vuln() với offset tiếp theo = 2.

`Payload 1: %c%c%c%c%c%c%4210746c%n%53654x%hn`

Khi thực thi lệnh trên xong, chương trình sẽ quay trở lại đầu hàm vuln(). Đây là lúc chúng ta leak địa chỉ của một hàm trong libc. 

- Bước 2: Leak địa chỉ của libc

Cũng trong ảnh trên, khi tìm kiếm một hồi thì ta thấy có thể leak được địa chỉ của libc_start_main_ret. Tuy nhiên, do hàm vuln() có câu lệnh này 

`0x00000000004011de <+8>:	sub    rsp,0x10`

nên lúc này offset sẽ khác, sau một hồi mày mò ta có offset của địa chỉ libc_start_main_ret = 15

`Payload 2: %15$p`

Sau câu lệnh đó, ta sẽ có được địa chỉ hiện tại của libc_start_main_ret. Và với libc_start_main_ret_offset có thể tìm được trong libc được cung cấp (có thể dùng trang [https://libc.blukat.me/](https://libc.blukat.me/) để lấy offset), ta sẽ tính ra được libc base, từ đó tính được địa chỉ hàm system.

- Bước 3: Overwrite printf@got với system@got

Vẫn như bước 1, ta sẽ kiếm trên stack có địa chỉ nào trỏ tới vị trí khác trên stack hay không. Ta sẽ dùng địa chỉ `0x00007fffffffde50` ở dòng `0x7fffffffde40` với offset = 16 để ghi địa chỉ của hàm printf@got.

![Stage3](https://raw.githubusercontent.com/nhtri2003gmail/writeup-cnsc.uit.edu.vn-letwarnup/master/images/Stage3.png)

Ta nhận thấy địa chỉ của printf và system có byte cuối giống nhau:

![printf_system](https://raw.githubusercontent.com/nhtri2003gmail/writeup-cnsc.uit.edu.vn-letwarnup/master/images/printf_system.png)

--> Ta chỉ cần overwrite 2 byte kế cuối của printf thành system.

`Payload 3: %c%c%c%c%c%c%c%c%c%c%c%c%c%c%4210707c%n%41603c%hn`

- Bước 4: Đưa chuỗi "/bin/sh" vào

Ở bước nhập cuối cùng ta chỉ việc nhập chuỗi "/bin/sh" vào là xong.

`Payload 4: /bin/sh`

Và chúng ta tạo được shell, nhưng chỉ trong gdb thôi vì địa chỉ tĩnh.

# 4. Lấy cờ

Đây là full code của mình: [solve.py](https://github.com/nhtri2003gmail/writeup-cnsc.uit.edu.vn-letwarnup/blob/master/solve.py)

![flag](https://raw.githubusercontent.com/nhtri2003gmail/writeup-cnsc.uit.edu.vn-letwarnup/master/images/flag.png)

Flag là "Wanna.One{This_format_string_is_more_insteresting_than_my_homework!!!}"













