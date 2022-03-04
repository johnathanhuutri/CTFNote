# cnsc.uit.edu.vn - feedback

Link challenge gốc (closed, inactive): [https://cnsc.uit.edu.vn/ctf/challenges](https://cnsc.uit.edu.vn/ctf/challenges)

Các bạn có thể tải challenge ở ngay repo của mình: [feedback.zip](feedback.zip)

Challenge sẽ bao gồm 2 file: 
- feedback
- libc-2.31.so (lấy từ challenge letwarnup)

Các bạn tải về và patch file libc-2.31.so vào file letwarnup bằng [patchelf](https://github.com/NixOS/patchelf) hoặc [pwninit](https://github.com/io12/pwninit) nhé. Và bây giờ chúng ta bắt đầu nào!

# 1. Tìm lỗi
Đầu tiên, dùng lệnh `file` để xem file thực thi có những gì:
```
feedback: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, BuildID[sha1]=03d655736af96457ea1f8cb5165a9b47f2f946fe, for GNU/Linux 3.2.0, not stripped
```
Đây là file 64-bit không bị mã hóa code nên ta có thể dễ dàng tìm kiếm function trong ghidra cũng như gdb.

Tiếp theo, ta mở challenge bằng ghidra. Ở đây sẽ có các function nhưng ta thấy chỉ có nah() là đáng chú ý.

![ghidra_nah](https://raw.githubusercontent.com/nhtri2003gmail/writeup-cnsc.uit.edu.vn-feedback/master/images/ghidra_nah.png)

Trong hàm nah(), nếu ta nhập chuỗi bé hơn 80 ký tự thì địa chỉ rbp sẽ không bị thay đổi

![Non80](https://raw.githubusercontent.com/nhtri2003gmail/writeup-cnsc.uit.edu.vn-feedback/master/images/Non80.png)

Nhưng nếu ta nhập đủ 80 ký tự, null byte của chuỗi sẽ được đẩy qua rbp

![80](https://raw.githubusercontent.com/nhtri2003gmail/writeup-cnsc.uit.edu.vn-feedback/master/images/80.png)

--> Least significant byte (LSB)

Kế đến, ta sẽ kiểm tra file bằng checksec:
```
Arch:     amd64-64-little
RELRO:    Full RELRO
Stack:    No canary found
NX:       NX enabled
PIE:      No PIE (0x400000)
```
Ta thấy NX và Full RELRO được bật --> Không thể thực thi code trên stack cũng như overwrite GOT.

# 2. Ý tưởng

Do không có lỗi format string hay BOF mà chỉ có LSB nên ta sẽ tận dụng lỗi này để đưa payload vào bằng ropchain. 

Khi nhập đủ 80 ký tự ở hàm nah(), do chạy trong gdb, với địa chỉ tĩnh, ta sẽ không thể thấy được điều gì. Vậy hãy đặt thử trong gdb, với địa chỉ động bằng câu lệnh `set diable-randomization off` và ta sẽ thấy được điều thú vị.

Với mỗi lần chạy khác nhau ở địa chỉ động, rip sẽ `ret` ở mỗi địa chỉ khác nhau, có lúc thì không đụng input, có lúc sẽ đụng ở vị trí nào đó trong input. Vì thế ta được ý tưởng đầu:

- Ý tưởng đầu tiên:

Ta sẽ sử dụng ROP để tạo payload, nhưng không biết nên làm thế nào nên ta chuyển sang ý tưởng kế tiếp.

- Ý tưởng thứ hai:

Khi ROP không được, ta thử one_gadget coi như thế nào. Nhưng muốn xài one_gadget, ta cần phải có địa chỉ động của libc đang chạy, vì thế ta cần phải leak địa chỉ, làm cho chương trình quay lại từ đầu để nhập payload kế và thực thi one_gadget

- Tổng kết ý tưởng:
  - Leak địa chỉ + làm cho chương trình quay lại từ đầu
  - Đưa one_gadget vào

# 3. Thực hiện

Như đã nói, chỉ khi địa chỉ động thì rip mới `ret` ở các địa chỉ khác nhau. Vì thế ta xài câu lệnh này `set disable-randomization off` để đặt địa chỉ từ tĩnh sang động.

- Bước 1: Leak địa chỉ + làm cho chương trình quay lại từ đầu

Ở bước này ta muốn leak địa chỉ nào cũng được. Do đó ta sẽ leak địa chỉ của printf.

Để leak địa chỉ printf, ta sẽ kết hợp giữa ROP và @plt để thực hiện. Ở đây, ta sẽ xử dụng hàm puts@plt để in ra địa chỉ của printf trong libc. Bây giờ ta sẽ kiếm những tham số cần thiết để làm điều đó:
```
ret = 0x40101a (Vì ta muốn rip chạm vào input thì sẽ chạy dọc theo nó để đụng tới code, cũng vì không dùng `\x90` được nên ta dùng `ret`)
pop_rdi_ret = 0x4015d3 (Dùng ROPgadget kiếm trong file challenge)
printf_got = 0x403fc0 (Dùng GDB để kiếm)
puts_plt = 0x4010a0 (Dùng GDB để kiếm)
main_func = 0x40145c (khi chạm vào input, thực thi xong payload sẽ quay lại từ main())
```

payload 1: `<ret>*n + <pop_rdi_ret> + <printf_got> + <puts_plt> + <main_func> + <Padding cho đủ 80 ký tự>`

Nếu payload trên không phù hợp (`<ret>*n`, với n bất kì) thì khi gặp lệnh printf@plt ở bất kì hàm nào cũng sẽ bị lỗi segfault ngay câu lệnh này

![movaps_error](https://raw.githubusercontent.com/nhtri2003gmail/writeup-cnsc.uit.edu.vn-feedback/master/images/movaps_error.png)

Câu lệnh đó sẽ liên quan tới địa chỉ của stack hiện tại:

![movaps_error_stack](https://raw.githubusercontent.com/nhtri2003gmail/writeup-cnsc.uit.edu.vn-feedback/master/images/movaps_error_stack.png)

Do byte cuối cùng của địa chỉ stack là 0x58, boundary là 8 không thỏa yêu cầu của movabs (yêu cầu boundary là 16). Vì thế ta sẽ tăng độ dài payload 1 lên bằng cách cộng thêm `ret` để byte cuối cùng của địa chỉ stack sẽ có dạng 0x00, 0x10, 0x20, 0x30, 0x40,...

Sau nhiều lần thử với số lần nhân `ret` thì nhân 3 là hợp lí, vì nếu nhân 5, khi quay trở lại nhập payload 2 sẽ làm cho chương trình lỗi vì rbp sẽ bằng <Padding cho đủ 80 ký tự> của payload 1

Từ đó, ta sẽ có payload 1 như sau (đã vào hàm nah()):

payload 1: `<ret>*3 + <pop_rdi_ret> + <printf_got> + <puts_plt> + <main_func> + <Padding cho đủ 80 ký tự>`

Thực thi payload 1 đó nhiều lần, sẽ có một vài lần ta thấy chương trình in ra địa chỉ của printf. Vậy ta đưa vào script và thực thi để có thể tính toán với địa chỉ đã leak.

- Bước 2: Đưa one_gadget vào

Khi đã có địa chỉ của one_gadget, ta sẽ xem thử coi nếu nhập đủ 80 ký tự thì có sinh lỗi hay không. Và khi nhập thì ta thấy ở cuối main, ret sẽ jump vào 8 byte cuối của payload 2. 

payload 2 demo: `aaaabaaacaaadaaaeaaafaaagaaahaaaiaaajaaakaaalaaamaaanaaaoaaapaaaqaaaraaasaaataaa`

![payload2demo](https://raw.githubusercontent.com/nhtri2003gmail/writeup-cnsc.uit.edu.vn-feedback/master/images/payload2.png)

Vì thế payload 2 sẽ như sau:

payload 2: `<Padding cho đủ 72 ký tự> + <one_gadget>`

# 4. Lấy cờ

Đây là full code của mình: [solve.py](solve.py)

Tuy nhiên, mình viết writeup này sau cuộc thi nên bây giờ mình không thể truy cập được server nữa, mong các bạn thông cảm. 

Dưới đây là hình ảnh của shell đã được tạo local

![Fake_Flag](https://raw.githubusercontent.com/nhtri2003gmail/writeup-cnsc.uit.edu.vn-feedback/master/images/FakeFlag.png)
