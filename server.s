.intel_syntax noprefix
.global _start

.section .data
.section .text
_start:

sock:                           #returned in rax den fd
mov     rdi, 2                  #AF_INET == 2 (tcp/ip)
mov     rsi, 1                  #SOCK_STREAM == 1 (tcp)
xor     rdx, rdx                #protocol = 0   (standard)
mov     rax, 41                 #socket call
syscall

bind:
mov     rdi, rax                #fd von sock
lea     rsi, [rip+sockaddr]     #struct ptr
mov     rdx, 16                 #struct len
mov     rax, 49                 #bind call
syscall

mov     r12, rdi

listen:                         #rdi == fd von bound socket
mov     rsi, 0                  #warteschlange (0 hosts erlaubt)
mov     rax, 50                 #listen call
syscall

# struct sigaction auf dem Stack: sa_handler = SIG_IGN (1), Rest 0
sub     rsp, 32
mov     qword ptr [rsp], 1      # SIG_IGN
mov     qword ptr [rsp+8], 0    # sa_flags
mov     qword ptr [rsp+16], 0   # sa_restorer
mov     qword ptr [rsp+24], 0   # sa_mask
mov     rdi, 17                 # SIGCHLD
mov     rsi, rsp
xor     rdx, rdx
mov     r10, 8                  # sigsetsize
mov     rax, 13                 # rt_sigaction
syscall
add     rsp, 32

accept:
mov     rdi, r12                #bound socket fd
mov     rsi, 0                  #addr
mov     rdx, 0                  #addr
mov     rax, 43                 #accept call
syscall
mov     r15, rax                #fd von neuem socket

fork:                           #gibt in rax die PID wieder >0 == parent, 0 == child
mov     rax, 57                 #fork call
syscall
cmp     rax, 0
je      child

close_new_sock:					#als Parent
mov     rdi, r15				#schließt die neue sock
mov     rax, 3					#close call
syscall
jmp accept						#geht wieder dazu über, Verbindungen anzunehmen

child:
mov     rdi, r12                #fd von altem sock
mov     rax, 3                  #close call (jz als child)
syscall

read_req:                       #liest Bytes aus dem sock
mov     rdi, r15                #fd von accept (4)
mov     rsi, rsp                #Adresse zum speichern der Bytes
mov     rdx, 1024               #Anzahl der Bytes die gespeichert werden sollen
mov     rax, 0                  #read call
syscall
mov     r13, rax                #anzahl der gelesenen bytes

mov     r14, rsp                #r14 ziegt auf Anfang der request
cmp     byte ptr [r14], 0x47    #ist erstes Zeichen 'G'?
je      GET
cmp     byte ptr [r14], 0x50    #ist erstes Zeichen 'P'?
je      POST
jmp		close					#falls keine GET oder keine POST > close und exit



##################
####HANDLE_GET####
##################

GET:
add     r14, 4					#zeigt auf Anfang des Pfads
call extract_path
lea		r14, [rsp+4]

ropen_file:
mov     rdi, r14	            #Pfad
mov     rsi, 0                  #read only-flag
mov     rax, 2                  #open call
syscall
cmp		rax, 0					#error-handling
jl		close

read_file:
mov     rdi, rax                #fd von ropen_file
mov     rsi, rsp                #adresse zum speichern
mov     rdx, 2048                #max bytes
mov     rax, 0                  #read call
syscall
mov     r14, rax                #anzahl der gelesenen bytes zu r14

call close_file                 #IN: rdi == fd vom file
call write_ok

write:                          #gibt eine Antwort an den Client
mov     rdi, r15                #fd von Client sock
mov     rsi, rsp                #Adresse des response string (File-Inhalt)
mov     rdx, r14                #Länge der response
mov     rax, 1                  #write call
syscall

jmp close						#IN: rdi == fd von sock



###################
####HANDLE_POST####
###################

POST:
add     r14, 5                  #r14 zeigt auf den Pfad
call    extract_path

wopen_file:                     #öffnet den File aus dem request-Pfad
                                #OUT: rax == fd
lea     rdi, [rsp+5]            #file Name vom Stack gelesen
mov     rsi, 0x41               #O_WRONLY | O_CREAT
mov     rdx, 0777               #Rechte
mov     rax, 2                  #open call
syscall
cmp		rax, 0					#error-handling
jl		close
mov     rdi, rax				#fd in rdi geladen

mov     r14, rsp                #r14 zeigt auf request-Anfang
lea     r8, [rsp+r13]			#r8 zeigt auf request-Ende
xor     r9, r9                  #damit wir eine geclearte count-variable haben

find_body:						#skipt erste Zeile der http-request und zeigt auf den anfang der Header
cmp     r14, r8					#zeigt r14 auf ende der request?
jae     close
mov     al, [r14]				#lädt den Byte der request in al
inc     r14						#r14 zeigt einen Byte weiter
cmp     al, 0x0d                #ist al '\r'?
je      find_body

cmp     al, 0x0a				#ist al '\n'
jne reset

inc     r9
cmp     r9, 2
je len_found

jmp find_body

reset:
xor     r9, r9					#r9 wird wieder gecleared, weil es nicht zwei '\n' hintereinander sind
jmp find_body

len_found:
mov     rsi, r14				#r14 ist inzwischen der Anfang des Bodys, weil wir immer incremented haben
mov     rdx, r8					#r8 ist noch die Adresse vom Ende der request
sub     rdx, r14				#Body-Länge = Ende - Body-Anfang

write_file:
mov     rax, 1
syscall

call close_file					#IN: rdi == fd vom file
call write_ok

close:                          #schließt das sock (den fd)
mov     rdi, r15                #fd von sock
mov     rax, 3                  #close call
syscall

exit:
mov     rdi, 0                  #exit code
mov     rax, 60                 #exit call
syscall


#################
####FUNCTIONS####
#################

extract_path:                   #vergleicht jeden byte der request mit ' '. Falls gefunden setzt dort '\0'
cmp     byte ptr [r14], 0x20    #vergleicht rcx mit ' ' (0x20)
je terminate_str                #falls ' ' springe
inc     r14                     #' ' nicht gefunden > auf nächsten byte zeigen
jmp extract_path                #zum vergleich springen

terminate_str:
mov     byte ptr [r14], 0       #setzt ' ' = '\0'
ret

close_file:						#IN: rdi == fd vom file
mov     rax, 3
syscall
ret

write_ok:
mov     rdi, r15
lea     rsi, [rip+res]
mov     rdx, 19
mov     rax, 1
syscall
ret



############
####DATA####
############

sockaddr:
    .word 2        # AF_INET
    .word 0x2005   # Port 80 als Bytes 00 50 (31337 == 7a 69)
    .long 0        # 0.0.0.0
    .zero 8

res:
    .asciz "HTTP/1.0 200 OK\r\n\r\n"
