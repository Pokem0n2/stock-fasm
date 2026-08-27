; stockmon - hand-written x86 asm, hand-crafted PE
; no import table: APIs resolved by ror13 hash via PEB walk
; build: fasm stock.asm stock_t.exe
; data: https://web.sqt.gtimg.cn/q=sh600519,sz000001
; columns: name|price|pct%|high|low|volume(万手), per-pixel alpha layered window

format binary
use32
org 400000h

; ===================== PE headers (hand-crafted) =====================
mz:
        db      'MZ'
        times   3Ah db 0
        dd      pe - mz                 ; e_lfanew

pe:
        db      'PE',0,0
        dw      14Ch                    ; Machine: i386
        dw      1                       ; NumberOfSections
        dd      0,0,0                   ; timestamp, symtab, numsym
        dw      0E0h                    ; SizeOfOptionalHeader
        dw      0103h                   ; EXECUTABLE | 32BIT | RELOCS_STRIPPED
; optional header (PE32)
        dw      10Bh                    ; magic
        dw      0                       ; linker version
        dd      raw_end - 401000h       ; SizeOfCode
        dd      0,0                     ; init/uninit data
        dd      start - 400000h         ; AddressOfEntryPoint (RVA)
        dd      1000h                   ; BaseOfCode
        dd      1000h                   ; BaseOfData
        dd      400000h                 ; ImageBase
        dd      1000h                   ; SectionAlignment (Win11 requires >= page)
        dd      200h                    ; FileAlignment (Win11 minimum 512)
        dw      4,0                     ; OS version 4.0
        dw      0,0                     ; image version
        dw      4,0                     ; subsystem version 4.0
        dd      0                       ; win32 version
        dd      ((bss_end - 400000h) + 0FFFh) and 0FFFFF000h  ; SizeOfImage
        dd      200h                    ; SizeOfHeaders
        dd      0                       ; checksum
        dw      2                       ; subsystem: WINDOWS GUI
        dw      0                       ; dll characteristics
        dd      100000h                 ; stack reserve
        dd      1000h                   ; stack commit
        dd      100000h                 ; heap reserve
        dd      1000h                   ; heap commit
        dd      0                       ; loader flags
        dd      16                      ; NumberOfRvaAndSizes
        times   128 db 0                ; all directories empty (no imports!)
; section table
        db      '.text',0,0,0
        dd      bss_end - 401000h       ; VirtualSize (incl. bss tail)
        dd      1000h                   ; VirtualAddress
        dd      raw_end - 401000h       ; SizeOfRawData
        dd      200h                    ; PointerToRawData
        dd      0,0                     ; relocs, linenums ptrs
        dw      0,0                     ; relocs, linenums counts
        dd      0E0000020h              ; code | exec | read | write
headers_end:

        times   200h-($-mz) db 0
; ===================== section: file 200h <-> RVA 1000h =====================
sect:
        org     $ + 0E00h               ; rebase so labels are VAs again

; ---- API table indices ----
API_LoadLibraryA              = 0
API_GetModuleFileNameA        = 1
API_GetPrivateProfileStringA  = 2
API_WritePrivateProfileStringA= 3
API_CreateThread              = 4
API_Sleep                     = 5
API_ExitProcess               = 6
API_RegisterClassA            = 7
API_CreateWindowExA           = 8
API_GetMessageA               = 9
API_DispatchMessageA          = 10
API_BeginPaint                = 11
API_EndPaint                  = 12
API_PostQuitMessage           = 13
API_SendMessageA              = 14
API_ReleaseCapture            = 15
API_DestroyWindow             = 16
API_GetWindowRect             = 17
API_UpdateLayeredWindow       = 18
API_wsprintfA                 = 19
API_LoadCursorA               = 20
API_CreateFontA               = 21
API_CreateCompatibleDC        = 22
API_CreateDIBSection          = 23
API_SelectObject              = 24
API_DeleteObject              = 25
API_SetTextColor              = 26
API_SetBkMode                 = 27
API_TextOutA                  = 28
API_GetTextExtentPoint32A     = 29
API_GetTextMetricsA           = 30
API_InternetOpenA             = 31
API_InternetOpenUrlA          = 32
API_InternetReadFile          = 33
API_InternetCloseHandle       = 34
API_DefWindowProcA            = 35
if defined DEBUG
API_CreateFileA               = 36
API_WriteFile                 = 37
API_CloseHandle               = 38
NAPI                          = 39
else
NAPI                          = 36
end if

macro apicall idx { call dword [apis + idx*4] }

; ===================== start =====================
start:
        ; --- module bases via PEB: exe, ntdll, kernel32 ---
        mov     eax,[fs:30h]            ; PEB
        mov     eax,[eax+0Ch]           ; LDR
        mov     esi,[eax+0Ch]           ; InLoadOrder.Flink (exe)
        mov     eax,[esi]               ; ntdll start
        mov     ecx,[eax]               ; kernel32 start
        mov     eax,[eax+18h]           ; ntdll base
        mov     ecx,[ecx+18h]           ; kernel32 base
        mov     [bases+4*4],eax
        mov     [bases+0*4],ecx
        ; --- LoadLibraryA first ---
        mov     ebx,ecx
        mov     eax,[hashes+0]
        call    resolve
        mov     [apis+0],eax
        ; --- load user32/gdi32/wininet ---
        mov     esi,dllnames
        mov     edi,1
.loadlp:
        push    esi
        call    dword [apis+0]
        mov     [bases+edi*4],eax
.adv:
        cmp     byte [esi],0
        je      .advz
        inc     esi
        jmp     .adv
.advz:
        inc     esi
        inc     edi
        cmp     edi,4
        jb      .loadlp
        ; --- resolve everything ---
        mov     edi,1                   ; skip idx 0 (done)
.rlp:
        cmp     edi,NAPI
        jae     .rdone
        movzx   eax,byte [dllidx+edi]
        mov     ebx,[bases+eax*4]
        mov     eax,[hashes+edi*4]
        call    resolve
        mov     [apis+edi*4],eax
        inc     edi
        jmp     .rlp
.rdone:
        ; --- ini path = exe dir + stock.ini ---
        push    260
        push    ini_path
        push    0
        apicall API_GetModuleFileNameA
        mov     esi,ini_path
        mov     edi,esi
.scan:
        mov     al,[esi]
        test    al,al
        jz      .scand
        cmp     al,'\'
        jne     .ns
        lea     edi,[esi+1]
.ns:
        inc     esi
        jmp     .scan
.scand:
        mov     esi,ininame
.cp:
        mov     al,[esi]
        mov     [edi],al
        inc     esi
        inc     edi
        test    al,al
        jnz     .cp
        ; --- codes ---
        push    ini_path
        push    1024
        push    codes
        push    defcodes
        push    keycodes
        push    sec
        apicall API_GetPrivateProfileStringA
        ; --- opacity/x/y ---
        mov     esi,keyop
        mov     edx,20
        call    iniint
        mov     [g_op],eax
        mov     esi,keyx
        mov     edx,100
        call    iniint
        mov     [wx],eax
        mov     esi,keyy
        mov     edx,100
        call    iniint
        mov     [wy],eax
        ; --- url = prefix + normalized codes ---
        mov     esi,urlpfx
        mov     edi,url
.pfx:
        mov     al,[esi]
        mov     [edi],al
        inc     esi
        inc     edi
        test    al,al
        jnz     .pfx
        dec     edi
        mov     esi,codes
.norm:
        mov     al,[esi]
        test    al,al
        jz      .normd
        cmp     al,' '
        je      .skip
        cmp     al,9
        je      .skip
        cmp     al,13
        je      .skip
        cmp     al,10
        je      .skip
        cmp     al,0A3h                 ; GBK full-width comma A3 AC
        jne     .utf8
        cmp     byte [esi+1],0ACh
        jne     .put
        mov     al,','
        inc     esi
        jmp     .put
.utf8:
        cmp     al,0EFh                 ; UTF-8 full-width comma EF BC 8C
        jne     .put
        cmp     byte [esi+1],0BCh
        jne     .put
        cmp     byte [esi+2],08Ch
        jne     .put
        mov     al,','
        add     esi,2
.put:
        mov     [edi],al
        inc     edi
.skip:
        inc     esi
        jmp     .norm
.normd:
        mov     byte [edi],0
        ; --- count commas -> g_n ---
        mov     eax,1
        mov     esi,url
.cnt:
        mov     cl,[esi]
        test    cl,cl
        jz      .cntd
        cmp     cl,','
        jne     .cn
        inc     eax
.cn:
        inc     esi
        jmp     .cnt
.cntd:
        cmp     eax,32
        jbe     .cap
        mov     eax,32
.cap:
        mov     [g_n],eax
        ; --- font ---
        push    fontname
        push    0
        push    3                       ; NONANTIALIASED_QUALITY
        push    0                       ; clip precision
        push    0                       ; out precision
        push    0                       ; charset
        push    0                       ; strikeout
        push    0                       ; underline
        push    0                       ; italic
        push    400                     ; weight
        push    0                       ; orientation
        push    0                       ; escapement
        push    0                       ; width
        push    -14                     ; height
        apicall API_CreateFontA
        mov     [hfont],eax
        ; --- memory dc ---
        push    0
        apicall API_CreateCompatibleDC
        mov     [hmdc],eax
        push    dword [hfont]
        push    eax
        apicall API_SelectObject
        ; --- line height ---
        push    tm
        push    dword [hmdc]
        apicall API_GetTextMetricsA
        mov     eax,dword [tm]          ; tmHeight
        add     eax,dword [tm+16]       ; tmExternalLeading
        mov     [g_lh],eax
        ; --- register class ---
        mov     dword [wcwnd+4],wndproc
        push    32512                   ; IDC_ARROW
        push    0
        apicall API_LoadCursorA
        mov     dword [wcwnd+24],eax          ; hCursor
        mov     dword [wcwnd+36],cls
        push    wcwnd
        apicall API_RegisterClassA
        ; --- create window ---
        mov     eax,[g_n]
        imul    eax,[g_lh]
        push    0
        push    0
        push    0
        push    0
        push    eax                     ; height
        push    480                     ; width (shrinks after first redraw)
        push    dword [wy]
        push    dword [wx]
        push    90000000h               ; WS_POPUP|WS_VISIBLE
        push    title
        push    cls
        push    80088h                  ; WS_EX_LAYERED|TOPMOST|TOOLWINDOW
        apicall API_CreateWindowExA
        mov     [hwnd],eax
        ; --- worker thread ---
        push    0
        push    0
        push    0
        push    worker
        push    0
        push    0
        apicall API_CreateThread
        ; --- message loop ---
.msg:
        push    0
        push    0
        push    0
        push    msg
        apicall API_GetMessageA
        test    eax,eax
        jle     .quit
        push    msg
        apicall API_DispatchMessageA
        jmp     .msg
.quit:
        push    0
        apicall API_ExitProcess

; ===================== resolve(base=ebx, hash=eax) -> eax =====================
resolve:
        push    esi
        push    edi
        push    ecx
        push    edx
        push    ebp
        mov     ebp,eax                 ; target hash
        mov     esi,[ebx+3Ch]
        add     esi,ebx                 ; PE header VA
        mov     esi,[esi+78h]           ; export dir RVA
        add     esi,ebx                 ; export dir VA
        mov     edi,[esi+20h]
        add     edi,ebx                 ; names array VA
        xor     ecx,ecx
.next:
        cmp     ecx,[esi+18h]           ; NumberOfNames
        jae     .done
        mov     eax,[edi+ecx*4]
        add     eax,ebx                 ; name VA
        push    ecx
        xor     edx,edx
.h:
        movzx   ecx,byte [eax]
        test    cl,cl
        jz      .hd
        ror     edx,13
        add     edx,ecx
        inc     eax
        jmp     .h
.hd:
        pop     ecx
        cmp     edx,ebp
        je      .found
        inc     ecx
        jmp     .next
.found:
        mov     eax,[esi+24h]           ; ordinals RVA
        add     eax,ebx
        movzx   ecx,word [eax+ecx*2]
        mov     eax,[esi+1Ch]           ; functions RVA
        add     eax,ebx
        mov     eax,[eax+ecx*4]
        add     eax,ebx
.done:
        pop     ebp
        pop     edx
        pop     ecx
        pop     edi
        pop     esi
        ret

; ===================== iniint(key=esi, def=edx) -> eax =====================
iniint:
        push    ini_path
        push    16
        push    tmpbuf
        push    emptystr
        push    esi
        push    sec
        apicall API_GetPrivateProfileStringA
        mov     esi,tmpbuf
        cmp     byte [esi],0
        je      .def
        call    satof
        sub     esp,4
        fistp   dword [esp]
        pop     eax
        ret
.def:
        mov     eax,edx
        ret

; ===================== satof(str=esi) -> st0 =====================
satof:
        push    ebx
        xor     eax,eax                 ; accumulator
        xor     ebx,ebx                 ; frac digit count
        xor     edx,edx                 ; sign flag
.l0:
        cmp     byte [esi],' '
        jne     .l1
        inc     esi
        jmp     .l0
.l1:
        cmp     byte [esi],'-'
        jne     .l2
        inc     esi
        mov     dl,1
.l2:
        movzx   ecx,byte [esi]
        sub     cl,'0'
        cmp     cl,9
        ja      .dot
        imul    eax,eax,10
        add     eax,ecx
        inc     esi
        jmp     .l2
.dot:
        cmp     byte [esi],'.'
        jne     .fin
        inc     esi
.l3:
        movzx   ecx,byte [esi]
        sub     cl,'0'
        cmp     cl,9
        ja      .fin
        imul    eax,eax,10
        add     eax,ecx
        inc     ebx
        inc     esi
        jmp     .l3
.fin:
        push    eax
        fild    dword [esp]             ; st0 = acc
        test    ebx,ebx
        jz      .nodiv
        push    10
        fild    dword [esp]             ; st0=10, st1=acc
        mov     ecx,ebx
.dl:
        fdiv    st1,st0                 ; acc /= 10
        dec     ecx
        jnz     .dl
        fstp    st0                     ; pop the 10 -> st0 = acc
        pop     eax                     ; discard int 10
.nodiv:
        pop     eax                     ; discard acc
        test    dl,dl
        jz      .pos
        fchs
.pos:
        pop     ebx
        ret

; ===================== dtoa2(st0=v, edi=out, cl=sign) =====================
dtoa2:
        push    ebx
        push    edx
        fldz
        fcomip  st0,st1                 ; 0 ? v (fcomip pops the 0 -> st0=v)
        jb      .gt                     ; v > 0
        jz      .nosign                 ; v == 0
        mov     byte [edi],'-'          ; v < 0
        inc     edi
        fchs
        jmp     .nosign
.gt:
        test    cl,cl
        jz      .nosign
        mov     byte [edi],'+'
        inc     edi
.nosign:
        fmul    dword [c100]
        fadd    dword [chalf]
        sub     esp,4
        fistp   dword [esp]
        pop     eax                     ; eax = round(|v|*100)
        mov     ebx,100
        xor     edx,edx
        div     ebx                     ; eax=int part, edx=frac 0..99
        push    edx
        mov     ebx,10
        xor     ecx,ecx
        test    eax,eax
        jnz     .it
        mov     byte [edi],'0'
        inc     edi
        jmp     .ipd
.it:
        xor     edx,edx
        div     ebx
        push    edx
        inc     ecx
        test    eax,eax
        jnz     .it
.wr:
        pop     eax
        add     al,'0'
        stosb
        dec     ecx
        jnz     .wr
.ipd:
        mov     byte [edi],'.'
        inc     edi
        pop     eax                     ; frac
        xor     edx,edx
        div     ebx                     ; tens, ones
        add     al,'0'
        stosb
        mov     al,dl
        add     al,'0'
        stosb
        mov     byte [edi],0
        pop     edx
        pop     ebx
        ret

; ===================== parse() =====================
; stock start: name 0-39, pr 40-55, pc 56-71, hi 72-87, lo 88-103,
;              vl 104-123, ok @124, color @128   (size 132)
parse:
        mov     eax,rbuf
        mov     [scanpos],eax
        xor     ebx,ebx                 ; stock index
.next:
        mov     esi,[scanpos]           ; resume after last closing quote
        cmp     ebx,[g_n]
        jae     .done
        cmp     ebx,32
        jae     .done
.fq:
        mov     al,[esi]
        test    al,al
        jz      .done
        cmp     al,'"'
        je      .gotq
        inc     esi
        jmp     .fq
.gotq:
        inc     esi
        mov     [flds],esi
        mov     ecx,1                   ; nf
.split:
        mov     al,[esi]
        test    al,al
        jz      .done                   ; truncated buffer
        cmp     al,'"'
        je      .close
        cmp     al,'~'
        jne     .adv
        mov     byte [esi],0
        inc     esi
        cmp     ecx,39
        jae     .split
        mov     [flds+ecx*4],esi
        inc     ecx
        jmp     .split
.adv:
        inc     esi
        jmp     .split
.close:
        inc     esi
        mov     [scanpos],esi           ; next stock starts after this quote
        cmp     ecx,35
        jb      .next                   ; garbage segment: retry same slot
        imul    eax,ebx,132
        lea     ebp,[stocks+eax]
        ; pr -> f64a, pc -> f64b
        mov     esi,[flds+3*4]
        call    satof
        fstp    qword [f64a]
        mov     esi,[flds+4*4]
        call    satof
        fstp    qword [f64b]
        ; pct = pc>0 ? (pr-pc)/pc*100 : 0
        fld     qword [f64a]
        fsub    qword [f64b]            ; pr-pc
        fld     qword [f64b]            ; pc
        fldz
        fcomip  st0,st1                 ; 0 ? pc (pops 0 -> st0=pc, st1=pr-pc)
        jae     .zero                   ; pc <= 0
        fdivp   st1,st0                 ; (pr-pc)/pc
        fmul    dword [c100]
        jmp     .p1
.zero:
        fstp    st0
        fstp    st0
        fldz
.p1:
        fstp    qword [f64c]            ; pct
        ; if pr<=0 then pr=pc (suspended)
        fldz
        fld     qword [f64a]
        fcomip  st0,st1                 ; pr ? 0 (pops pr -> st0=0)
        fstp    st0                     ; pop the 0
        ja      .keeppr
        mov     eax,[f64b]
        mov     [f64a],eax
        mov     eax,[f64b+4]
        mov     [f64a+4],eax
.keeppr:
        ; color from pct
        fldz
        fld     qword [f64c]
        fcomip  st0,st1                 ; pct ? 0 (pops pct -> st0=0)
        fstp    st0
        ja      .red
        jb      .green
        mov     eax,0DCDCDCh            ; white
        jmp     .col
.red:
        mov     eax,05050FFh            ; RGB(255,80,80)
        jmp     .col
.green:
        mov     eax,050DC50h            ; RGB(80,220,80)
.col:
        mov     [ebp+128],eax
        ; name (max 39 bytes)
        mov     esi,[flds+1*4]
        mov     edi,ebp
        mov     ecx,39
.cpn:
        mov     al,[esi]
        test    al,al
        jz      .cpd
        mov     [edi],al
        inc     esi
        inc     edi
        dec     ecx
        jnz     .cpn
.cpd:
        mov     byte [edi],0
        ; price string
        lea     edi,[ebp+40]
        fld     qword [f64a]
        xor     cl,cl
        call    dtoa2
        ; pct string + '%'
        lea     edi,[ebp+56]
        fld     qword [f64c]
        mov     cl,1
        call    dtoa2
        mov     byte [edi],'%'
        inc     edi
        mov     byte [edi],0
        ; high
        mov     esi,[flds+33*4]
        call    satof
        lea     edi,[ebp+72]
        xor     cl,cl
        call    dtoa2
        ; low
        mov     esi,[flds+34*4]
        call    satof
        lea     edi,[ebp+88]
        xor     cl,cl
        call    dtoa2
        ; volume(万手)
        mov     esi,[flds+6*4]
        call    satof
        fdiv    dword [c10000]
        lea     edi,[ebp+104]
        xor     cl,cl
        call    dtoa2
        mov     dword [edi],0D6CAF2CDh  ; "万手" GBK
        mov     byte [edi+4],0
        ; ok
        mov     dword [ebp+124],1
        inc     ebx
        jmp     .next
.done:
        ret

; ===================== redraw() =====================
redraw:
        xor     eax,eax
        mov     [wc],eax
        mov     [wc+4],eax
        mov     [wc+8],eax
        mov     [wc+12],eax
        mov     [wc+16],eax
        mov     [wc+20],eax
        mov     [nr],eax
        ; ---- measure pass ----
        xor     ebx,ebx
.mloop:
        cmp     ebx,[g_n]
        jae     .mdone
        imul    eax,ebx,132
        lea     ebp,[stocks+eax]
        cmp     dword [ebp+124],0
        je      .mnext
        mov     dword [ci],0
.mcl:
        mov     ecx,[ci]
        mov     esi,ebp
        add     esi,[cellofs+ecx*4]
        xor     eax,eax
.msl:
        cmp     byte [esi+eax],0
        jz      .mslz
        inc     eax
        jmp     .msl
.mslz:
        push    szpt
        push    eax
        push    esi
        push    dword [hmdc]
        apicall API_GetTextExtentPoint32A
        mov     ecx,[ci]
        mov     eax,[szpt]              ; width
        cmp     eax,[wc+ecx*4]
        jbe     .mnb
        mov     [wc+ecx*4],eax
.mnb:
        inc     dword [ci]
        cmp     dword [ci],6
        jb      .mcl
        inc     dword [nr]
.mnext:
        inc     ebx
        jmp     .mloop
.mdone:
        cmp     dword [nr],0
        jne     .go
        ret
.go:
        mov     eax,[wc]
        mov     ecx,1
.tl:
        add     eax,[wc+ecx*4]
        add     eax,12
        inc     ecx
        cmp     ecx,6
        jb      .tl
        mov     edx,[nr]
        imul    edx,[g_lh]
        cmp     eax,[ww]
        jne     .newdib
        cmp     edx,[wh]
        je      .draw
.newdib:
        mov     [ww],eax
        mov     [wh],edx
        mov     dword [bih],40
        mov     [bih+4],eax
        neg     edx
        mov     [bih+8],edx
        mov     dword [bih+12],00200001h ; planes=1, bpp=32
        xor     eax,eax
        mov     [bih+16],eax
        mov     [bih+20],eax
        mov     [bih+24],eax
        mov     [bih+28],eax
        mov     [bih+32],eax
        mov     [bih+36],eax
        push    0
        push    0
        push    pxptr
        push    0
        push    bih
        push    dword [hmdc]
        apicall API_CreateDIBSection
        push    eax                     ; new bmp
        push    eax
        push    dword [hmdc]
        apicall API_SelectObject
        mov     ecx,eax                 ; old obj
        pop     eax                     ; new bmp
        cmp     dword [hbmp],0
        je      .noold
        push    ecx
        apicall API_DeleteObject
.noold:
        mov     [hbmp],eax
.draw:
        mov     edi,[pxptr]
        mov     ecx,[ww]
        imul    ecx,[wh]
        mov     eax,01000000h
        rep     stosd                   ; alpha=1 black background
        push    1                       ; TRANSPARENT
        push    dword [hmdc]
        apicall API_SetBkMode
        ; ---- draw pass ----
        xor     ebx,ebx
        mov     dword [cy],0
.dloop:
        cmp     ebx,[g_n]
        jae     .present
        imul    eax,ebx,132
        lea     ebp,[stocks+eax]
        cmp     dword [ebp+124],0
        je      .dnext
        push    dword [ebp+128]         ; color
        push    dword [hmdc]
        apicall API_SetTextColor
        mov     dword [ci],0
        mov     dword [cx_],0
.dcl:
        mov     ecx,[ci]
        mov     esi,ebp
        add     esi,[cellofs+ecx*4]
        xor     eax,eax
.dsl:
        cmp     byte [esi+eax],0
        jz      .dslz
        inc     eax
        jmp     .dsl
.dslz:
        mov     [tmpbuf],eax            ; save len
        push    szpt
        push    eax
        push    esi
        push    dword [hmdc]
        apicall API_GetTextExtentPoint32A
        mov     ecx,[ci]
        mov     eax,[cx_]
        add     eax,[wc+ecx*4]
        sub     eax,[szpt]              ; right-aligned x
        push    dword [tmpbuf]          ; len
        push    esi
        push    dword [cy]
        push    eax
        push    dword [hmdc]
        apicall API_TextOutA
        mov     ecx,[ci]
        mov     eax,[wc+ecx*4]
        add     eax,12
        add     [cx_],eax
        inc     dword [ci]
        cmp     dword [ci],6
        jb      .dcl
        mov     eax,[g_lh]
        add     [cy],eax
.dnext:
        inc     ebx
        jmp     .dloop
.present:
        ; ---- alpha pass: bg -> alpha 1, text -> alpha g_op (premultiplied) ----
        mov     edi,[pxptr]
        mov     ecx,[ww]
        imul    ecx,[wh]
        mov     ebx,[g_op]
.al:
        mov     eax,[edi]
        test    eax,0FFFFFFh
        jnz     .tx
        mov     dword [edi],01000000h
        jmp     .nx
.tx:
        movzx   edx,al                  ; r
        imul    edx,ebx
        imul    edx,8081h
        shr     edx,23                  ; r*op/255 (exact for our range)
        movzx   esi,ah                  ; g
        imul    esi,ebx
        imul    esi,8081h
        shr     esi,23
        shl     esi,8
        or      edx,esi
        mov     esi,eax
        shr     esi,16
        and     esi,0FFh                ; b
        imul    esi,ebx
        imul    esi,8081h
        shr     esi,23
        shl     esi,16
        or      edx,esi
        mov     esi,ebx
        shl     esi,24                  ; alpha = op
        or      edx,esi
        mov     [edi],edx
.nx:
        add     edi,4
        dec     ecx
        jnz     .al
        ; ---- present ----
        mov     dword [blend],01FF0000h ; {AC_SRC_OVER,0,255,AC_SRC_ALPHA}
        mov     eax,[ww]
        mov     [szout],eax
        mov     eax,[wh]
        mov     [szout+4],eax
        push    2                       ; ULW_ALPHA
        push    blend
        push    0                       ; crKey
        push    pt0                     ; pptSrc
        push    dword [hmdc]
        push    szout
        push    0                       ; pptDst
        push    0                       ; hdcDst
        push    dword [hwnd]
        apicall API_UpdateLayeredWindow
        ret

; ===================== worker / wndproc =====================
worker:
        call    fetch
        call    redraw
        push    1000
        apicall API_Sleep
        jmp     worker

fetch:
        push    0
        push    0
        push    0
        push    0
        push    agent
        apicall API_InternetOpenA
        test    eax,eax
        jz      .fail
        mov     [hinet],eax
        push    0
        push    84000100h               ; RELOAD|NO_CACHE_WRITE|PRAGMA_NOCACHE
        push    0
        push    0
        push    url
        push    eax
        apicall API_InternetOpenUrlA
        test    eax,eax
        jz      .close1
        mov     [hurl],eax
        xor     ebx,ebx
.rd:
        mov     eax,32767
        sub     eax,ebx
        jz      .done
        push    got
        push    eax
        mov     eax,rbuf
        add     eax,ebx
        push    eax
        push    dword [hurl]
        apicall API_InternetReadFile
        test    eax,eax
        jz      .done
        mov     eax,[got]
        test    eax,eax
        jz      .done
        add     ebx,eax
        jmp     .rd
.done:
        mov     byte [rbuf+ebx],0
        push    dword [hurl]
        apicall API_InternetCloseHandle
.close1:
        push    dword [hinet]
        apicall API_InternetCloseHandle
      if defined DEBUG
        ; dump url + rbuf to dbg.bin next to exe dir
        push    0
        push    0
        push    2                       ; CREATE_ALWAYS
        push    0
        push    0
        push    40000000h               ; GENERIC_WRITE
        push    dbgpath
        apicall API_CreateFileA
        mov     [hfile],eax
        ; write url (strlen)
        mov     esi,url
        xor     eax,eax
.ulen:
        cmp     byte [esi+eax],0
        jz      .ulz
        inc     eax
        jmp     .ulen
.ulz:
        push    0
        push    got
        push    eax
        push    url
        push    dword [hfile]
        apicall API_WriteFile
        ; write rbuf (ebx bytes)
        push    0
        push    got
        push    ebx
        push    rbuf
        push    dword [hfile]
        apicall API_WriteFile
        push    dword [hfile]
        apicall API_CloseHandle
      end if
.fail:
        call    parse
      if defined DEBUG
        ; dump g_n + stocks[0..7] raw
        push    0
        push    0
        push    2
        push    0
        push    0
        push    40000000h
        push    dbgpath2
        apicall API_CreateFileA
        mov     [hfile],eax
        push    0
        push    got
        push    4
        push    g_n
        push    dword [hfile]
        apicall API_WriteFile
        push    0
        push    got
        push    132*8
        push    stocks
        push    dword [hfile]
        apicall API_WriteFile
        push    dword [hfile]
        apicall API_CloseHandle
      end if
        ret

wndproc:                                ; (hwnd,msg,w,l)
        mov     eax,[esp+8]
        cmp     eax,0Fh                 ; WM_PAINT
        je      .paint
        cmp     eax,201h                ; WM_LBUTTONDOWN
        je      .ldown
        cmp     eax,205h                ; WM_RBUTTONUP
        je      .rup
        cmp     eax,2                   ; WM_DESTROY
        je      .destroy
        jmp     dword [apis + API_DefWindowProcA*4]   ; tail call
.paint:
        mov     eax,[esp+4]
        push    ps
        push    eax
        apicall API_BeginPaint
        mov     eax,[esp+4]
        push    ps
        push    eax
        apicall API_EndPaint
        xor     eax,eax
        ret     16
.ldown:
        apicall API_ReleaseCapture
        mov     eax,[esp+4]
        push    0
        push    2                       ; HTCAPTION
        push    0A1h                    ; WM_NCLBUTTONDOWN
        push    eax
        apicall API_SendMessageA
        xor     eax,eax
        ret     16
.rup:
        sub     esp,16                  ; RECT
        mov     eax,[esp+16+4]          ; hwnd
        mov     edx,esp
        push    edx
        push    eax
        apicall API_GetWindowRect
        mov     eax,[esp]               ; left
        push    eax
        push    fmt
        push    tmpbuf
        apicall API_wsprintfA
        add     esp,12                  ; cdecl
        push    tmpbuf
        push    keyx
        push    sec
        push    ini_path
        apicall API_WritePrivateProfileStringA
        mov     eax,[esp+4]             ; top
        push    eax
        push    fmt
        push    tmpbuf
        apicall API_wsprintfA
        add     esp,12
        push    tmpbuf
        push    keyy
        push    sec
        push    ini_path
        apicall API_WritePrivateProfileStringA
        mov     eax,[esp+16+4]          ; hwnd
        push    eax
        apicall API_DestroyWindow
        add     esp,16
        xor     eax,eax
        ret     16
.destroy:
        push    0
        apicall API_PostQuitMessage
        xor     eax,eax
        ret     16

; ===================== data =====================
sec:      db 'stock',0
keycodes: db 'codes',0
keyop:    db 'opacity',0
keyx:     db 'x',0
keyy:     db 'y',0
defcodes: db 'sh600519,sz000001',0
ininame:  db 'stock.ini',0
urlpfx:   db 'https://web.sqt.gtimg.cn/q=',0
cls:      db 'stkmon',0
title:    db 'stk',0
agent:    db 's',0
fmt:      db '%d',0
emptystr: db 0
fontname: db 'Microsoft YaHei',0
dllnames: db 'user32.dll',0
          db 'gdi32.dll',0
          db 'wininet.dll',0
dbgpath:  db 'dbg.bin',0
dbgpath2: db 'dbg2.bin',0
c100:     dd 42C80000h                ; 100.0f
chalf:    dd 3F000000h                ; 0.5f
c10000:   dd 461C4000h                ; 10000.0f
cellofs:  dd 0,40,56,72,88,104
dllidx:   db 0,0,0,0,0,0,0,1,1,1,1,1,1,1,1,1,1,1,1,1,1,2,2,2,2,2,2,2,2,2,2,3,3,3,3,4
if defined DEBUG
          db 0,0,0
end if
align 4
hashes:
  dd 0EC0E4E8Eh   ;  0 LoadLibraryA
  dd 045B06D76h   ;  1 GetModuleFileNameA
  dd 08F2A152Dh   ;  2 GetPrivateProfileStringA
  dd 04B63076Ch   ;  3 WritePrivateProfileStringA
  dd 0CA2BD06Bh   ;  4 CreateThread
  dd 0DB2D49B0h   ;  5 Sleep
  dd 073E2D87Eh   ;  6 ExitProcess
  dd 02538882Eh   ;  7 RegisterClassA
  dd 084454941h   ;  8 CreateWindowExA
  dd 07AC67BEDh   ;  9 GetMessageA
  dd 0690A1701h   ; 10 DispatchMessageA
  dd 02C1B37CCh   ; 11 BeginPaint
  dd 0C72D2386h   ; 12 EndPaint
  dd 04BE0469Dh   ; 13 PostQuitMessage
  dd 0EB6CC3F4h   ; 14 SendMessageA
  dd 0497E38E0h   ; 15 ReleaseCapture
  dd 094305BE0h   ; 16 DestroyWindow
  dd 0927C5439h   ; 17 GetWindowRect
  dd 07BF9B6AEh   ; 18 UpdateLayeredWindow
  dd 057F6BBDBh   ; 19 wsprintfA
  dd 0CBA6C0CFh   ; 20 LoadCursorA
  dd 088781825h   ; 21 CreateFontA
  dd 066F33A69h   ; 22 CreateCompatibleDC
  dd 089364153h   ; 23 CreateDIBSection
  dd 0FE97A655h   ; 24 SelectObject
  dd 0FE3DA875h   ; 25 DeleteObject
  dd 07805F866h   ; 26 SetTextColor
  dd 0F1F6D8E6h   ; 27 SetBkMode
  dd 0A33B683Dh   ; 28 TextOutA
  dd 0D0260B83h   ; 29 GetTextExtentPoint32A
  dd 0BE602635h   ; 30 GetTextMetricsA
  dd 057E84429h   ; 31 InternetOpenA
  dd 07E0FED49h   ; 32 InternetOpenUrlA
  dd 05FE34B8Bh   ; 33 InternetReadFile
  dd 0FA9B69C7h   ; 34 InternetCloseHandle
  dd 0577A6CB2h   ; 35 NtdllDefWindowProc_A
if defined DEBUG
  dd 07C0017A5h   ; 36 CreateFileA
  dd 0E80A791Fh   ; 37 WriteFile
  dd 00FFD97FBh   ; 38 CloseHandle
end if

raw_end:

; ===================== bss (zero-filled tail, no file bytes) =====================
virtual at raw_end
ini_path: rb 260
codes:    rb 1024
url:      rb 1408
rbuf:     rb 32768
stocks:   rb 132*32
flds:     rb 160
tm:       rb 60
ps:       rb 64
msg:      rb 28
wcwnd:    rb 40
bih:      rb 40
tmpbuf:   rb 16
wc:       rd 6
szpt:     rd 2
szout:    rd 2
pt0:      rd 2
blend:    rd 1
f64a:     rq 1
f64b:     rq 1
f64c:     rq 1
bases:    rd 6
apis:     rd NAPI
g_n:      rd 1
g_op:     rd 1
g_lh:     rd 1
wx:       rd 1
wy:       rd 1
nr:       rd 1
ci:       rd 1
cx_:      rd 1
cy:       rd 1
ww:       rd 1
wh:       rd 1
hwnd:     rd 1
hmdc:     rd 1
hbmp:     rd 1
hfont:    rd 1
pxptr:    rd 1
hinet:    rd 1
hurl:     rd 1
hfile:    rd 1
got:      rd 1
scanpos:  rd 1
bss_end:
end virtual
