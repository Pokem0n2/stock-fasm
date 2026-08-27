/* stockmon - minimal stock price monitor
 * data: https://web.sqt.gtimg.cn/q=sh600519,sz000001
 * build: see build.bat (CRT-less, /NODEFAULTLIB)
 * columns: name | price | pct% | high | low | volume(万手)
 * rendering: per-pixel alpha via UpdateLayeredWindow —
 *   background alpha=1 (invisible but clickable), text alpha=opacity
 */
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <wininet.h>

#pragma comment(lib, "kernel32.lib")
#pragma comment(lib, "user32.lib")
#pragma comment(lib, "gdi32.lib")
#pragma comment(lib, "wininet.lib")

#define MAXSTK 32
#define GAP 12          /* column gap px */

typedef struct {
    char name[40], pr[16], pc[16], hi[16], lo[16], vl[20];
    double pct; int ok;
} STK;

static STK  *g_s;
static char *g_url;
static char *g_buf;
static char g_ini[MAX_PATH];           /* ini file path (next to exe) */
static int  g_n;                       /* number of stocks */
static int  g_op = 20;
static int  g_lh = 18;                 /* line height px */
static HWND g_hwnd;
static HFONT g_font;
static HDC  g_mdc;
static HBITMAP g_bmp;
static DWORD *g_px;
static int  g_w, g_h;
static CRITICAL_SECTION g_cs;

/* ---- tiny libc replacements ---- */
int _fltused;   /* required by linker when using floats without CRT */
void* __cdecl memset(void *d, int c, size_t n){ unsigned char *p=d; while(n--) *p++=(unsigned char)c; return d; }
static int slen(const char *s){ int n=0; while(s[n]) n++; return n; }
static void scpy(char *d, const char *s){ while((*d++=*s++)); }
static void scat(char *d, const char *s){ while(*d) d++; scpy(d,s); }
static void scpyn(char *d, const char *s, int m){ int i=0; while(i<m-1 && s[i]){ d[i]=s[i]; i++; } d[i]=0; }

static double satof(const char *s){
    double r=0, f=0, d=1; int neg=0;
    while(*s==' ') s++;
    if(*s=='-'){ neg=1; s++; }
    while(*s>='0' && *s<='9'){ r=r*10+(*s-'0'); s++; }
    if(*s=='.'){ s++; while(*s>='0' && *s<='9'){ f=f*10+(*s-'0'); d*=10; s++; } }
    r+=f/d;
    return neg?-r:r;
}

/* format v with 2 decimals; sign=1 -> leading '+' when positive */
static void dtoa2(double v, char *o, int sign){
    long i; long ip; char tmp[24]; int n=0;
    if(sign && v>0) *o++='+';
    if(v<0){ *o++='-'; v=-v; }
    i=(long)(v*100+0.5);
    ip=i/100;
    if(ip==0) tmp[n++]='0';
    while(ip){ tmp[n++]=(char)('0'+ip%10); ip/=10; }
    while(n) *o++=tmp[--n];
    *o++='.';
    *o++=(char)('0'+(i/10)%10);
    *o++=(char)('0'+i%10);
    *o=0;
}

/* ---- parse web.sqt.gtimg.cn response: v_sh600519="1~name~code~price~prev~open~vol~..."; ---- */
/* fields: 1=name 3=price 4=prevclose 6=volume(手) 33=high 34=low */
static void parse(void){
    char *p=g_buf; int i=0;
    EnterCriticalSection(&g_cs);
    while(i<g_n && i<MAXSTK){
        char *f[40]; int nf=0;
        double pr, pc, vol;
        while(*p && *p!='\"') p++;
        if(!*p) break;
        p++;
        f[nf++]=p;
        while(*p && *p!='\"'){
            if(*p=='~'){ *p=0; if(nf<39) f[nf++]=p+1; }
            p++;
        }
        if(*p=='\"') p++;
        if(nf<35) continue;
        pr=satof(f[3]); pc=satof(f[4]); vol=satof(f[6]);
        if(pr<=0) pr=pc;              /* suspended: show prev close */
        g_s[i].pct = pc>0 ? (pr-pc)/pc*100 : 0;
        scpyn(g_s[i].name, f[1], 40);
        dtoa2(pr, g_s[i].pr, 0);
        dtoa2(g_s[i].pct, g_s[i].pc, 1); scat(g_s[i].pc, "%");
        dtoa2(satof(f[33]), g_s[i].hi, 0);
        dtoa2(satof(f[34]), g_s[i].lo, 0);
        dtoa2(vol/10000, g_s[i].vl, 0);
        scat(g_s[i].vl, "\xCD\xF2\xCA\xD6");   /* "万手" in GBK */
        g_s[i].ok=1;
        i++;
    }
    LeaveCriticalSection(&g_cs);
}

/* render data into the layered window with per-pixel alpha */
static void redraw(void){
    int wc[6]={0,0,0,0,0,0}, i, c, rows=0, x, y, tot;
    SIZE sz; const char *e[6];
    EnterCriticalSection(&g_cs);
    for(i=0;i<g_n;i++) if(g_s[i].ok){
        e[0]=g_s[i].name; e[1]=g_s[i].pr; e[2]=g_s[i].pc;
        e[3]=g_s[i].hi;   e[4]=g_s[i].lo; e[5]=g_s[i].vl;
        for(c=0;c<6;c++){
            GetTextExtentPoint32A(g_mdc,e[c],slen(e[c]),&sz);
            if(sz.cx>wc[c]) wc[c]=sz.cx;
        }
        rows++;
    }
    if(!rows){ LeaveCriticalSection(&g_cs); return; }
    tot=wc[0];
    for(c=1;c<6;c++) tot+=GAP+wc[c];
    if(tot!=g_w || rows*g_lh!=g_h){       /* (re)create 32bpp DIB at content size */
        BITMAPINFO bi; void *ppv=0; HBITMAP nb, ob;
        g_w=tot; g_h=rows*g_lh;
        memset(&bi,0,sizeof(bi));
        bi.bmiHeader.biSize=sizeof(bi.bmiHeader);
        bi.bmiHeader.biWidth=g_w;
        bi.bmiHeader.biHeight=-g_h;       /* top-down */
        bi.bmiHeader.biPlanes=1;
        bi.bmiHeader.biBitCount=32;
        nb=CreateDIBSection(g_mdc,&bi,DIB_RGB_COLORS,&ppv,0,0);
        ob=(HBITMAP)SelectObject(g_mdc,nb);
        if(g_bmp) DeleteObject(ob);
        g_bmp=nb; g_px=(DWORD*)ppv;
    }
    { DWORD *p=g_px; int k=g_w*g_h; while(k--) *p++=0x01000000; }  /* alpha=1 bg */
    SetBkMode(g_mdc,TRANSPARENT);
    y=0;
    for(i=0;i<g_n;i++) if(g_s[i].ok){
        e[0]=g_s[i].name; e[1]=g_s[i].pr; e[2]=g_s[i].pc;
        e[3]=g_s[i].hi;   e[4]=g_s[i].lo; e[5]=g_s[i].vl;
        SetTextColor(g_mdc, g_s[i].pct>0?RGB(255,80,80)
                          : g_s[i].pct<0?RGB(80,220,80)
                          : RGB(220,220,220));
        x=0;
        for(c=0;c<6;c++){          /* right-align each cell in its column */
            GetTextExtentPoint32A(g_mdc,e[c],slen(e[c]),&sz);
            TextOutA(g_mdc, x+wc[c]-sz.cx, y, e[c], slen(e[c]));
            x+=wc[c]+GAP;
        }
        y+=g_lh;
    }
    /* fix alpha: background pixels -> alpha 1; text pixels -> alpha g_op (premultiplied) */
    { DWORD *p=g_px; int k=g_w*g_h, a=g_op; DWORD cc, r, g, b;
      while(k--){
        cc=*p;
        if((cc&0xFFFFFF)==0){ *p++=0x01000000; }
        else{
            r=(cc&0xFF)*a/255; g=((cc>>8)&0xFF)*a/255; b=((cc>>16)&0xFF)*a/255;
            *p++=((DWORD)a<<24)|(b<<16)|(g<<8)|r;
        }
      } }
    { POINT pt={0,0}; SIZE so={g_w,g_h};
      BLENDFUNCTION bf={AC_SRC_OVER,0,255,AC_SRC_ALPHA};
      UpdateLayeredWindow(g_hwnd,0,0,&so,g_mdc,&pt,0,&bf,ULW_ALPHA); }
    LeaveCriticalSection(&g_cs);
}

static void fetch(void){
    HINTERNET h1, h2; DWORD got, total=0; int tmo=5000;
    g_buf[0]=0;
    h1=InternetOpenA("stkmon", INTERNET_OPEN_TYPE_PRECONFIG, 0, 0, 0);
    if(!h1) return;
    InternetSetOptionA(h1, INTERNET_OPTION_CONNECT_TIMEOUT, &tmo, sizeof(tmo));
    InternetSetOptionA(h1, INTERNET_OPTION_RECEIVE_TIMEOUT, &tmo, sizeof(tmo));
    h2=InternetOpenUrlA(h1, g_url, 0, 0,
        INTERNET_FLAG_RELOAD|INTERNET_FLAG_NO_CACHE_WRITE|INTERNET_FLAG_PRAGMA_NOCACHE, 0);
    if(h2){
        while(total<32767){
            if(!InternetReadFile(h2, g_buf+total, 32767-total, &got) || !got) break;
            total+=got;
        }
        g_buf[total]=0;
        InternetCloseHandle(h2);
    }
    InternetCloseHandle(h1);
    parse();
}

static DWORD WINAPI worker(LPVOID p){
    (void)p;
    for(;;){ fetch(); redraw(); Sleep(1000); }
    return 0;
}

static LRESULT CALLBACK wp(HWND h, UINT m, WPARAM w, LPARAM l){
    switch(m){
    case WM_PAINT: {               /* content comes from UpdateLayeredWindow */
        PAINTSTRUCT ps; BeginPaint(h,&ps); EndPaint(h,&ps);
        return 0; }
    case WM_LBUTTONDOWN:           /* drag to move */
        ReleaseCapture();
        SendMessageA(h,WM_NCLBUTTONDOWN,HTCAPTION,0);
        return 0;
    case WM_RBUTTONUP: {           /* right click: save position, then exit */
        RECT r; char sx[16], sy[16];
        GetWindowRect(h,&r);
        wsprintfA(sx,"%d",r.left); wsprintfA(sy,"%d",r.top);
        WritePrivateProfileStringA("stock","x",sx,g_ini);
        WritePrivateProfileStringA("stock","y",sy,g_ini);
        DestroyWindow(h);
        return 0; }
    case WM_DESTROY:
        PostQuitMessage(0);
        return 0;
    }
    return DefWindowProcA(h,m,w,l);
}

void WINAPI WinMainCRTStartup(void){
    char codes[1024], tmp[1024], *q;
    static WNDCLASSA wc;   /* zero-init without memset */
    MSG m; int x, y, i, n;
    HINSTANCE hi=GetModuleHandleA(0);

    /* big buffers from heap, keeps .data tiny */
    g_s  =HeapAlloc(GetProcessHeap(),HEAP_ZERO_MEMORY,MAXSTK*sizeof(STK));
    g_url=HeapAlloc(GetProcessHeap(),0,1200);
    g_buf=HeapAlloc(GetProcessHeap(),0,32768);

    /* ini next to exe */
    GetModuleFileNameA(0, g_ini, MAX_PATH);
    q=g_ini+slen(g_ini); while(q>g_ini && q[-1]!='\\') q--;
    scpy(q, "stock.ini");
    GetPrivateProfileStringA("stock","codes","sh600519,sz000001",codes,sizeof(codes),g_ini);
    g_op=GetPrivateProfileIntA("stock","opacity",20,g_ini);
    if(g_op<10) g_op=10;
    if(g_op>255) g_op=255;
    x=GetPrivateProfileIntA("stock","x",100,g_ini);
    y=GetPrivateProfileIntA("stock","y",100,g_ini);

    /* normalize codes: strip blanks, full-width comma (GBK A3AC / UTF-8 EFBCAC) -> ',' */
    n=0;
    for(i=0; codes[i] && n<(int)sizeof(tmp)-1; i++){
        unsigned char c=(unsigned char)codes[i];
        if(c==' '||c=='\t'||c=='\r'||c=='\n') continue;
        if(c==0xA3 && (unsigned char)codes[i+1]==0xAC){ tmp[n++]=','; i++; continue; }
        if(c==0xEF && (unsigned char)codes[i+1]==0xBC && (unsigned char)codes[i+2]==0x8C){ tmp[n++]=','; i+=2; continue; }
        tmp[n++]=(char)c;
    }
    tmp[n]=0;

    scpy(g_url, "https://web.sqt.gtimg.cn/q=");
    scat(g_url, tmp);
    g_n=1;
    for(q=tmp; *q; q++) if(*q==',') g_n++;
    if(g_n>MAXSTK) g_n=MAXSTK;

    /* non-antialiased font: glyph pixels are binary, clean alpha mapping */
    g_font=CreateFontA(-14,0,0,0,FW_NORMAL,0,0,0,DEFAULT_CHARSET,
        OUT_DEFAULT_PRECIS,CLIP_DEFAULT_PRECIS,NONANTIALIASED_QUALITY,0,"Microsoft YaHei");
    g_mdc=CreateCompatibleDC(0);
    SelectObject(g_mdc,g_font);
    { TEXTMETRICA tm;
      GetTextMetricsA(g_mdc,&tm);
      g_lh=tm.tmHeight+tm.tmExternalLeading; }

    wc.lpfnWndProc=wp;
    wc.hInstance=hi;
    wc.lpszClassName="stkmon";
    wc.hCursor=LoadCursorA(0,IDC_ARROW);
    RegisterClassA(&wc);

    g_hwnd=CreateWindowExA(WS_EX_LAYERED|WS_EX_TOPMOST|WS_EX_TOOLWINDOW,
        "stkmon","stk", WS_POPUP|WS_VISIBLE,
        x,y,480,g_n*g_lh, 0,0,hi,0);

    InitializeCriticalSection(&g_cs);
    CreateThread(0,0,worker,0,0,0);

    while(GetMessageA(&m,0,0,0)){ DispatchMessageA(&m); }
    ExitProcess(0);
}
